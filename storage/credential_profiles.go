package storage

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
)

// The SDK remains responsible for profile validation and provider precedence.
// Its process-provider hook tells us whether the selected chain needs a safe
// executor; other provider types retain the SDK's implementation.
func configureProfileCredentials(ctx context.Context, sess *session.Session, explicit string, shared, processSelected bool) error {
	if explicit == "" && !processSelected {
		return nil
	}
	files, err := credentialProfileFiles(shared)
	if err != nil {
		return err
	}
	name := explicit
	if name == "" {
		name = os.Getenv("AWS_PROFILE")
		if name == "" && shared {
			name = os.Getenv("AWS_DEFAULT_PROFILE")
		}
		if name == "" {
			name = "default"
		}
	}
	profile := readCredentialProfile(files, name, shared)
	if explicit != "" && !explicitProfileHasCredentials(files, explicit, shared) {
		return errors.New("explicit profile does not contain a credential provider")
	}
	if !processSelected {
		return nil
	}
	var roles []credentialProfile
	seen := make(map[string]bool)
	for {
		if seen[name] {
			return errors.New("credential process source profile cycle")
		}
		seen[name] = true
		if profile.values["role_arn"] != "" {
			roles = append(roles, profile)
		}
		source := profile.values["source_profile"]
		if source == "" {
			break
		}
		name = source
		profile = readCredentialProfile(files, name, shared)
	}
	command := profile.values["credential_process"]
	if command == "" || profile.static {
		return errors.New("unable to resolve selected credential process")
	}
	scope, _ := ctx.Value(credentialProcessContextKey{}).(*credentialProcessScope)
	creds := credentials.NewCredentials(&processCredentials{command: command, timeout: time.Minute, scope: scope})
	for i := len(roles) - 1; i >= 0; i-- {
		role := roles[i]
		sourceSession := sess.Copy(aws.NewConfig().WithCredentials(creds))
		creds = stscreds.NewCredentials(sourceSession, role.values["role_arn"], func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = role.values["role_session_name"]
			if externalID := role.values["external_id"]; externalID != "" {
				p.ExternalID = aws.String(externalID)
			}
			if seconds, err := strconv.Atoi(role.values["duration_seconds"]); err == nil {
				duration := time.Duration(seconds) * time.Second
				if duration/time.Minute > 15 {
					p.Duration = duration
				}
			}
		})
	}
	sess.Config.Credentials = creds
	return nil
}

type credentialProfileFile map[string]map[string]string

func credentialProfileFiles(shared bool) ([]credentialProfileFile, error) {
	paths := []string{profileFilePath("AWS_SHARED_CREDENTIALS_FILE", defaults.SharedCredentialsFilename())}
	if shared {
		paths = append([]string{profileFilePath("AWS_CONFIG_FILE", defaults.SharedConfigFilename())}, paths...)
	}
	var files []credentialProfileFile
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			// The SDK skips files it cannot open or read.
			continue
		}
		file, err := parseCredentialProfileFile(data)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

// This reader captures only scalar profile fields after the SDK has validated
// the files. Keep token boundaries, quoting, and numeric values consistent with
// the pinned SDK; differential tests exercise both readers on the same input.
func parseCredentialProfileFile(data []byte) (credentialProfileFile, error) {
	file := make(credentialProfileFile)
	section := make(map[string]string)
	skipNested := false
	lines, err := profileLogicalLines(string(data))
	if err != nil {
		return nil, err
	}
	for row := 0; row < len(lines); row++ {
		rawLine := lines[row]
		line := strings.TrimSuffix(rawLine, "\r")
		first, _ := utf8.DecodeRuneInString(line)
		if skipNested && profileWhitespace(first) {
			continue
		}
		skipNested = false
		trimmed := strings.TrimLeftFunc(line, profileWhitespace)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		for strings.HasPrefix(trimmed, "[") {
			end := profileSectionEnd(trimmed)
			if end < 0 {
				return nil, errors.New("unable to parse credential profile file")
			}
			name := strings.TrimFunc(trimmed[1:end], profileWhitespace)
			section = make(map[string]string)
			file[name] = section
			line = trimmed[end+1:]
			trimmed = strings.TrimLeftFunc(line, profileWhitespace)
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		separator := strings.IndexAny(line, "=:")
		if separator < 0 {
			skipNested = true
			continue
		}
		key := strings.TrimFunc(line[:separator], profileWhitespace)
		value := strings.TrimLeftFunc(line[separator+1:], profileWhitespace)
		if value == "" || strings.HasPrefix(value, "#") || strings.HasPrefix(value, ";") {
			skipNested = true
			continue
		}
		if strings.HasPrefix(value, `"`) {
			end := quotedProfileValueEnd(value)
			if end < 0 && strings.HasSuffix(rawLine, "\r") {
				value += "\r"
			}
			for end < 0 && row+1 < len(lines) {
				row++
				value += "\n" + lines[row]
				end = quotedProfileValueEnd(value)
			}
			if end < 0 {
				return nil, errors.New("unable to parse credential profile file")
			}
			if _, skip := unquotedProfileValue(value[end+1:]); skip {
				skipNested = true
				continue
			}
			value = value[:end+1]
		} else {
			var skip bool
			value, skip = unquotedProfileValue(value)
			if skip {
				skipNested = true
				continue
			}
		}
		if key == "duration_seconds" {
			// SDK Int reads the raw token, including quotes/trailing whitespace,
			// and accepts base prefixes. Invalid values override with zero.
			seconds, _ := strconv.ParseInt(value, 0, 64)
			section[key] = strconv.FormatInt(seconds, 10)
		} else {
			section[key] = profileValue(value)
		}
	}
	return file, nil
}

// A quoted token can span physical lines wherever it starts, including in a
// key, an unquoted value, or trailing text. Comments do not start quoted tokens.
func profileLogicalLines(data string) ([]string, error) {
	var lines []string
	start := 0
	boundary, quoted, comment := true, false, false
	for i := 0; i < len(data); {
		char, width := utf8.DecodeRuneInString(data[i:])
		if quoted {
			if char == '"' && (i == 0 || data[i-1] != '\\') {
				quoted = false
				boundary = true
			}
		} else if char == '\n' {
			lines = append(lines, data[start:i])
			start = i + width
			boundary, comment = true, false
		} else if !comment {
			switch {
			case boundary && profileWhitespace(char):
			case boundary && char == '"':
				quoted = true
			case boundary && (char == '#' || char == ';'):
				comment = true
			default:
				boundary = strings.ContainsRune(" :=[]", char) || boundary && char == ','
			}
		}
		i += width
	}
	if quoted {
		return nil, errors.New("unable to parse credential profile file")
	}
	return append(lines, data[start:]), nil
}

func profileSectionEnd(value string) int {
	boundary := true
	for i := 1; i < len(value); {
		char, width := utf8.DecodeRuneInString(value[i:])
		if boundary && profileWhitespace(char) {
			i += width
			continue
		}
		if boundary && char == '"' {
			end := quotedProfileValueEnd(value[i:])
			if end < 0 {
				return -1
			}
			i += end + 1
			continue
		} else if char == ']' {
			return i
		}
		boundary = strings.ContainsRune(" :=[", char)
		i += width
	}
	return -1
}

func quotedProfileValueEnd(value string) int {
	for i := 1; i < len(value); i++ {
		escaped := value[i-1] == '\\'
		if value[i] == '"' && !escaped {
			return i
		}
	}
	return -1
}

// SDK literals end at spaces and INI operators; tabs inside a literal remain
// literal. A comma token discards the key rather than creating a scalar value.
func unquotedProfileValue(value string) (string, bool) {
	boundary := true
	for i := 0; i < len(value); {
		char, width := utf8.DecodeRuneInString(value[i:])
		if boundary {
			if profileWhitespace(char) {
				i += width
				continue
			}
			switch char {
			case '#', ';':
				return value[:i], false
			case ',':
				return "", true
			case '"':
				if end := quotedProfileValueEnd(value[i:]); end > 0 {
					i += end + 1
					continue
				}
			}
		}
		boundary = strings.ContainsRune(" :=[]", char)
		i += width
	}
	return value, false
}

func profileWhitespace(char rune) bool {
	return unicode.IsSpace(char) && char != '\r' && char != '\n'
}

func profileValue(value string) string {
	if strings.HasPrefix(value, `"`) {
		if end := quotedProfileValueEnd(value); end > 0 {
			characters := []rune(value[1:end])
			for i := 1; i < len(characters); i++ {
				if characters[i-1] != '\\' {
					continue
				}
				switch characters[i] {
				case '\\', '"', '\'':
				case 'n':
					characters[i] = '\n'
				case 't':
					characters[i] = '\t'
				default:
					continue
				}
				characters[i-1] = characters[i]
				characters = append(characters[:i], characters[i+1:]...)
				i--
			}
			return string(characters)
		}
	}
	return strings.Trim(value, " \n")
}

func profileFilePath(variable, fallback string) string {
	if path := os.Getenv(variable); path != "" {
		return path
	}
	return fallback
}

type credentialProfile struct {
	values map[string]string
	static bool
}

func readCredentialProfile(files []credentialProfileFile, name string, shared bool) credentialProfile {
	profile := credentialProfile{values: make(map[string]string)}
	for _, file := range files {
		values, present := file[name]
		if !present {
			values, present = file["profile "+name]
		}
		if !present {
			continue
		}
		// A later file replaces static credentials only when both keys occur
		// together, matching the SDK's shared configuration merge rules.
		if values["aws_access_key_id"] != "" && values["aws_secret_access_key"] != "" {
			profile.static = true
		}
		for _, key := range []string{"credential_process", "web_identity_token_file"} {
			if value, present := values[key]; present {
				profile.values[key] = value
			}
		}
		if shared {
			for _, key := range []string{"role_arn", "source_profile", "credential_source", "role_session_name", "external_id", "duration_seconds", "sso_session", "sso_start_url", "sso_region", "sso_account_id", "sso_role_name"} {
				if value, present := values[key]; present {
					profile.values[key] = value
				}
			}
		}
	}
	return profile
}

func explicitProfileHasCredentials(files []credentialProfileFile, name string, shared bool) bool {
	seen := make(map[string]bool)
	for {
		profile := readCredentialProfile(files, name, shared)
		source := profile.values["source_profile"]
		if source == "" || seen[name] {
			return profile.hasCredentials()
		}
		seen[name] = true
		name = source
	}
}

func (p credentialProfile) hasCredentials() bool {
	if p.static {
		return true
	}
	for _, key := range []string{"credential_process", "credential_source", "web_identity_token_file", "sso_session", "sso_start_url", "sso_region", "sso_account_id", "sso_role_name"} {
		if p.values[key] != "" {
			return true
		}
	}
	return false
}
