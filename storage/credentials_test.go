package storage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"gotest.tools/v3/assert"

	"github.com/peak/s5cmd/v2/log"
)

func buildCredentialProcess(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "helper files")
	assert.NilError(t, os.Mkdir(dir, 0700))
	binary := filepath.Join(dir, "credential-process.exe")
	cmd := exec.Command("go", "build", "-o", binary, "../internal/testdata/credential-process/main.go")
	output, err := cmd.CombinedOutput()
	assert.NilError(t, err, "build credential process: %s", output)
	return binary
}

func credentialProcessConfig(t *testing.T, binary, mode string) string {
	t.Helper()
	for _, key := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_SDK_LOAD_CONFIG",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("AWS_REGION", "us-east-1")
	dir := filepath.Join(t.TempDir(), "profile files")
	assert.NilError(t, os.Mkdir(dir, 0700))
	state := filepath.Join(dir, "invocations")
	command := fmt.Sprintf("exec %q %s %q", binary, mode, state)
	if runtime.GOOS == "windows" {
		command = fmt.Sprintf("call \"%s\" %s \"%s\"", binary, mode, state)
	}
	config := "[default]\ncredential_process = " + command + "\n[profile process]\ncredential_process = " + command + "\n"
	configPath := filepath.Join(dir, "config")
	assert.NilError(t, os.WriteFile(configPath, []byte(config), 0600))
	credentialsPath := filepath.Join(dir, "credentials")
	assert.NilError(t, os.WriteFile(credentialsPath, nil, 0600))
	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsPath)
	globalSessionCache.clear()
	t.Cleanup(globalSessionCache.clear)
	return state
}

func TestCredentialProcessProfileSelection(t *testing.T) {
	binary := buildCredentialProcess(t)
	for _, tc := range []struct {
		name    string
		profile string
		env     string
	}{
		{name: "default"},
		{name: "environment", env: "process"},
		{name: "explicit", profile: "process"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := credentialProcessConfig(t, binary, "success")
			t.Setenv("AWS_PROFILE", tc.env)
			sess, err := globalSessionCache.newSession(context.Background(), Options{Profile: tc.profile, LogLevel: log.LevelError})
			assert.NilError(t, err)
			value, err := sess.Config.Credentials.Get()
			assert.NilError(t, err)
			assert.Equal(t, value.ProviderName, "ProcessProvider")
			assert.Equal(t, value.AccessKeyID, "synthetic-process-key-1")
			assert.Equal(t, value.SessionToken, "synthetic-process-session")
			data, err := os.ReadFile(state)
			assert.NilError(t, err)
			assert.Equal(t, string(data), "1")
		})
	}
}

func TestCredentialProviderPrecedence(t *testing.T) {
	binary := buildCredentialProcess(t)
	for _, tc := range []struct {
		name       string
		options    Options
		envKeys    bool
		fileKeys   bool
		sharedKeys bool
		wantKey    string
		wantCalls  bool
	}{
		{name: "environment overrides environment profile", envKeys: true, wantKey: "synthetic-env-key"},
		{name: "explicit profile overrides environment", options: Options{Profile: "process"}, envKeys: true, wantKey: "synthetic-process-key-1", wantCalls: true},
		{name: "explicit credentials file overrides process", options: Options{Profile: "process"}, envKeys: true, fileKeys: true, wantKey: "synthetic-file-key"},
		{name: "shared static profile overrides environment", options: Options{Profile: "process"}, envKeys: true, sharedKeys: true, wantKey: "synthetic-file-key"},
		{name: "anonymous overrides process", options: Options{NoSignRequest: true}, envKeys: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := credentialProcessConfig(t, binary, "success")
			t.Setenv("AWS_PROFILE", "process")
			if tc.envKeys {
				t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-env-key")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-env-secret")
			}
			opts := tc.options
			opts.LogLevel = log.LevelError
			if tc.fileKeys || tc.sharedKeys {
				file := filepath.Join(t.TempDir(), "credentials")
				assert.NilError(t, os.WriteFile(file, []byte("[process]\naws_access_key_id = synthetic-file-key\naws_secret_access_key = synthetic-file-secret\n"), 0600))
				if tc.fileKeys {
					opts.CredentialFile = file
				} else {
					t.Setenv("AWS_SHARED_CREDENTIALS_FILE", file)
				}
			}
			sess, err := globalSessionCache.newSession(context.Background(), opts)
			assert.NilError(t, err)
			if opts.NoSignRequest {
				assert.Equal(t, sess.Config.Credentials, credentials.AnonymousCredentials)
			} else {
				value, err := sess.Config.Credentials.Get()
				assert.NilError(t, err)
				assert.Equal(t, value.AccessKeyID, tc.wantKey)
			}
			_, err = os.Stat(state)
			if tc.wantCalls {
				assert.NilError(t, err)
			} else {
				assert.Assert(t, os.IsNotExist(err), "credential process must not be invoked")
			}
		})
	}
}

func TestCredentialProviderConfiguration(t *testing.T) {
	binary := buildCredentialProcess(t)
	t.Run("missing explicit profile", func(t *testing.T) {
		state := credentialProcessConfig(t, binary, "success")
		t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-env-key")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-env-secret")
		sess, err := globalSessionCache.newSession(context.Background(), Options{Profile: "missing", LogLevel: log.LevelError})
		var value credentials.Value
		if err == nil {
			value, err = sess.Config.Credentials.Get()
		}
		assert.Assert(t, err != nil, "an explicit missing profile must not fall back to environment credentials")
		assert.Assert(t, !value.HasKeys())
		_, err = os.Stat(state)
		assert.Assert(t, os.IsNotExist(err))
	})
	t.Run("shared configuration disabled", func(t *testing.T) {
		state := credentialProcessConfig(t, binary, "success")
		t.Setenv("AWS_SDK_LOAD_CONFIG", "0")
		t.Setenv("AWS_PROFILE", "process")
		sess, err := globalSessionCache.newSession(context.Background(), Options{LogLevel: log.LevelError})
		assert.NilError(t, err)
		value, err := sess.Config.Credentials.Get()
		assert.Assert(t, err != nil)
		assert.Assert(t, !value.HasKeys())
		_, err = os.Stat(state)
		assert.Assert(t, os.IsNotExist(err), "disabled shared configuration must not invoke the process")
	})
}

func TestExplicitProfileDoesNotUseAmbientCredentials(t *testing.T) {
	binary := buildCredentialProcess(t)
	for _, tc := range []struct {
		name     string
		profile  string
		disabled bool
	}{
		{name: "missing", profile: "missing"},
		{name: "empty", profile: "empty"},
		{name: "commented provider", profile: "empty"},
		{name: "dotted profile with parent credentials", profile: "team.child"},
		{name: "empty source profile", profile: "role"},
		{name: "cleared process", profile: "process"},
		{name: "comma provider", profile: "empty"},
		{name: "mixed case provider", profile: "empty"},
		{name: "quoted provider comma", profile: "empty"},
		{name: "quoted provider key", profile: "empty"},
		{name: "multiline unquoted value", profile: "empty"},
		{name: "multiline unquoted key", profile: "empty"},
		{name: "multiline trailing text", profile: "empty"},
		{name: "configuration disabled", profile: "process", disabled: true},
		{name: "default chain allows container credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := credentialProcessConfig(t, binary, "success")
			config := "[default]\nregion = us-east-1\n[profile empty]\nregion = us-east-1\n"
			if tc.name == "commented provider" {
				config += "credential_process = # disabled\naws_access_key_id = ; disabled\naws_secret_access_key = # disabled\n"
			}
			if tc.name == "comma provider" {
				config += "credential_process = helper a , b\n"
			}
			if tc.name == "mixed case provider" {
				config += "Credential_Process = helper\n"
			}
			if tc.name == "quoted provider comma" {
				config += "credential_process = \"helper\", b\n"
			}
			if tc.name == "quoted provider key" {
				config += "\"credential_process\" = helper\n"
			}
			if tc.name == "multiline unquoted value" {
				config += "role_session_name = ci \"x\ncredential_process = helper\"\n"
			}
			if tc.name == "multiline unquoted key" {
				config += "unknown \"x\ncredential_process = helper\" = value\n"
			}
			if tc.name == "multiline trailing text" {
				config += "role_session_name = \"ci\" \"x\ncredential_process = helper\"\n"
			}
			if tc.name == "dotted profile with parent credentials" {
				config += "[profile team]\naws_access_key_id = synthetic-parent-key\naws_secret_access_key = synthetic-parent-secret\n[profile team.child]\nregion = us-east-1\n"
			}
			if tc.name == "empty source profile" {
				config += "[profile role]\nrole_arn = arn:aws:iam::123456789012:role/synthetic-role\nsource_profile = empty\n"
			}
			if tc.name == "cleared process" {
				data, err := os.ReadFile(os.Getenv("AWS_CONFIG_FILE"))
				assert.NilError(t, err)
				config = string(data)
				assert.NilError(t, os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[process]\ncredential_process = \"\"\n"), 0600))
			}
			if !tc.disabled {
				assert.NilError(t, os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(config), 0600))
			}
			if tc.disabled {
				t.Setenv("AWS_SDK_LOAD_CONFIG", "0")
			}
			var calls int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				atomic.AddInt32(&calls, 1)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"AccessKeyId":     "synthetic-container-key",
					"SecretAccessKey": "synthetic-container-secret",
					"Token":           "synthetic-container-token",
					"Expiration":      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				})
			}))
			defer server.Close()
			t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL)
			sess, err := globalSessionCache.newSession(context.Background(), Options{Profile: tc.profile, LogLevel: log.LevelError})
			var value credentials.Value
			if err == nil {
				value, err = sess.Config.Credentials.Get()
			}
			if tc.profile == "" {
				assert.NilError(t, err)
				assert.Equal(t, value.AccessKeyID, "synthetic-container-key")
				assert.Equal(t, atomic.LoadInt32(&calls), int32(1))
			} else {
				assert.Assert(t, err != nil, "an explicit profile without credentials must fail")
				assert.Assert(t, !value.HasKeys())
				assert.Equal(t, atomic.LoadInt32(&calls), int32(0), "explicit profile must not consult ambient credentials")
			}
			_, err = os.Stat(state)
			assert.Assert(t, os.IsNotExist(err))
		})
	}
}

type credentialServiceTransport struct {
	endpoint *url.URL
	requests chan string
}

func (tr credentialServiceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr.requests <- r.URL.Hostname()
	if r.URL.Hostname() == "sts.amazonaws.com" || strings.HasPrefix(r.URL.Hostname(), "sts.") {
		r = r.Clone(r.Context())
		if r.Host == "" {
			r.Host = r.URL.Host
		}
		r.URL.Scheme = tr.endpoint.Scheme
		r.URL.Host = tr.endpoint.Host
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestExplicitProfileCredentialServiceEndpoint(t *testing.T) {
	binary := buildCredentialProcess(t)
	for _, source := range []string{"environment role", "web identity", "process role", "process role chain", "process role comments", "process role unquoted comments", "process role tab comments", "process role quoted escapes", "process role nested", "process role nested CRLF", "process role unicode spaces", "process role escaped closing quote", "process role multiline", "process role inline ARN", "process role inline external ID", "process role inline external ID CRLF", "process role duration 959", "process role duration 960"} {
		t.Run(source, func(t *testing.T) {
			state := credentialProcessConfig(t, binary, "success")
			config := "[profile role]\nrole_arn = arn:aws:iam::123456789012:role/synthetic-test-role\n"
			if source == "environment role" {
				config += "credential_source = Environment\n"
				t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-env-key")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-env-secret")
			} else if source == "web identity" {
				token := filepath.Join(t.TempDir(), "web-identity-token")
				assert.NilError(t, os.WriteFile(token, []byte("synthetic-web-identity-token"), 0600))
				config += "web_identity_token_file = " + token + "\n"
			} else {
				data, err := os.ReadFile(os.Getenv("AWS_CONFIG_FILE"))
				assert.NilError(t, err)
				config += "source_profile = process\nrole_session_name = synthetic-session\nexternal_id = synthetic-external\nduration_seconds = 1800\n" + string(data)
				if source == "process role chain" {
					config = strings.Replace(config, "source_profile = process", "source_profile = intermediate", 1)
					config += "[profile intermediate]\nrole_arn = arn:aws:iam::123456789012:role/synthetic-intermediate\nsource_profile = process\n"
				}
				if source == "process role comments" {
					config = strings.ReplaceAll(config, "source_profile = process", "source_profile = \"process\"\t; source")
					config = strings.ReplaceAll(config, "duration_seconds = 1800", "duration_seconds = \"1800\" # duration")
					config = strings.ReplaceAll(config, "external_id = synthetic-external", "external_id = \"synthetic-external\" ; external")
					config += "unrecognized line\n"
				}
				if source == "process role unquoted comments" {
					config = strings.ReplaceAll(config, "source_profile = process", "source_profile = process ; source")
					config = strings.ReplaceAll(config, "duration_seconds = 1800", "duration_seconds = 1800 # duration")
					config = strings.ReplaceAll(config, "external_id = synthetic-external", "external_id = synthetic-external ; external")
				}
				if source == "process role tab comments" {
					config = strings.ReplaceAll(config, "role_session_name = synthetic-session", "role_session_name = synthetic-session\t; session")
					config = strings.ReplaceAll(config, "external_id = synthetic-external", "external_id = synthetic-external\t# external")
				}
				if source == "process role quoted escapes" {
					config = strings.ReplaceAll(config, "role_session_name = synthetic-session", `role_session_name = "synthetic\\session\tname\nend\""`)
					config = strings.ReplaceAll(config, "external_id = synthetic-external", `external_id = "synthetic\\external\tvalue\nend\""`)
				}
				if strings.HasPrefix(source, "process role nested") {
					files, err := credentialProfileFiles(true)
					assert.NilError(t, err)
					command := readCredentialProfile(files, "process", true).values["credential_process"]
					config = strings.Replace(config, "source_profile = process\n", "", 1)
					config = strings.Replace(config, "[profile role]\n", "[profile role]\ncredential_process = "+command+"\ns3 =\n  addressing_style = path\n\n", 1)
					for _, key := range []string{"role_arn", "role_session_name", "external_id", "duration_seconds"} {
						config = strings.ReplaceAll(config, "\n"+key, "\n  "+key)
					}
					if source == "process role nested CRLF" {
						config = strings.ReplaceAll(config, "\n", "\r\n")
					}
				}
				if source == "process role unicode spaces" {
					config = strings.ReplaceAll(config, "source_profile = process", "source_profile = \u00a0process")
					config = strings.ReplaceAll(config, "external_id = synthetic-external", "external_id = \vsynthetic-external")
					config = strings.ReplaceAll(config, "role_session_name = synthetic-session", "role_session_name = \fsynthetic-session")
				}
				if source == "process role escaped closing quote" {
					config = strings.ReplaceAll(config, "role_session_name = synthetic-session", `role_session_name = "synthetic\\"session"`)
					config = strings.ReplaceAll(config, "external_id = synthetic-external", `external_id = "synthetic\\"external"`)
				}
				if source == "process role multiline" {
					config = strings.ReplaceAll(config, "role_session_name = synthetic-session", "role_session_name = \"synthetic\nsession\"")
					config = strings.ReplaceAll(config, "external_id = synthetic-external", "external_id = \"synthetic\r\nexternal\"")
				}
				if source == "process role inline ARN" {
					config = strings.Replace(config, "[profile role]\nrole_arn", "[profile role] role_arn", 1)
				}
				if strings.HasPrefix(source, "process role duration ") {
					seconds := strings.TrimPrefix(source, "process role duration ")
					config = strings.Replace(config, "duration_seconds = 1800", "duration_seconds = "+seconds, 1)
				}
				if strings.HasPrefix(source, "process role inline external ID") {
					config = strings.Replace(config, "external_id = synthetic-external\n", "", 1)
					config = strings.Replace(config, "[profile role]\n", "[profile role]\t external_id = synthetic-external\n", 1)
					if strings.HasSuffix(source, "CRLF") {
						config = strings.ReplaceAll(config, "\n", "\r\n")
					}
				}
			}
			assert.NilError(t, os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(config), 0600))
			type exchange struct {
				host, action, authorization, token string
				sessionName, externalID, duration  string
			}
			writeExchange := func(w http.ResponseWriter, action string) {
				w.Header().Set("Content-Type", "text/xml")
				_, _ = fmt.Fprintf(w, `<%sResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><%sResult><Credentials><AccessKeyId>synthetic-role-key</AccessKeyId><SecretAccessKey>synthetic-role-secret</SecretAccessKey><SessionToken>synthetic-role-token</SessionToken><Expiration>%s</Expiration></Credentials></%sResult></%sResponse>`, action, action, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), action, action)
			}
			exchanges := make(chan exchange, 2)
			credentialServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				action := r.FormValue("Action")
				exchanges <- exchange{host: r.Host, action: action, authorization: r.Header.Get("Authorization"), token: r.FormValue("WebIdentityToken"), sessionName: r.FormValue("RoleSessionName"), externalID: r.FormValue("ExternalId"), duration: r.FormValue("DurationSeconds")}
				writeExchange(w, action)
			}))
			defer credentialServer.Close()
			endpoint, err := url.Parse(credentialServer.URL)
			assert.NilError(t, err)
			originalDefaultClient := http.DefaultClient
			verifiedRequests := make(chan string, 4)
			http.DefaultClient = &http.Client{Transport: credentialServiceTransport{endpoint: endpoint, requests: verifiedRequests}}
			t.Cleanup(func() {
				http.DefaultClient = originalDefaultClient
			})
			storageRequests := make(chan exchange, 2)
			storageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				storageRequests <- exchange{host: r.Host, action: r.Method, authorization: r.Header.Get("Authorization"), token: r.FormValue("WebIdentityToken")}
				if action := r.FormValue("Action"); action != "" {
					writeExchange(w, action)
					return
				}
				w.Header().Set("Content-Type", "text/xml")
				_, _ = fmt.Fprint(w, `<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets/></ListAllMyBucketsResult>`)
			}))
			defer storageServer.Close()
			var rawExchange *exchange
			if strings.HasPrefix(source, "process role") {
				raw, err := session.NewSessionWithOptions(session.Options{Profile: "role", SharedConfigState: session.SharedConfigEnable})
				assert.NilError(t, err)
				_, err = raw.Config.Credentials.Get()
				assert.NilError(t, err)
				for len(verifiedRequests) > 0 {
					<-verifiedRequests
				}
				for len(exchanges) > 0 {
					captured := <-exchanges
					rawExchange = &captured
				}
				assert.NilError(t, os.WriteFile(state, nil, 0600))
			}
			opts := Options{Profile: "role", Endpoint: storageServer.URL, LogLevel: log.LevelError}
			sess, err := globalSessionCache.newSession(context.Background(), opts)
			assert.NilError(t, err)
			value, err := sess.Config.Credentials.Get()
			assert.NilError(t, err)
			assert.Equal(t, value.AccessKeyID, "synthetic-role-key")
			wantExchanges := 1
			if source == "process role chain" {
				wantExchanges = 2
			}
			assert.Equal(t, len(verifiedRequests), wantExchanges)
			assert.Equal(t, len(storageRequests), 0, "credential exchanges must not reach storage")
			assert.Equal(t, len(exchanges), wantExchanges)
			received := <-exchanges
			assert.Assert(t, strings.HasPrefix(received.host, "sts."), "exchange must target the STS service")
			if source == "environment role" {
				assert.Equal(t, received.action, "AssumeRole")
				assert.Assert(t, strings.Contains(received.authorization, "Credential=synthetic-env-key/"))
			} else if source == "web identity" {
				assert.Equal(t, received.action, "AssumeRoleWithWebIdentity")
				assert.Equal(t, received.token, "synthetic-web-identity-token")
			} else {
				assert.Equal(t, received.action, "AssumeRole")
				assert.Assert(t, strings.Contains(received.authorization, "Credential=synthetic-process-key-1/"))
				if source == "process role chain" {
					received = <-exchanges
					assert.Assert(t, strings.Contains(received.authorization, "Credential=synthetic-role-key/"))
				}
				sessionName, externalID := "synthetic-session", "synthetic-external"
				if source == "process role tab comments" {
					sessionName += "\t; session"
					externalID += "\t# external"
				}
				if source == "process role quoted escapes" {
					sessionName = "synthetic\\session\tname\nend\""
					externalID = "synthetic\\external\tvalue\nend\""
				}
				if source == "process role escaped closing quote" {
					sessionName, externalID = `synthetic"session`, `synthetic"external`
				}
				if source == "process role multiline" {
					sessionName, externalID = "synthetic\nsession", "synthetic\r\nexternal"
				}
				assert.Equal(t, received.sessionName, sessionName)
				assert.Equal(t, received.externalID, externalID)
				assert.Equal(t, received.sessionName, rawExchange.sessionName)
				assert.Equal(t, received.externalID, rawExchange.externalID)
				assert.Equal(t, received.duration, rawExchange.duration)
			}
			storage, err := newS3Storage(context.Background(), opts)
			assert.NilError(t, err)
			_, err = storage.ListBuckets(context.Background(), "")
			assert.NilError(t, err)
			assert.Equal(t, len(storageRequests), 1)
			received = <-storageRequests
			assert.Equal(t, received.action, http.MethodGet)
			assert.Assert(t, strings.Contains(received.authorization, "Credential=synthetic-role-key/"))
			assert.Equal(t, received.token, "")
			assert.Equal(t, len(verifiedRequests), wantExchanges+1)
			_, err = os.Stat(state)
			if strings.HasPrefix(source, "process role") {
				assert.NilError(t, err)
			} else {
				assert.Assert(t, os.IsNotExist(err))
			}
		})
	}
}

func TestCredentialServiceTLSWithStorageClientCertificate(t *testing.T) {
	binary := buildCredentialProcess(t)
	credentialProcessConfig(t, binary, "success")
	config := "[profile role]\nrole_arn = arn:aws:iam::123456789012:role/synthetic-test-role\ncredential_source = Environment\n"
	assert.NilError(t, os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(config), 0600))
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-env-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-env-secret")
	credentialHosts := make(chan string, 2)
	credentialServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credentialHosts <- r.Host
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>synthetic-role-key</AccessKeyId><SecretAccessKey>synthetic-role-secret</SecretAccessKey><SessionToken>synthetic-role-token</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	defer credentialServer.Close()
	cert := credentialServer.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	assert.NilError(t, err)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client-cert.pem"), filepath.Join(dir, "client-key.pem")
	assert.NilError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	assert.NilError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	t.Setenv("AWS_SDK_GO_CLIENT_TLS_CERT", certPath)
	t.Setenv("AWS_SDK_GO_CLIENT_TLS_KEY", keyPath)
	roots := x509.NewCertPool()
	roots.AddCert(credentialServer.Certificate())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: credentialServer.Certificate().DNSNames[0]}
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "sts.") {
			addr = credentialServer.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	originalDefaultClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		http.DefaultClient = originalDefaultClient
	})
	peerCertificates := make(chan int, 2)
	storageServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerCertificates <- len(r.TLS.PeerCertificates)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprint(w, `<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets/></ListAllMyBucketsResult>`)
	}))
	storageServer.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	storageServer.StartTLS()
	defer storageServer.Close()
	opts := Options{Profile: "role", Endpoint: storageServer.URL, NoVerifySSL: true, LogLevel: log.LevelError}
	storage, err := newS3Storage(context.Background(), opts)
	assert.NilError(t, err)
	_, err = storage.ListBuckets(context.Background(), "")
	assert.NilError(t, err, "storage must retain its client certificate")
	assert.Equal(t, len(peerCertificates), 1)
	assert.Equal(t, <-peerCertificates, 1)
	assert.Equal(t, len(credentialHosts), 1)
	assert.Assert(t, strings.HasPrefix(<-credentialHosts, "sts."))
	assert.Assert(t, !transport.TLSClientConfig.InsecureSkipVerify, "credential-service TLS verification must remain enabled")
	storageTransport := storage.api.(*s3.S3).Config.HTTPClient.Transport.(*http.Transport)
	assert.Assert(t, storageTransport != transport)
	assert.Assert(t, storageTransport.TLSClientConfig != transport.TLSClientConfig)
	assert.Assert(t, storageTransport.TLSClientConfig.InsecureSkipVerify)
	assert.Equal(t, len(storageTransport.TLSClientConfig.Certificates), 1)
	storageTransport.CloseIdleConnections()
}

func TestCredentialProcessRefresh(t *testing.T) {
	binary := buildCredentialProcess(t)
	for _, mode := range []string{"refresh", "renew-malformed", "renew-exit", "renew-valid-exit", "renew-oversized"} {
		t.Run(mode, func(t *testing.T) {
			state := credentialProcessConfig(t, binary, mode)
			t.Setenv("AWS_PROFILE", "process")
			sess, err := globalSessionCache.newSession(context.Background(), Options{LogLevel: log.LevelError})
			assert.NilError(t, err)
			value, err := sess.Config.Credentials.Get()
			assert.NilError(t, err)
			assert.Equal(t, value.AccessKeyID, "synthetic-process-key-1")
			expiration, err := sess.Config.Credentials.ExpiresAt()
			assert.NilError(t, err)
			cached, err := sess.Config.Credentials.Get()
			assert.NilError(t, err)
			assert.Equal(t, cached.AccessKeyID, value.AccessKeyID)
			time.Sleep(time.Until(expiration) + 10*time.Millisecond)
			value, err = sess.Config.Credentials.Get()
			if mode == "refresh" {
				assert.NilError(t, err)
				assert.Equal(t, value.AccessKeyID, "synthetic-process-key-2")
			} else {
				assert.Assert(t, err != nil, "failed renewal must not return cached credentials")
				assert.Assert(t, !value.HasKeys())
				assert.Assert(t, !strings.Contains(err.Error(), "synthetic-private-"), "credential output must not appear in errors")
			}
			data, err := os.ReadFile(state)
			assert.NilError(t, err)
			assert.Equal(t, string(data), "2")
		})
	}
}

func TestCredentialProcessFailureDoesNotFallBack(t *testing.T) {
	binary := buildCredentialProcess(t)
	for _, mode := range []string{"malformed", "exit", "valid-exit", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			credentialProcessConfig(t, binary, mode)
			t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-env-key")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-env-secret")
			sess, err := globalSessionCache.newSession(context.Background(), Options{Profile: "process", LogLevel: log.LevelError})
			assert.NilError(t, err)
			value, err := sess.Config.Credentials.Get()
			assert.Assert(t, err != nil, "credential process failure must be returned")
			assert.Assert(t, !value.HasKeys())
			assert.Assert(t, !strings.Contains(err.Error(), "synthetic-private-"), "credential output must not appear in errors")
		})
	}
}
