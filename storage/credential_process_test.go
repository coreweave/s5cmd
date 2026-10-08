package storage

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/peak/s5cmd/v2/log"
)

func TestCredentialProcessTimeout(t *testing.T) {
	binary := buildCredentialProcess(t)
	state := credentialProcessConfig(t, binary, "sleep")
	files, err := credentialProfileFiles(true)
	assert.NilError(t, err)
	profile := readCredentialProfile(files, "process", true)
	command := profile.values["credential_process"]
	if runtime.GOOS != "windows" {
		command = strings.TrimPrefix(command, "exec ") + "; true"
	}
	provider := &processCredentials{command: command, timeout: time.Second}
	started := time.Now()
	value, err := provider.Retrieve()
	assert.Error(t, err, "ProcessProviderError: credential process timed out")
	assert.Assert(t, !value.HasKeys())
	assert.Assert(t, time.Since(started) < 3*time.Second, "timed out retrieval must return promptly")
	first, err := os.ReadFile(state)
	assert.NilError(t, err, "helper must start before timeout")
	pidData, err := os.ReadFile(state + ".pid")
	assert.NilError(t, err)
	pid, err := strconv.Atoi(string(pidData))
	assert.NilError(t, err)
	t.Cleanup(func() {
		latest, err := os.ReadFile(state)
		if err != nil || string(latest) == string(first) {
			return
		}
		if process, err := os.FindProcess(pid); err == nil {
			_ = process.Kill()
			_ = process.Release()
		}
	})
	time.Sleep(200 * time.Millisecond)
	second, err := os.ReadFile(state)
	assert.NilError(t, err)
	assert.Equal(t, string(first), string(second), "helper must stop on timeout")
	if runtime.GOOS == "windows" {
		assert.NilError(t, os.Remove(binary), "timed out helper must release its executable")
	}
}

func TestCredentialProcessApplicationCancellation(t *testing.T) {
	binary := buildCredentialProcess(t)
	state := credentialProcessConfig(t, binary, "sleep")
	files, err := credentialProfileFiles(true)
	assert.NilError(t, err)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := WithCredentialProcessContext(parent)
	defer stop()
	scope := ctx.Value(credentialProcessContextKey{}).(*credentialProcessScope)
	provider := &processCredentials{command: readCredentialProfile(files, "process", true).values["credential_process"], timeout: time.Minute, scope: scope}
	done := make(chan error, 1)
	go func() {
		_, err := provider.Retrieve()
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(state); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("credential helper did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	stop()
	select {
	case err := <-done:
		assert.Error(t, err, "ProcessProviderError: credential process cancelled")
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled credential helper did not finish")
	}
	first, err := os.ReadFile(state)
	assert.NilError(t, err)
	time.Sleep(200 * time.Millisecond)
	second, err := os.ReadFile(state)
	assert.NilError(t, err)
	assert.Equal(t, string(first), string(second), "cancelled helper must stop writing")
	if runtime.GOOS == "windows" {
		assert.NilError(t, os.Remove(binary), "cancelled helper must release its executable")
	}
}

func TestCredentialProcessProfileMerge(t *testing.T) {
	binary := buildCredentialProcess(t)
	for _, test := range []string{"credentials file process", "partial credentials", "disabled configuration ignores default profile", "default profile environment", "dotted process profile"} {
		t.Run(test, func(t *testing.T) {
			credentialProcessConfig(t, binary, "success")
			config, err := os.ReadFile(os.Getenv("AWS_CONFIG_FILE"))
			assert.NilError(t, err)
			profile := "process"
			switch test {
			case "credentials file process":
				assert.NilError(t, os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), config, 0600))
				t.Setenv("AWS_SDK_LOAD_CONFIG", "0")
			case "partial credentials":
				assert.NilError(t, os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[process]\naws_access_key_id = incomplete-key\n"), 0600))
			case "disabled configuration ignores default profile":
				assert.NilError(t, os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), config, 0600))
				t.Setenv("AWS_SDK_LOAD_CONFIG", "0")
				t.Setenv("AWS_DEFAULT_PROFILE", "missing")
				profile = ""
			case "default profile environment":
				t.Setenv("AWS_DEFAULT_PROFILE", "process")
				profile = ""
			case "dotted process profile":
				profile = "team.child"
				config = []byte(strings.ReplaceAll(string(config), "[profile process]", "[profile team.child]") + "[profile team]\naws_access_key_id = synthetic-parent-key\naws_secret_access_key = synthetic-parent-secret\nrole_arn = arn:aws:iam::123456789012:role/synthetic-parent\nsource_profile = missing\n")
				assert.NilError(t, os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), config, 0600))
			}
			sess, err := globalSessionCache.newSession(context.Background(), Options{Profile: profile, LogLevel: log.LevelError})
			assert.NilError(t, err)
			value, err := sess.Config.Credentials.Get()
			assert.NilError(t, err)
			assert.Equal(t, value.AccessKeyID, "synthetic-process-key-1")
		})
	}
}

func TestCredentialProcessParserMatchesSDK(t *testing.T) {
	binary := buildCredentialProcess(t)
	for _, test := range []string{"unknown lines", "cleared role", "cleared source", "trailing backslash", "unquoted empty role", "duplicate section", "mixed case role"} {
		t.Run(test, func(t *testing.T) {
			credentialProcessReferenceConfig(t, binary, "success")
			data, err := os.ReadFile(os.Getenv("AWS_CONFIG_FILE"))
			assert.NilError(t, err)
			config := string(data)
			credentials := ""
			files, err := credentialProfileFiles(true)
			assert.NilError(t, err)
			command := readCredentialProfile(files, "default", true).values["credential_process"]
			switch test {
			case "unknown lines":
				config += "unrecognized line\n"
			case "cleared role":
				config += "role_arn = arn:aws:iam::123456789012:role/synthetic-role\n"
				credentials = "[process]\nrole_arn = \"\"\n"
			case "cleared source":
				config += "role_arn = arn:aws:iam::123456789012:role/synthetic-role\nsource_profile = default\ncredential_process = \"\"\n"
				credentials = "[process]\nrole_arn = \"\"\nsource_profile = \"\"\ncredential_process = " + command + "\n"
			case "unquoted empty role":
				credentials = "[process]\nrole_arn =\n"
			case "duplicate section":
				config = "[profile process]\nrole_arn = arn:aws:iam::123456789012:role/synthetic-role\n" + config
			case "mixed case role":
				config += "Role_Arn = arn:aws:iam::123456789012:role/synthetic-role\n"
			case "trailing backslash":
				config = strings.ReplaceAll(config, "[profile process]\n", "[profile process]\nunused_path = path\\\n")
			}
			assert.NilError(t, os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(config), 0600))
			assert.NilError(t, os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte(credentials), 0600))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			}))
			defer server.Close()
			endpoint, err := url.Parse(server.URL)
			assert.NilError(t, err)
			original := http.DefaultClient
			http.DefaultClient = &http.Client{Transport: credentialServiceTransport{endpoint: endpoint, requests: make(chan string, 8)}}
			t.Cleanup(func() { http.DefaultClient = original })
			raw, err := session.NewSessionWithOptions(session.Options{Profile: "process", SharedConfigState: session.SharedConfigEnable})
			assert.NilError(t, err)
			want, err := raw.Config.Credentials.Get()
			assert.NilError(t, err)
			safe, err := globalSessionCache.newSession(context.Background(), Options{Profile: "process", LogLevel: log.LevelError})
			assert.NilError(t, err)
			got, err := safe.Config.Credentials.Get()
			assert.NilError(t, err)
			assert.Equal(t, got.ProviderName, want.ProviderName)
			assert.Equal(t, got.SecretAccessKey, want.SecretAccessKey)
			assert.Equal(t, got.SessionToken, want.SessionToken)
		})
	}
}

func TestHTTPSContainerCredentials(t *testing.T) {
	binary := buildCredentialProcess(t)
	credentialProcessConfig(t, binary, "success")
	assert.NilError(t, os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), nil, 0600))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("Authorization"), "synthetic-container-authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"AccessKeyId": "synthetic-container-key", "SecretAccessKey": "synthetic-container-secret",
			"Token": "synthetic-container-session", "Expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer server.Close()
	// Exercise an HTTPS hostname rather than a literal loopback address.
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", strings.Replace(server.URL, "127.0.0.1", "credentials.example.invalid", 1))
	authorizationFile := filepath.Join(t.TempDir(), "authorization")
	assert.NilError(t, os.WriteFile(authorizationFile, []byte("synthetic-container-authorization"), 0600))
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", authorizationFile)
	original := http.DefaultClient
	http.DefaultClient = server.Client()
	http.DefaultClient.Transport.(*http.Transport).TLSClientConfig.ServerName = "127.0.0.1"
	http.DefaultClient.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(func() { http.DefaultClient = original })
	sess, err := globalSessionCache.newSession(context.Background(), Options{LogLevel: log.LevelError})
	assert.NilError(t, err)
	value, err := sess.Config.Credentials.Get()
	assert.NilError(t, err)
	assert.Equal(t, value.AccessKeyID, "synthetic-container-key")
}
