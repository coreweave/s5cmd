package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/peak/s5cmd/v2/storage"
	"gotest.tools/v3/assert"
)

func credentialProcessCommand(t *testing.T, helper, mode, endpoint string, args ...string) (*exec.Cmd, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profile files")
	assert.NilError(t, os.Mkdir(dir, 0700))
	state := filepath.Join(dir, "invocations")
	config := filepath.Join(dir, "config")
	command := fmt.Sprintf("exec %q %s %q", helper, mode, state)
	if runtime.GOOS == "windows" {
		command = fmt.Sprintf("call \"%s\" %s \"%s\"", helper, mode, state)
	}
	assert.NilError(t, os.WriteFile(config, []byte("[profile process]\ncredential_process = "+command+"\n"), 0600))
	credentials := filepath.Join(dir, "credentials")
	assert.NilError(t, os.WriteFile(credentials, nil, 0600))
	env := make([]string, 0, len(os.Environ()))
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "AWS_") {
			env = append(env, value)
		}
	}
	env = append(env,
		"AWS_CONFIG_FILE="+config,
		"AWS_SHARED_CREDENTIALS_FILE="+credentials,
		"AWS_PROFILE=process",
		"AWS_REGION=us-east-1",
		"AWS_EC2_METADATA_DISABLED=true",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, s5cmdPath, append([]string{"--endpoint-url", endpoint, "--retry-count", "0"}, args...)...)
	cmd.Env = env
	return cmd, state
}

func TestCredentialProcessCLI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "helper files")
	assert.NilError(t, os.Mkdir(dir, 0700))
	helper := filepath.Join(dir, "credential-process.exe")
	build := exec.Command("go", "build", "-o", helper, "../internal/testdata/credential-process/main.go")
	output, err := build.CombinedOutput()
	assert.NilError(t, err, "build credential process: %s", output)

	t.Run("explicit virtual-host style for custom endpoints", func(t *testing.T) {
		for _, force := range []bool{false, true} {
			t.Run(fmt.Sprint(force), func(t *testing.T) {
				hosts := make(chan string, 1)
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hosts <- r.Host
					_, _ = io.WriteString(w, `<ListBucketResult><Name>testbucket</Name><IsTruncated>false</IsTruncated></ListBucketResult>`)
				}))
				defer proxy.Close()
				args := []string{"ls", "s3://testbucket/"}
				if force {
					args = append([]string{"--use-virtual-host-style"}, args...)
				}
				cmd, _ := credentialProcessCommand(t, helper, "success", "http://objects.example.invalid", args...)
				cmd.Env = append(cmd.Env, "HTTP_PROXY="+proxy.URL, "NO_PROXY=")
				_, err := cmd.CombinedOutput()
				assert.NilError(t, err)
				want := "objects.example.invalid"
				if force {
					want = "testbucket." + want
				}
				assert.Equal(t, <-hosts, want)
			})
		}
	})

	t.Run("helper cannot consume command input", func(t *testing.T) {
		requests := make(chan struct{}, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests <- struct{}{}
			_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name><IsTruncated>false</IsTruncated></ListBucketResult>`)
		}))
		defer server.Close()
		cmd, _ := credentialProcessCommand(t, helper, "read-stdin", server.URL, "--numworkers", "1", "run")
		stdin, err := cmd.StdinPipe()
		assert.NilError(t, err)
		defer stdin.Close()
		assert.NilError(t, cmd.Start())
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		_, err = io.WriteString(stdin, "ls s3://bucket/\n")
		assert.NilError(t, err)
		select {
		case <-requests:
		case <-time.After(5 * time.Second):
			t.Fatal("credential helper must not wait on command input")
		}
		assert.NilError(t, stdin.Close())
		assert.NilError(t, cmd.Wait())
	})

	t.Run("successful requests do not log credentials", func(t *testing.T) {
		for _, level := range []string{"info", "debug", "trace"} {
			t.Run(level, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/xml")
					_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name><IsTruncated>false</IsTruncated></ListBucketResult>`)
				}))
				defer server.Close()
				cmd, _ := credentialProcessCommand(t, helper, "success", server.URL, "--log", level, "ls", "s3://bucket/")
				output, err := cmd.CombinedOutput()
				assert.NilError(t, err)
				for _, secret := range []string{"synthetic-process-key", "synthetic-process-secret", "synthetic-process-session"} {
					assert.Assert(t, !strings.Contains(string(output), secret), "successful request logs must exclude credentials")
				}
			})
		}
	})

	t.Run("explicit profile overrides environment", func(t *testing.T) {
		requests := make(chan string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests <- r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name><IsTruncated>false</IsTruncated></ListBucketResult>`)
		}))
		defer server.Close()
		cmd, state := credentialProcessCommand(t, helper, "success", server.URL, "--profile", "process", "ls", "s3://bucket/")
		cmd.Env = append(cmd.Env, "AWS_ACCESS_KEY_ID=synthetic-env-key", "AWS_SECRET_ACCESS_KEY=synthetic-env-secret")
		output, err := cmd.CombinedOutput()
		assert.NilError(t, err, "CLI output: %s", output)
		select {
		case signed := <-requests:
			assert.Assert(t, strings.Contains(signed, "synthetic-process-key-1/"))
		default:
			t.Fatal("signed request was not received")
		}
		data, err := os.ReadFile(state)
		assert.NilError(t, err)
		assert.Equal(t, string(data), "1")
	})

	t.Run("initial failure", func(t *testing.T) {
		for _, mode := range []string{"malformed", "exit", "valid-exit", "oversized"} {
			for _, level := range []string{"info", "debug", "trace"} {
				t.Run(mode+"/"+level, func(t *testing.T) {
					requests := make(chan struct{}, 1)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						requests <- struct{}{}
						w.WriteHeader(http.StatusInternalServerError)
					}))
					defer server.Close()
					cmd, _ := credentialProcessCommand(t, helper, mode, server.URL, "--log", level, "ls", "s3://bucket/")
					output, err := cmd.CombinedOutput()
					assert.Assert(t, err != nil, "initial authentication failure must fail the CLI")
					assert.Assert(t, !strings.Contains(string(output), "synthetic-private-"), "provider diagnostics must not expose credentials")
					assert.Assert(t, strings.Contains(string(output), "ProcessProvider"), "failure must retain a provider diagnostic")
					assert.Equal(t, len(requests), 0, "storage must not be contacted without credentials")
				})
			}
		}
	})

	t.Run("renewal in one process", func(t *testing.T) {
		for _, mode := range []string{"refresh", "renew-malformed", "renew-exit", "renew-valid-exit", "renew-oversized"} {
			t.Run(mode, func(t *testing.T) {
				requests := make(chan string, 4)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests <- r.Header.Get("Authorization") + " " + r.Header.Get("X-Amz-Security-Token")
					w.Header().Set("Content-Type", "application/xml")
					_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name><IsTruncated>false</IsTruncated></ListBucketResult>`)
				}))
				defer server.Close()
				cmd, state := credentialProcessCommand(t, helper, mode, server.URL, "--numworkers", "1", "--log", "debug", "run")
				stdin, err := cmd.StdinPipe()
				assert.NilError(t, err)
				defer stdin.Close()
				var output bytes.Buffer
				cmd.Stdout, cmd.Stderr = &output, &output
				assert.NilError(t, cmd.Start())
				t.Cleanup(func() { _ = cmd.Process.Kill() })
				_, err = io.WriteString(stdin, "ls s3://bucket/\n")
				assert.NilError(t, err)
				select {
				case signed := <-requests:
					assert.Assert(t, strings.Contains(signed, "synthetic-process-key-1/"))
					assert.Assert(t, strings.Contains(signed, "synthetic-process-session"))
				case <-time.After(10 * time.Second):
					t.Fatal("first signed request was not received")
				}
				time.Sleep(1100 * time.Millisecond)
				_, err = io.WriteString(stdin, "ls s3://bucket/\n")
				assert.NilError(t, err)
				assert.NilError(t, stdin.Close())
				err = cmd.Wait()
				assert.Assert(t, !strings.Contains(output.String(), "synthetic-private-"), "failed renewal must not expose provider output")
				if mode == "refresh" {
					assert.NilError(t, err, "CLI output: %s", output.String())
					select {
					case signed := <-requests:
						assert.Assert(t, strings.Contains(signed, "synthetic-process-key-2/"), "second request must use refreshed credentials")
						assert.Assert(t, strings.Contains(signed, "synthetic-process-session"))
					default:
						t.Fatal("second signed request was not received")
					}
				} else {
					assert.Assert(t, err != nil, "failed renewal must fail the CLI")
					assert.Equal(t, len(requests), 0, "failed renewal must not send a stale signed request")
					assert.Assert(t, strings.Contains(output.String(), "ProcessProvider"))
				}
				data, err := os.ReadFile(state)
				assert.NilError(t, err)
				assert.Equal(t, string(data), "2", "one CLI process must invoke the provider again after expiration")
			})
		}
	})
}

func TestLiveFixtureRenewableCredentials(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "credential-process.exe")
	build := exec.Command("go", "build", "-o", helper, "../internal/testdata/credential-process/main.go")
	output, err := build.CombinedOutput()
	assert.NilError(t, err, "build credential process: %s", output)
	for _, mode := range []string{"refresh", "renew-malformed"} {
		t.Run(mode, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			config := filepath.Join(t.TempDir(), "config")
			command := fmt.Sprintf("exec %q %s %q", helper, mode, state)
			if runtime.GOOS == "windows" {
				command = fmt.Sprintf("call \"%s\" %s \"%s\"", helper, mode, state)
			}
			assert.NilError(t, os.WriteFile(config, []byte("[profile acceptance]\ncredential_process = "+command+"\n"), 0600))
			credentials := filepath.Join(t.TempDir(), "credentials")
			assert.NilError(t, os.WriteFile(credentials, nil, 0600))
			for _, value := range os.Environ() {
				key := strings.SplitN(value, "=", 2)[0]
				if strings.HasPrefix(key, "AWS_") {
					t.Setenv(key, "")
				}
			}
			for key, value := range map[string]string{
				"S5CMD_TEST_MODE": "live", "S5CMD_TEST_ENDPOINT_URL": "https://storage.example.invalid", "S5CMD_REGION": "us-east-1",
				"S5CMD_IS_VIRTUAL_HOST": "true", "S5CMD_I_KNOW_WHAT_IM_DOING": "1", "S5CMD_ACCESS_KEY_ID": "", "S5CMD_SECRET_ACCESS_KEY": "",
				"AWS_PROFILE": "acceptance", "AWS_CONFIG_FILE": config, "AWS_SHARED_CREDENTIALS_FILE": credentials,
			} {
				t.Setenv(key, value)
			}
			client := s3client(t, storage.Options{}, nil)
			first, err := client.Config.Credentials.Get()
			assert.NilError(t, err)
			assert.Equal(t, first.ProviderName, "ProcessProvider")
			time.Sleep(1100 * time.Millisecond)
			second, err := client.Config.Credentials.Get()
			if mode == "refresh" {
				assert.NilError(t, err)
				assert.Assert(t, first.AccessKeyID != second.AccessKeyID)
			} else {
				assert.Assert(t, err != nil)
				assert.Assert(t, !strings.Contains(err.Error(), "synthetic-private-"))
			}
			data, err := os.ReadFile(state)
			assert.NilError(t, err)
			assert.Equal(t, string(data), "2")
		})
	}
}
