package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

// processCredentials owns the execution boundary so helper output never reaches
// SDK diagnostics. credentials.Credentials serializes retrieval and renewal.
type processCredentials struct {
	credentials.Expiry
	command string
	timeout time.Duration
	static  bool
	scope   *credentialProcessScope
}

type credentialProcessContextKey struct{}

type credentialProcessScope struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
}

// WithCredentialProcessContext ties credential helpers to the application
// lifetime. Call the returned function before shutdown to stop and reap helpers.
func WithCredentialProcessContext(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	scope := &credentialProcessScope{ctx: ctx, cancel: cancel}
	return context.WithValue(ctx, credentialProcessContextKey{}, scope), func() {
		scope.mu.Lock()
		scope.closed = true
		scope.cancel()
		scope.mu.Unlock()
		scope.active.Wait()
	}
}

func (s *credentialProcessScope) start() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return false
	}
	s.active.Add(1)
	return true
}

func (p *processCredentials) Retrieve() (credentials.Value, error) {
	parent := context.Background()
	if p.scope != nil {
		if !p.scope.start() {
			return credentials.Value{}, processCredentialError("credential process cancelled")
		}
		defer p.scope.active.Done()
		parent = p.scope.ctx
	}
	ctx, cancel := context.WithTimeout(parent, p.timeout)
	defer cancel()
	if strings.TrimSpace(p.command) == "" {
		return credentials.Value{}, processCredentialError("credential process command is empty")
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", p.command)
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/C", p.command)
	}
	configureCredentialProcess(cmd)
	// Descendants may retain stdout after the helper exits.
	cmd.WaitDelay = time.Second
	output := &credentialOutput{}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			if ctx.Err() == context.Canceled {
				return credentials.Value{}, processCredentialError("credential process cancelled")
			}
			return credentials.Value{}, processCredentialError("credential process timed out")
		}
		return credentials.Value{}, processCredentialError("credential process execution failed")
	}
	var response struct {
		Version         int
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string
		SessionToken    string
		Expiration      *time.Time
	}
	data := output.buffer.Bytes()
	if runtime.GOOS == "windows" {
		data = bytes.ReplaceAll(data, []byte(`\"`), []byte(`"`))
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return credentials.Value{}, processCredentialError("credential process returned invalid JSON")
	}
	if response.Version != 1 || response.AccessKeyID == "" || response.SecretAccessKey == "" {
		return credentials.Value{}, processCredentialError("credential process returned invalid credentials")
	}
	p.static = response.Expiration == nil
	if response.Expiration != nil {
		if !response.Expiration.After(time.Now()) {
			return credentials.Value{}, processCredentialError("credential process returned expired credentials")
		}
		p.SetExpiration(*response.Expiration, 0)
	}
	return credentials.Value{
		ProviderName: "ProcessProvider", AccessKeyID: response.AccessKeyID,
		SecretAccessKey: response.SecretAccessKey, SessionToken: response.SessionToken,
	}, nil
}

func processCredentialError(message string) error {
	return awserr.New("ProcessProviderError", message, nil)
}

func (p *processCredentials) IsExpired() bool {
	return !p.static && p.Expiry.IsExpired()
}

// Reject overflow rather than parsing a prefix of an oversized response.
type credentialOutput struct{ buffer bytes.Buffer }

func (b *credentialOutput) Write(data []byte) (int, error) {
	if len(data) > 8*1024-b.buffer.Len() {
		return 0, io.ErrShortBuffer
	}
	return b.buffer.Write(data)
}
