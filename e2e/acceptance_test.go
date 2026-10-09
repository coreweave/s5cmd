package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

func isMissingBucket(err error) bool {
	var failure awserr.RequestFailure
	return errors.As(err, &failure) && failure.StatusCode() == 404
}

// TestAcceptanceStorage is the complete live suite. It uses one disposable
// bucket and never lists or modifies resources belonging to another run.
func TestAcceptanceStorage(t *testing.T) {
	if !isEndpointFromEnv() {
		t.Skip("external storage is not selected")
	}
	ctx, cancel := context.WithTimeout(acceptanceContext, 15*time.Minute)
	defer cancel()
	client, command := setup(t)
	if os.Getenv("S5CMD_TEST_MODE") == "live" {
		if _, err := client.Config.Credentials.GetWithContext(ctx); err != nil {
			t.Fatal("live fixture credential preflight failed")
		}
		expiration, err := client.Config.Credentials.ExpiresAt()
		if err != nil || !expiration.After(time.Now()) {
			t.Fatal("live credentials must have a future expiration")
		}
	}
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal("resource identifier generation failed")
	}
	bucket := "s5cmd-acceptance-" + hex.EncodeToString(suffix[:])
	uri := "s3://" + bucket + "/"
	ledger := os.Getenv("S5CMD_TEST_RESOURCE_FILE")
	if ledger != "" {
		file, err := os.OpenFile(ledger, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("resource ledger creation failed")
		}
		_, writeErr := io.WriteString(file, bucket+"\n")
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("resource ledger write failed")
		}
	}
	// Register cleanup before creating the bucket: a lost response can hide a
	// successful creation. Cleanup uses its own deadline after suite cancellation.
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 3*time.Minute)
		defer stop()
		if err := cleanAcceptanceBucket(cleanupCtx, client, bucket); err != nil {
			t.Error("acceptance resource cleanup failed")
		} else if ledger != "" {
			if err := os.Remove(ledger); err != nil {
				t.Error("resource ledger cleanup failed")
			}
		}
	})
	input := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
	region := aws.StringValue(client.Config.Region)
	if region != "us-east-1" {
		input.CreateBucketConfiguration = &s3.CreateBucketConfiguration{LocationConstraint: aws.String(region)}
	}
	if _, err := client.CreateBucketWithContext(ctx, input); err != nil {
		var failure awserr.RequestFailure
		if errors.As(err, &failure) {
			t.Fatalf("acceptance bucket creation failed (HTTP %d, %s)", failure.StatusCode(), safeStorageErrorCode(failure.Code()))
		}
		t.Fatal("acceptance bucket creation failed")
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer readyCancel()
	for {
		_, err := client.HeadBucketWithContext(readyCtx, &s3.HeadBucketInput{Bucket: aws.String(bucket)})
		if err == nil {
			break
		}
		select {
		case <-readyCtx.Done():
			t.Fatal("acceptance bucket readiness failed")
		case <-time.After(2 * time.Second):
		}
	}
	t.Log("disposable bucket ready")
	dir := t.TempDir()
	run := func(stage string, stdin io.Reader, args ...string) []byte {
		t.Helper()
		spec := command(args...)
		cmdCtx, stop := context.WithTimeout(ctx, 2*time.Minute)
		defer stop()
		cmd := exec.CommandContext(cmdCtx, spec.Command[0], spec.Command[1:]...)
		cmd.Env, cmd.Dir, cmd.Stdin = spec.Env, spec.Dir, stdin
		var out bytes.Buffer
		cmd.Stdout = &out
		// Endpoint URLs, service error bodies and signed headers must not become
		// CI diagnostics. A stage name is enough to identify the failing operation.
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			t.Fatalf("acceptance stage failed: %s", stage)
		}
		return out.Bytes()
	}
	payload := bytes.Repeat([]byte("acceptance-payload\n"), 1024*1024)
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal("payload creation failed")
	}
	run("multipart upload", nil, "cp", "--part-size", "5", "--concurrency", "2", "--metadata", "acceptance=verified", source, uri+"source")
	head, err := client.HeadObjectWithContext(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String("source")})
	metadataOK := false
	if err == nil {
		for key, value := range head.Metadata {
			if strings.EqualFold(key, "acceptance") && aws.StringValue(value) == "verified" {
				metadataOK = true
			}
		}
	}
	if !metadataOK {
		t.Fatal("object metadata validation failed")
	}
	download := filepath.Join(dir, "download")
	run("download", nil, "cp", uri+"source", download)
	got, err := os.ReadFile(download)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("download integrity validation failed")
	}
	run("server-side copy", nil, "cp", "--part-size", "5", "--concurrency", "2", uri+"source", uri+"copy")
	// cat validates the server-side copy without writing object contents to logs.
	if !bytes.Equal(run("copied content", nil, "cat", uri+"copy"), payload) {
		t.Fatal("copy integrity validation failed")
	}
	pipe := []byte("synthetic pipe content\n")
	run("pipe upload", bytes.NewReader(pipe), "pipe", uri+"pipe")
	if !bytes.Equal(run("pipe content", nil, "cat", uri+"pipe"), pipe) {
		t.Fatal("pipe integrity validation failed")
	}
	syncDir := filepath.Join(dir, "sync")
	if err := os.Mkdir(syncDir, 0700); err != nil {
		t.Fatal("sync fixture creation failed")
	}
	if err := os.WriteFile(filepath.Join(syncDir, "present"), pipe, 0600); err != nil {
		t.Fatal("sync fixture creation failed")
	}
	putAcceptanceObject(t, ctx, client, bucket, "sync/stale", pipe)
	run("sync and delete", nil, "sync", "--delete", syncDir+string(os.PathSeparator), uri+"sync/")
	listed, err := client.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String("sync/")})
	if err != nil || len(listed.Contents) != 1 || aws.StringValue(listed.Contents[0].Key) != "sync/present" {
		t.Fatal("sync/delete validation failed")
	}
	// Exceed the service's default 1,000-object page size, using bounded workers
	// and one-byte objects rather than large uploads.
	const count = 1001
	var wg sync.WaitGroup
	tasks := make(chan int)
	failures := make(chan struct{}, count)
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range tasks {
				_, err := client.PutObjectWithContext(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(fmt.Sprintf("pages/%04d", n)), Body: bytes.NewReader([]byte("x"))})
				if err != nil {
					failures <- struct{}{}
				}
			}
		}()
	}
	for n := 0; n < count; n++ {
		tasks <- n
	}
	close(tasks)
	wg.Wait()
	if len(failures) != 0 {
		t.Fatal("pagination fixture creation failed")
	}
	for _, variant := range []string{"v2", "v1"} {
		args := []string{"ls", uri + "pages/*"}
		if variant == "v1" {
			args = append([]string{"--use-list-objects-v1"}, args...)
		}
		output := run("paginated listing "+variant, nil, args...)
		if len(strings.Split(strings.TrimSpace(string(output)), "\n")) != count {
			t.Fatal("paginated CLI listing lost objects")
		}
	}
	run("wildcard deletion", nil, "rm", uri+"pages/*")
	remaining, err := client.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String("pages/")})
	if err != nil || len(remaining.Contents) != 0 {
		t.Fatal("wildcard deletion validation failed")
	}
	// The application must stop promptly when its parent cancels a command.
	cancelCtx, stop := context.WithCancel(ctx)
	spec := command("run")
	blocked := exec.CommandContext(cancelCtx, spec.Command[0], spec.Command[1:]...)
	blocked.Env = spec.Env
	stdin, err := blocked.StdinPipe()
	if err != nil {
		t.Fatal("cancellation fixture failed")
	}
	defer stdin.Close()
	if err := blocked.Start(); err != nil {
		t.Fatal("cancellation command failed to start")
	}
	stop()
	if err := blocked.Wait(); err == nil {
		t.Fatal("cancelled command succeeded")
	}
	t.Log("upload, integrity, metadata, copy, pipe, sync/delete, pagination and cancellation passed")
	acceptanceCompleted = true
}

func safeStorageErrorCode(code string) string {
	switch code {
	case "AccessDenied", "Forbidden", "InvalidAccessKeyId", "InvalidToken", "ExpiredToken", "SignatureDoesNotMatch", "InvalidRegion", "InvalidRequest", "InvalidArgument", "AuthorizationHeaderMalformed", "InvalidLocationConstraint", "NoSuchBucket", "NotImplemented":
		return code
	default:
		return "storage request failed"
	}
}

func putAcceptanceObject(t *testing.T, ctx context.Context, client *s3.S3, bucket, key string, body []byte) {
	t.Helper()
	_, err := client.PutObjectWithContext(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(body)})
	if err != nil {
		t.Fatal("acceptance fixture upload failed")
	}
}

// cleanAcceptanceBucket removes multipart uploads, versions, and objects only
// inside the exact bucket allocated by this run. No account-wide sweep occurs.
func cleanAcceptanceBucket(ctx context.Context, client s3iface.S3API, bucket string) error {
	if !strings.HasPrefix(bucket, "s5cmd-acceptance-") || len(bucket) != len("s5cmd-acceptance-")+24 {
		return fmt.Errorf("invalid cleanup scope")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(bucket, "s5cmd-acceptance-")); err != nil {
		return fmt.Errorf("invalid cleanup scope")
	}
	_, err := client.HeadBucketWithContext(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)})
	if isMissingBucket(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cleanup bucket lookup failed")
	}
	var uploads []*s3.MultipartUpload
	err = client.ListMultipartUploadsPagesWithContext(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(bucket)}, func(page *s3.ListMultipartUploadsOutput, _ bool) bool {
		uploads = append(uploads, page.Uploads...)
		return len(uploads) <= 100
	})
	if err != nil || len(uploads) > 100 {
		return fmt.Errorf("cleanup upload enumeration failed")
	}
	for _, upload := range uploads {
		if _, err := client.AbortMultipartUploadWithContext(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(bucket), Key: upload.Key, UploadId: upload.UploadId}); err != nil {
			return fmt.Errorf("cleanup multipart abort failed")
		}
	}
	var objects []*s3.ObjectIdentifier
	err = client.ListObjectVersionsPagesWithContext(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)}, func(page *s3.ListObjectVersionsOutput, _ bool) bool {
		for _, version := range page.Versions {
			objects = append(objects, &s3.ObjectIdentifier{Key: version.Key, VersionId: version.VersionId})
		}
		for _, marker := range page.DeleteMarkers {
			objects = append(objects, &s3.ObjectIdentifier{Key: marker.Key, VersionId: marker.VersionId})
		}
		return len(objects) <= 3000
	})
	if err != nil || len(objects) > 3000 {
		return fmt.Errorf("cleanup version enumeration failed")
	}
	for len(objects) > 0 {
		n := len(objects)
		if n > 1000 {
			n = 1000
		}
		out, err := client.DeleteObjectsWithContext(ctx, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &s3.Delete{Objects: objects[:n], Quiet: aws.Bool(true)}})
		if err != nil || len(out.Errors) > 0 {
			return fmt.Errorf("cleanup object deletion failed")
		}
		objects = objects[n:]
	}
	if _, err := client.DeleteBucketWithContext(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		return fmt.Errorf("cleanup bucket deletion failed")
	}
	return nil
}
