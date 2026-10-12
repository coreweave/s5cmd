package e2e

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

// TestAcceptanceRecovery is a separate cleanup operation. Its completion never
// substitutes for the full suite in the release gate.
func TestAcceptanceRecovery(t *testing.T) {
	if os.Getenv("S5CMD_TEST_MODE") != "live" {
		t.Skip("live recovery is not selected")
	}
	ledger := os.Getenv("S5CMD_TEST_RESOURCE_FILE")
	if ledger == "" {
		t.Fatal("live recovery requires a private resource ledger")
	}
	client, _ := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := recoverAcceptanceBucket(ctx, client, ledger); err != nil {
		t.Fatal(err)
	}
	acceptanceCompleted = true
}

func recoverAcceptanceBucket(ctx context.Context, client s3iface.S3API, ledger string) error {
	info, err := os.Lstat(ledger)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128 {
		return fmt.Errorf("invalid recovery ledger")
	}
	file, err := os.Open(ledger)
	if err != nil {
		return fmt.Errorf("recovery ledger unavailable")
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, 129))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(contents) > 128 {
		return fmt.Errorf("invalid recovery ledger")
	}
	bucket := strings.TrimSuffix(string(contents), "\n")
	if err := cleanAcceptanceBucket(ctx, client, bucket); err != nil {
		return fmt.Errorf("scoped recovery failed: %w", err)
	}
	if err := os.Remove(ledger); err != nil {
		return fmt.Errorf("recovery ledger removal failed")
	}
	return nil
}
