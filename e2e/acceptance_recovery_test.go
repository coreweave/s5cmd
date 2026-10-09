package e2e

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAcceptanceLedgerRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private ledger permissions require a Unix filesystem")
	}
	const bucket = "s5cmd-acceptance-0123456789abcdef01234567"
	for _, stage := range []string{"success", "absent", "failure", "invalid scope", "public file", "symlink"} {
		t.Run(stage, func(t *testing.T) {
			ledger := filepath.Join(t.TempDir(), "resource")
			fixture := &cleanupFixture{bucket: bucket}
			if stage != "absent" {
				contents := bucket + "\n"
				if stage == "invalid scope" {
					contents = "unrelated-bucket\n"
				}
				if err := os.WriteFile(ledger, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "failure" {
				fixture.fail = "bucket"
			}
			if stage == "public file" {
				if err := os.Chmod(ledger, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "symlink" {
				link := ledger + "-link"
				if err := os.Symlink(ledger, link); err != nil {
					t.Skip("symlink creation unavailable")
				}
				ledger = link
			}
			err := recoverAcceptanceBucket(context.Background(), fixture, ledger)
			if stage == "success" || stage == "absent" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(ledger); !os.IsNotExist(err) {
					t.Fatal("successful recovery retained its ledger")
				}
			} else {
				if err == nil {
					t.Fatal("unsafe or failed recovery succeeded")
				}
				if _, err := os.Lstat(ledger); err != nil {
					t.Fatal("failed recovery lost its ledger")
				}
				if stage != "failure" && (fixture.aborted > 0 || fixture.deleted > 0 || fixture.removed) {
					t.Fatal("unsafe recovery reached storage")
				}
			}
		})
	}
}
