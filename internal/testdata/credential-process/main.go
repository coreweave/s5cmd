// The credential process emits synthetic credentials for provider regression tests.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	mode, state := os.Args[1], os.Args[2]
	if mode == "sleep" {
		if err := os.WriteFile(state+".pid", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(2)
		}
		for count := 0; count < 3000; count++ {
			if err := os.WriteFile(state, []byte(strconv.Itoa(count)), 0600); err != nil {
				os.Exit(2)
			}
			time.Sleep(20 * time.Millisecond)
		}
		return
	}
	data, err := os.ReadFile(state)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		os.Exit(2)
	}
	count, _ := strconv.Atoi(string(data))
	count++
	if err := os.WriteFile(state, []byte(strconv.Itoa(count)), 0600); err != nil {
		os.Exit(2)
	}
	if mode == "read-stdin" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil || len(data) != 0 {
			os.Exit(2)
		}
	}

	failure := strings.TrimPrefix(mode, "renew-")
	failNow := !strings.HasPrefix(mode, "renew-") || count > 1
	if failNow {
		switch failure {
		case "malformed":
			fmt.Print(`{"SecretAccessKey":"synthetic-private-secret","AccessKeyId":"synthetic-private-key","SessionToken":"synthetic-private-session","Token":"synthetic-private-jwt"`)
			return
		case "exit":
			fmt.Fprintln(os.Stderr, "synthetic-private-secret synthetic-private-key synthetic-private-session synthetic-private-jwt")
			os.Exit(2)
		}
	}

	expiration := time.Now().Add(time.Hour)
	if count == 1 && (mode == "refresh" || strings.HasPrefix(mode, "renew-")) {
		expiration = time.Now().Add(time.Second)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
		"Version":         1,
		"AccessKeyId":     fmt.Sprintf("synthetic-process-key-%d", count),
		"SecretAccessKey": "synthetic-process-secret",
		"SessionToken":    "synthetic-process-session",
		"Expiration":      expiration.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		os.Exit(2)
	}
	if failNow && failure == "valid-exit" {
		_ = os.Stdout.Close()
		time.Sleep(100 * time.Millisecond)
		fmt.Fprintln(os.Stderr, "synthetic-private-secret synthetic-private-key synthetic-private-session synthetic-private-jwt")
		os.Exit(2)
	}
	if failNow && failure == "oversized" {
		fmt.Print(strings.Repeat(" ", 16*1024))
	}
}
