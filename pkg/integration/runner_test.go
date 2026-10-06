package integration_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/integration"
)

func TestExtractAndCompareVersions(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"[INF] Current Version: v2.16.0", "2.16.0"},
		{"[INF] Current version: v1.8.0", "1.8.0"},
		{"[INF] Nuclei Engine Version: v3.11.1", "3.11.1"},
		{"subfinder version 2.6.5", "2.6.5"},
		{"1.12.0", "1.12.0"},
	}

	for _, c := range cases {
		got := integration.ExtractVersion(c.input)
		if got != c.expected {
			t.Errorf("ExtractVersion(%q) = %q; want %q", c.input, got, c.expected)
		}
	}

	if integration.CompareVersions("2.16.0", "2.6.0") <= 0 {
		t.Error("expected 2.16.0 > 2.6.0")
	}
	if integration.CompareVersions("1.8.0", "1.8.0") != 0 {
		t.Error("expected 1.8.0 == 1.8.0")
	}
	if integration.CompareVersions("1.7.9", "1.8.0") >= 0 {
		t.Error("expected 1.7.9 < 1.8.0")
	}
}

func TestOSRunnerEcho(t *testing.T) {
	runner := integration.NewOSRunner(t.TempDir())

	plan := integration.ExecutionPlan{
		Command: integration.CommandSpec{
			Binary:         "echo",
			Args:           []string{"hello world"},
			Timeout:        2 * time.Second,
			MaxStdoutBytes: 1024,
			MaxStderrBytes: 1024,
		},
		OutputSource: integration.OutputSourceStdout,
	}

	ctx := context.Background()
	res, err := runner.Run(ctx, plan)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	defer res.Stdout.Close()

	body, err := io.ReadAll(res.Stdout)
	if err != nil {
		t.Fatalf("reading stdout failed: %v", err)
	}

	if !strings.Contains(string(body), "hello world") {
		t.Fatalf("unexpected stdout: %q", string(body))
	}
}

func TestOSRunnerTimeout(t *testing.T) {
	runner := integration.NewOSRunner(t.TempDir())

	plan := integration.ExecutionPlan{
		Command: integration.CommandSpec{
			Binary:         "sleep",
			Args:           []string{"5"},
			Timeout:        50 * time.Millisecond,
			MaxStdoutBytes: 1024,
			MaxStderrBytes: 1024,
		},
		OutputSource: integration.OutputSourceStdout,
	}

	ctx := context.Background()
	_, err := runner.Run(ctx, plan)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !integration.IsErrorCode(err, integration.ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
}

func TestResolveBinaryPathWithEnv(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-tool")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("EXPOSUREGUARD_FAKE_TOOL_PATH", fakeBin)
	resolved, err := integration.ResolveBinaryPath("fake-tool")
	if err != nil {
		t.Fatalf("expected resolution via env, got: %v", err)
	}
	if resolved != fakeBin {
		t.Fatalf("expected %q, got %q", fakeBin, resolved)
	}
}
