package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OSRunner executes subprocesses on the host operating system.
type OSRunner struct {
	BaseTempDir string
}

// NewOSRunner initializes an OSRunner with an optional base temporary directory.
func NewOSRunner(baseTempDir string) *OSRunner {
	if baseTempDir == "" {
		baseTempDir = filepath.Join(os.TempDir(), "exposureguard")
	}
	return &OSRunner{
		BaseTempDir: baseTempDir,
	}
}

// LookPath locates the binary using ExposureGuard discovery priority.
func (r *OSRunner) LookPath(binary string) (string, error) {
	return ResolveBinaryPath(binary)
}

// DetectVersion executes the binary with discovery flags and extracts its version string.
func (r *OSRunner) DetectVersion(ctx context.Context, binary string, args []string) (string, error) {
	binPath, err := r.LookPath(binary)
	if err != nil {
		return "", NewError(ErrNotInstalled, binary, fmt.Sprintf("binary %q not found", binary), err)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, binPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// Clean basic environment
	cmd.Env = sanitizeEnvironment(nil)

	_ = cmd.Run() // Many security tools print version on stderr or exit 1; check both

	combined := outBuf.String() + "\n" + errBuf.String()
	version := ExtractVersion(combined)
	if version == "" {
		return "", NewError(ErrUnsupportedVersion, binary, fmt.Sprintf("unable to detect version from %s output", binary), nil)
	}
	return version, nil
}

// Run executes an ExecutionPlan under strict resource bounds and context timeouts.
func (r *OSRunner) Run(ctx context.Context, plan ExecutionPlan) (*RunResult, error) {
	binPath, err := r.LookPath(plan.Command.Binary)
	if err != nil {
		return nil, NewError(ErrNotInstalled, plan.Command.Binary, fmt.Sprintf("binary %q not installed", plan.Command.Binary), err)
	}

	// 1. Isolate temporary directory
	scanDir := filepath.Join(r.BaseTempDir, fmt.Sprintf("proc-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(scanDir, 0o700); err != nil {
		return nil, NewError(ErrInternal, plan.Command.Binary, "creating temp execution directory failed", err)
	}

	workDir := plan.Command.WorkingDir
	if workDir == "" {
		workDir = scanDir
	}

	// 2. Timeout context
	runCtx := ctx
	var cancel context.CancelFunc
	if plan.Command.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, plan.Command.Timeout)
		defer cancel()
	}

	// 3. Prepare command
	cmd := exec.Command(binPath, plan.Command.Args...)
	cmd.Dir = workDir
	cmd.Env = sanitizeEnvironment(plan.Command.Env)
	prepareCommand(cmd)

	// 4. Output capture setup
	maxStdout := plan.Command.MaxStdoutBytes
	if maxStdout <= 0 {
		maxStdout = 50 * 1024 * 1024 // 50MB default
	}
	maxStderr := plan.Command.MaxStderrBytes
	if maxStderr <= 0 {
		maxStderr = 2 * 1024 * 1024 // 2MB default
	}

	var limitHit atomic.Bool
	stdoutPath := filepath.Join(scanDir, "stdout.data")
	stdoutFile, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = os.RemoveAll(scanDir)
		return nil, NewError(ErrInternal, plan.Command.Binary, "opening stdout file failed", err)
	}

	bw := &boundedWriter{
		w:     stdoutFile,
		limit: maxStdout,
		onLimit: func() {
			limitHit.Store(true)
			terminateProcess(cmd, 200*time.Millisecond)
		},
	}
	cmd.Stdout = bw

	stderrBuf := &boundedBuffer{limit: maxStderr}
	cmd.Stderr = stderrBuf

	// 5. Start process
	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		_ = stdoutFile.Close()
		_ = os.RemoveAll(scanDir)
		return nil, NewError(ErrProcessFailed, plan.Command.Binary, "failed to start process", err)
	}

	// 6. Monitor process cancellation and completion
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var waitErr error
	select {
	case <-runCtx.Done():
		terminateProcess(cmd, 500*time.Millisecond)
		<-done
		_ = stdoutFile.Close()
		_ = os.RemoveAll(scanDir)
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return nil, NewError(ErrTimeout, plan.Command.Binary, "process execution timed out", runCtx.Err())
		}
		return nil, NewError(ErrCancelled, plan.Command.Binary, "process execution cancelled", runCtx.Err())

	case waitErr = <-done:
	}

	duration := time.Since(startTime)
	_ = stdoutFile.Close()

	if limitHit.Load() {
		_ = os.RemoveAll(scanDir)
		return nil, NewError(ErrOutputLimit, plan.Command.Binary, fmt.Sprintf("stdout exceeded limit of %d bytes", maxStdout), nil)
	}

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			_ = os.RemoveAll(scanDir)
			return nil, NewError(ErrProcessFailed, plan.Command.Binary, "process exited abnormally", waitErr)
		}
	}

	// 7. Locate output reader
	var readPath string
	if plan.OutputSource == OutputSourceFile && plan.OutputFilePath != "" {
		readPath = plan.OutputFilePath
	} else {
		readPath = stdoutPath
	}

	rf, err := os.Open(readPath)
	if err != nil {
		_ = os.RemoveAll(scanDir)
		if exitCode != 0 {
			return nil, NewError(ErrProcessFailed, plan.Command.Binary, fmt.Sprintf("process failed with exit code %d and output not found: %s", exitCode, stderrBuf.String()), waitErr)
		}
		return nil, NewError(ErrInternal, plan.Command.Binary, fmt.Sprintf("unable to open output file %s", readPath), err)
	}

	reader := &cleanupReadCloser{
		file: rf,
		dir:  scanDir,
	}

	return &RunResult{
		ExitCode: exitCode,
		Stdout:   reader,
		Stderr:   stderrBuf.String(),
		Duration: duration,
	}, nil
}

// sanitizeEnvironment retains only safe host variables and prevents secret leakage.
func sanitizeEnvironment(extraEnv []string) []string {
	safeKeys := map[string]bool{
		"PATH":       true,
		"HOME":       true,
		"USER":       true,
		"LOGNAME":    true,
		"SHELL":      true,
		"LANG":       true,
		"LC_ALL":     true,
		"LC_CTYPE":   true,
		"TMPDIR":     true,
		"TEMP":       true,
		"TMP":        true,
		"SYSTEMROOT": true,
		"WINDIR":     true,
		"COMSPEC":    true,
		"PATHEXT":    true,
		"TZ":         true,
	}

	var cleaned []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 0 {
			continue
		}
		key := strings.ToUpper(parts[0])
		if isSensitiveEnvKey(key) {
			continue
		}
		if safeKeys[key] {
			cleaned = append(cleaned, env)
		}
	}

	for _, e := range extraEnv {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 && !isSensitiveEnvKey(strings.ToUpper(parts[0])) {
			cleaned = append(cleaned, e)
		}
	}
	return cleaned
}

func isSensitiveEnvKey(key string) bool {
	upper := strings.ToUpper(key)
	sensitiveTokens := []string{
		"SECRET", "TOKEN", "KEY", "PASSWORD", "PASS", "AUTH", "CREDENTIAL",
		"AWS_", "GCP_", "AZURE_", "DATABASE", "DB_", "EXPOSUREGUARD_CLOUD",
	}
	for _, tok := range sensitiveTokens {
		if strings.Contains(upper, tok) {
			return true
		}
	}
	return false
}

type boundedWriter struct {
	w       io.Writer
	limit   int64
	written int64
	onLimit func()
	once    sync.Once
}

func (b *boundedWriter) Write(p []byte) (n int, err error) {
	if b.written >= b.limit {
		b.once.Do(b.onLimit)
		return 0, fmt.Errorf("write limit reached")
	}
	remaining := b.limit - b.written
	toWrite := p
	if int64(len(p)) > remaining {
		toWrite = p[:remaining]
	}
	n, err = b.w.Write(toWrite)
	b.written += int64(n)
	if b.written >= b.limit {
		b.once.Do(b.onLimit)
	}
	return n, err
}

type boundedBuffer struct {
	buf   bytes.Buffer
	limit int64
	mu    sync.Mutex
}

func (b *boundedBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if int64(b.buf.Len()) >= b.limit {
		return len(p), nil
	}
	avail := b.limit - int64(b.buf.Len())
	if int64(len(p)) > avail {
		p = p[:avail]
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type cleanupReadCloser struct {
	file *os.File
	dir  string
	once sync.Once
}

func (c *cleanupReadCloser) Read(p []byte) (int, error) {
	return c.file.Read(p)
}

func (c *cleanupReadCloser) Close() error {
	err := c.file.Close()
	c.once.Do(func() {
		_ = os.RemoveAll(c.dir)
	})
	return err
}
