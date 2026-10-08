package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/exposureguard/exposureguard/integrations"
	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/exposureguard/exposureguard/pkg/batch"
	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/engine"
	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/protocol"
	"github.com/spf13/cobra"
)

const (
	maxBatchScans         = 20
	maxBatchDefaultSize   = 16
	maxBatchParallelScans = 4
	maxBatchParallel      = maxBatchParallelScans
	maxBatchProcesses     = 4
	maxBatchRequestBytes  = 8 << 20
	maxBatchEventBytes    = 64 << 20
	maxBatchOutputBytes   = 64 << 20
	maxBatchTempBytes     = 256 << 20
	batchScanConcurrency  = 2
	batchScanRate         = 1.0
)

type batchEventWriter struct {
	mu         sync.Mutex
	writer     io.Writer
	batchID    string
	seq        int64
	written    int64
	limit      int64
	terminal   bool
	fatal      error
	cancel     context.CancelFunc
	scanSeq    map[string]int64
	scanEnd    map[string]bool
	scanStatus map[string]string
	scans      map[string]struct{}
}

func (w *batchEventWriter) failure() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fatal
}

func (w *batchEventWriter) scanStarted(scanID string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.scanSeq[scanID] > 0
}

func (w *batchEventWriter) scanTerminated(scanID string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.scanEnd[scanID]
}

func (w *batchEventWriter) setScans(scans []model.ScanRequest) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.scans = make(map[string]struct{}, len(scans))
	for _, scan := range scans {
		w.scans[scan.ScanID] = struct{}{}
	}
}

func newBatchEventWriter(writer io.Writer, batchID string, limit ...int64) *batchEventWriter {
	maxOutput := int64(maxBatchOutputBytes)
	if len(limit) > 0 && limit[0] > 0 {
		maxOutput = limit[0]
	}
	return &batchEventWriter{writer: writer, batchID: batchID, limit: maxOutput, scanSeq: make(map[string]int64), scanEnd: make(map[string]bool), scanStatus: make(map[string]string), scans: make(map[string]struct{})}
}

func (w *batchEventWriter) emitBatch(kind string, data any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fatal != nil {
		return w.fatal
	}
	if kind != "batch.started" && kind != "batch.completed" && kind != "batch.failed" && kind != "batch.cancelled" {
		return fmt.Errorf("unsupported batch event type %q", kind)
	}
	if w.terminal || (kind == "batch.started" && w.seq != 0) || (kind != "batch.started" && w.seq == 0) {
		return errors.New("invalid batch event order")
	}
	payload, err := json.Marshal(map[string]any{
		"batch_protocol_version": buildinfo.BatchProtocolVersion,
		"seq":                    w.seq + 1,
		"timestamp":              time.Now().UTC(),
		"type":                   kind,
		"batch_id":               w.batchID,
		"data":                   data,
	})
	if err != nil {
		return err
	}
	if kind != "batch.started" {
		for scanID := range w.scans {
			if !w.scanEnd[scanID] {
				return fmt.Errorf("scan %s lacks terminal event", scanID)
			}
		}
		if result, ok := data.(model.BatchResult); ok {
			want := map[model.BatchStatus]string{model.BatchStatusComplete: "batch.completed", model.BatchStatusPartial: "batch.completed", model.BatchStatusFailed: "batch.failed", model.BatchStatusCancelled: "batch.cancelled"}[result.Status]
			if kind != want {
				return fmt.Errorf("%s conflicts with aggregate status %q", kind, result.Status)
			}
		}
	}
	if err := w.writeLocked(payload); err != nil {
		w.terminal = true
		return err
	}
	w.seq++
	if kind == "batch.completed" || kind == "batch.failed" || kind == "batch.cancelled" {
		w.terminal = true
	}
	return nil
}

func (w *batchEventWriter) emitScan(payload []byte) error {
	var event map[string]any
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	scanID, _ := event["scan_id"].(string)
	kind, _ := event["type"].(string)
	localSeq, ok := event["seq"].(float64)
	if !ok || scanID == "" {
		return errors.New("invalid scan event sequence or id")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fatal != nil {
		return w.fatal
	}
	if _, ok := w.scans[scanID]; !ok {
		return errors.New("scan event ID is not present in BatchRequest")
	}
	if int64(localSeq) != w.scanSeq[scanID]+1 {
		return errors.New("invalid per-scan event sequence")
	}
	if w.terminal || w.scanEnd[scanID] {
		return errors.New("event emitted after terminal event")
	}
	if localSeq == 1 && kind != string(protocol.EventScanStarted) {
		return errors.New("scan.started must be first per-scan event")
	}
	if (kind == string(protocol.EventScanCompleted) && statusFromEvent(event) != "complete" && statusFromEvent(event) != "partial") ||
		(kind == string(protocol.EventScanFailed) && statusFromEvent(event) != "failed") ||
		(kind == string(protocol.EventScanCancelled) && statusFromEvent(event) != "cancelled") {
		return fmt.Errorf("scan terminal event %q conflicts with result status %q", kind, statusFromEvent(event))
	}
	if w.seq == 0 {
		return errors.New("batch.started must be first event")
	}
	event["batch_protocol_version"] = buildinfo.BatchProtocolVersion
	event["batch_id"] = w.batchID
	event["scan_seq"] = int64(localSeq)
	event["seq"] = w.seq + 1
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := w.writeLocked(encoded); err != nil {
		w.terminal = true
		return err
	}
	w.seq++
	w.scanSeq[scanID]++
	if kind == string(protocol.EventScanCompleted) || kind == string(protocol.EventScanFailed) || kind == string(protocol.EventScanCancelled) {
		w.scanEnd[scanID] = true
		w.scanStatus[scanID] = statusFromEvent(event)
		if w.scanStatus[scanID] == "" {
			w.scanStatus[scanID] = map[string]string{string(protocol.EventScanCompleted): "complete", string(protocol.EventScanFailed): "failed", string(protocol.EventScanCancelled): "cancelled"}[kind]
		}
	}
	return nil
}

func statusFromEvent(event map[string]any) string {
	data, ok := event["data"].(map[string]any)
	if !ok {
		return ""
	}
	if result, ok := data["result"].(map[string]any); ok {
		if status, ok := result["status"].(string); ok {
			return status
		}
	}
	status, _ := data["status"].(string)
	return status
}

func (w *batchEventWriter) scanHasStarted(scanID string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.scanSeq[scanID] > 0
}

func (w *batchEventWriter) writeLocked(payload []byte) error {
	lineBytes := int64(len(payload) + 1)
	if int64(len(payload)) > maxBatchEventBytes || w.written+lineBytes > w.limit {
		w.fatal = errors.New("batch output budget exceeded")
		w.terminal = true
		if w.cancel != nil {
			w.cancel()
		}
		return w.fatal
	}
	if _, err := w.writer.Write(append(payload, '\n')); err != nil {
		w.fatal = err
		w.terminal = true
		if w.cancel != nil {
			w.cancel()
		}
		return err
	}
	w.written += lineBytes
	if flusher, ok := w.writer.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			w.fatal = err
			w.terminal = true
			if w.cancel != nil {
				w.cancel()
			}
			return err
		}
	}
	return nil
}

type batchOptions struct {
	requestJSON  string
	format       string
	resultOut    string
	allowPrivate bool
	output       io.Writer
}

func newBatchCmd() *cobra.Command {
	opts := &batchOptions{}
	cmd := &cobra.Command{
		Use:   "batch",
		Short: "Execute bounded independent scans as one JSONL stream",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.requestJSON == "" || (opts.format != "jsonl" && opts.format != "json") {
				return &ExitCodeError{Code: 2, Err: errors.New("batch requires --request-json and --format jsonl|json")}
			}
			return runBatch(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.requestJSON, "request-json", "", "BatchRequest file path or '-' for stdin")
	cmd.Flags().StringVar(&opts.format, "format", "jsonl", "output format: jsonl or json")
	cmd.Flags().StringVar(&opts.resultOut, "result-out", "", "optional BatchResult JSON path")
	cmd.Flags().BoolVar(&opts.allowPrivate, "allow-private", false, "allow private targets for controlled local testing")
	return cmd
}

func runBatch(ctx context.Context, opts *batchOptions) error {
	stdout := opts.output
	if stdout == nil {
		stdout = os.Stdout
	}
	return runBatchIO(ctx, opts, os.Stdin, stdout)
}

func runBatchIO(parent context.Context, opts *batchOptions, stdin io.Reader, stdout io.Writer) error {
	payload, err := readBounded(opts.requestJSON, stdin, maxBatchRequestBytes)
	if err != nil {
		return &ExitCodeError{Code: 2, Err: err}
	}
	var request model.BatchRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return &ExitCodeError{Code: 2, Err: fmt.Errorf("invalid BatchRequest: %w", err)}
	}
	parallel, processes, tempBudget, outputBudget, err := batchResourceLimits(request.Limits)
	if err != nil {
		return &ExitCodeError{Code: 2, Err: err}
	}
	if err := validateBatchRequest(request); err != nil {
		return &ExitCodeError{Code: 2, Err: err}
	}
	for _, scan := range request.Scans {
		if scan.PreviousSnapshot != nil {
			encoded, err := json.Marshal(scan.PreviousSnapshot)
			if err != nil || len(encoded) > 4<<20 {
				return &ExitCodeError{Code: 2, Err: fmt.Errorf("scan %s previous_snapshot exceeds 4 MiB", scan.ScanID)}
			}
		}
	}
	if opts.format == "jsonl" && outputBudget < 1<<20 {
		return &ExitCodeError{Code: 2, Err: errors.New("JSONL aggregate output budget must be at least 1 MiB")}
	}
	if opts.format == "jsonl" && opts.resultOut != "" {
		return &ExitCodeError{Code: 2, Err: errors.New("--result-out is only supported with --format json")}
	}
	if opts.format == "json" && int64(len(payload)) > outputBudget {
		return &ExitCodeError{Code: 2, Err: errors.New("BatchRequest exceeds JSON mode output budget")}
	}
	requestBytes := int64(len(payload))
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	startedAt := time.Now().UTC()
	var events *batchEventWriter
	if opts.format == "jsonl" {
		events = newBatchEventWriter(stdout, request.BatchID, outputBudget)
		events.cancel = stop
		events.setScans(request.Scans)
		if err := events.emitBatch("batch.started", map[string]any{"total": len(request.Scans), "started_at": startedAt}); err != nil {
			return &ExitCodeError{Code: 1, Err: err}
		}
	}

	registry := integrations.NewBuiltinRegistry()
	sharedRunner := integration.NewOSRunnerWithLimits("", processes, tempBudget, maxBatchOutputBytes)
	batchTempDir := filepath.Join(os.TempDir(), "exposureguard", request.BatchID)
	if err := os.MkdirAll(batchTempDir, 0o700); err != nil {
		return &ExitCodeError{Code: 1, Err: fmt.Errorf("create batch temp directory: %w", err)}
	}
	defer os.RemoveAll(batchTempDir)
	policy := netguard.NetworkPolicy(netguard.DefaultNetworkPolicy{})
	if opts.allowPrivate {
		policy = netguard.AllowPrivateNetworkPolicy{}
	}
	results := batch.Execute(ctx, request.Scans, parallel, func(ctx context.Context, scan model.ScanRequest) model.BatchScanResult {
		budget := outputBudget - requestBytes
		if events != nil {
			budget = outputBudget / int64(parallel)
		}
		if budget < 1 {
			return failedBatchScan(scan.ScanID, "failed", errors.New("batch output budget exhausted by request"), events)
		}
		return runOneBatchScan(ctx, scan, registry, sharedRunner, events, budget, policy, batchTempDir)
	})
	if events != nil {
		if err := events.failure(); err != nil {
			return &ExitCodeError{Code: 1, Err: err}
		}
	}
	finishedAt := time.Now().UTC()
	result := aggregateBatch(request.BatchID, results, startedAt, finishedAt)
	if opts.resultOut != "" {
		if err := writeBatchResult(opts.resultOut, result, outputBudget); err != nil {
			return &ExitCodeError{Code: 1, Err: err}
		}
	}
	if opts.format == "json" {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil || int64(len(encoded)+1) > outputBudget {
			return &ExitCodeError{Code: 1, Err: errors.New("BatchResult encoding exceeded output budget")}
		}
		_, err = fmt.Fprintln(stdout, string(encoded))
		return err
	}
	terminal := "batch.completed"
	if result.Status == "failed" {
		terminal = "batch.failed"
	} else if result.Status == "cancelled" {
		terminal = "batch.cancelled"
	}
	if err := events.emitBatch(terminal, result); err != nil {
		return &ExitCodeError{Code: 1, Err: err}
	}
	return nil
}

func runOneBatchScan(ctx context.Context, request model.ScanRequest, registry *integration.Registry, runner integration.Runner, events *batchEventWriter, outputBudget int64, policy netguard.NetworkPolicy, tempRoot string) model.BatchScanResult {
	if ctx.Err() != nil {
		return failedBatchScan(request.ScanID, "cancelled", errors.New("batch cancelled before scan started"), events)
	}
	request.SchemaVersion = "1"
	if request.Mode == "" {
		request.Mode = model.ScanModePublic
	}
	if request.Profile == "" {
		request.Profile = "standard"
	}
	request.Limits.Clamp()
	request.Limits.MaxConcurrency = min(request.Limits.MaxConcurrency, batchScanConcurrency)
	request.Limits.MaxPerHostConcurrency = min(request.Limits.MaxPerHostConcurrency, batchScanConcurrency)
	request.Limits.RequestsPerSecondPerHost = min(request.Limits.RequestsPerSecondPerHost, batchScanRate)

	scanOutput := &boundedBatchBuffer{limit: outputBudget}
	var scanWriter io.Writer = scanOutput
	eventLimit := outputBudget
	if events != nil {
		scanWriter = batchScanEventWriter{events: events}
	}
	encoder := protocol.NewEncoderWithLimit(scanWriter, request.ScanID, eventLimit)
	env := checks.NewEnvironmentWithPolicy(nil, nil, policy, request.Limits, encoder)
	result, err := engine.NewEngineWithIntegrations(env, encoder, registry, runner).Run(ctx, engine.Options{Request: request, PreviousSnapshot: request.PreviousSnapshot, IncludeResultInTerminal: true, MaxSnapshotBytes: outputBudget, TempRoot: tempRoot})
	if err != nil {
		status := string(model.ScanStatusFailed)
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status = string(model.ScanStatusCancelled)
		}
		if events != nil && events.failure() != nil {
			return model.BatchScanResult{ScanID: request.ScanID, Status: status, Error: err.Error()}
		}
		if events != nil && events.scanHasStarted(request.ScanID) && events.scanTerminated(request.ScanID) {
			return model.BatchScanResult{ScanID: request.ScanID, Status: status, Error: err.Error()}
		}
		return failedBatchScan(request.ScanID, status, err, events)
	}
	snapshotBytes, err := json.Marshal(result.Snapshot)
	if err != nil || int64(len(snapshotBytes)) > outputBudget {
		return failedBatchScan(request.ScanID, "failed", errors.New("Snapshot exceeds batch output budget"), events)
	}
	if events != nil && events.scanStarted(request.ScanID) && !events.scanTerminated(request.ScanID) {
		return failedBatchScan(request.ScanID, "failed", errors.New("scan terminal event missing from engine output"), events)
	}
	if events == nil {
		if int64(scanOutput.Len()) > outputBudget {
			return failedBatchScan(request.ScanID, "failed", errors.New("ScanResult exceeds batch output budget"), events)
		}
		var encodedResult struct {
			Result *model.ScanResult `json:"result"`
		}
		if err := json.Unmarshal(scanOutput.Bytes(), &encodedResult); err == nil && encodedResult.Result != nil {
			result = encodedResult.Result
		}
	}

	return model.BatchScanResult{ScanID: request.ScanID, Status: string(result.Status), Result: result}
}

type boundedBatchBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (b *boundedBatchBuffer) Write(p []byte) (int, error) {
	if int64(b.buffer.Len()+len(p)) > b.limit {
		return 0, errors.New("batch result output budget exceeded")
	}
	return b.buffer.Write(p)
}

func (b *boundedBatchBuffer) Bytes() []byte { return b.buffer.Bytes() }
func (b *boundedBatchBuffer) Len() int      { return b.buffer.Len() }

func failedBatchScan(scanID, status string, reason error, events *batchEventWriter) model.BatchScanResult {
	message := reason.Error()
	var output bytes.Buffer
	var scanWriter io.Writer = &output
	if events != nil {
		scanWriter = batchScanEventWriter{events: events}
	}
	encoder := protocol.NewEncoder(scanWriter, scanID)
	started := events == nil || !events.scanHasStarted(scanID)
	if started {
		_ = encoder.Emit(protocol.EventScanStarted, map[string]string{"scan_id": scanID})
	}
	if started {
		_ = encoder.Emit(protocol.EventScanSummary, model.ScanStats{})
	}
	terminal := protocol.EventScanFailed
	if status == "cancelled" {
		terminal = protocol.EventScanCancelled
	}
	_ = encoder.Emit(terminal, map[string]any{"status": status, "errors": []string{message}})
	_ = emitScanLines(events, &output)
	if events != nil && events.failure() != nil {
		return model.BatchScanResult{ScanID: scanID, Status: status, Error: message}
	}
	return model.BatchScanResult{ScanID: scanID, Status: status, Error: message}
}

type batchScanEventWriter struct {
	events *batchEventWriter
}

func (w batchScanEventWriter) Write(payload []byte) (int, error) {
	line := bytes.TrimSuffix(payload, []byte{'\n'})
	if err := w.events.emitScan(line); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func emitScanLines(writer *batchEventWriter, output *bytes.Buffer) error {
	if writer == nil {
		return nil
	}
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 64*1024), maxBatchEventBytes)
	for scanner.Scan() {
		if err := writer.emitScan(scanner.Bytes()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func aggregateBatch(id string, scans []model.BatchScanResult, started, finished time.Time) model.BatchResult {
	result := model.BatchResult{ProtocolVersion: buildinfo.BatchProtocolVersion, BatchID: id, ScanCount: len(scans), Scans: scans}
	for _, scan := range scans {
		switch scan.Status {
		case "complete":
			result.CompletedCount++
		case "partial":
			result.PartialCount++
		case "failed":
			result.FailedCount++
		case "cancelled":
			result.CancelledCount++
		}
	}
	switch {
	case result.ScanCount > 0 && result.CancelledCount == result.ScanCount:
		result.Status = model.BatchStatusCancelled
	case result.ScanCount > 0 && result.FailedCount == result.ScanCount:
		result.Status = model.BatchStatusFailed
	case result.PartialCount+result.FailedCount+result.CancelledCount > 0:
		result.Status = model.BatchStatusPartial
	default:
		result.Status = model.BatchStatusComplete
	}
	result.Summary = model.BatchSummary{
		Total: result.ScanCount, Completed: result.CompletedCount, Partial: result.PartialCount,
		Failed: result.FailedCount, Cancelled: result.CancelledCount, StartedAt: started,
		FinishedAt: finished, Duration: int64(finished.Sub(started)), EngineVersion: buildinfo.Version, GitCommit: buildinfo.GitCommit,
	}
	for _, scan := range scans {
		if scan.Result == nil {
			continue
		}
		result.Summary.Assets += len(scan.Result.Snapshot.Assets)
		result.Summary.Observations += len(scan.Result.Snapshot.Observations)
		result.Summary.Findings += len(scan.Result.Snapshot.Findings)
		result.Summary.Changes += len(scan.Result.Changes)
	}
	return result
}

func readBounded(path string, stdin io.Reader, limit int64) ([]byte, error) {
	reader := stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("read BatchRequest: %w", err)
		}
		defer file.Close()
		reader = file
	}
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read BatchRequest: %w", err)
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("BatchRequest exceeds %d byte limit", limit)
	}
	return payload, nil
}

func validateBatchRequest(request model.BatchRequest) error {
	if request.ProtocolVersion != buildinfo.BatchProtocolVersion {
		return fmt.Errorf("unsupported batch protocol version %q", request.ProtocolVersion)
	}
	maxBatchSize := request.Limits.MaxBatchSize
	if maxBatchSize == 0 {
		maxBatchSize = maxBatchDefaultSize
	}
	if maxBatchSize < 1 || maxBatchSize > maxBatchScans {
		return fmt.Errorf("max_batch_size must be 1..%d", maxBatchScans)
	}
	if len(request.Scans) > maxBatchSize {
		return fmt.Errorf("batch contains %d scans, max_batch_size is %d", len(request.Scans), maxBatchSize)
	}
	if !isUUID(request.BatchID) {
		return errors.New("batch_id must be a UUID")
	}
	if len(request.Scans) < 1 || len(request.Scans) > maxBatchScans {
		return fmt.Errorf("batch must contain 1..%d scans", maxBatchScans)
	}
	seen := make(map[string]struct{}, len(request.Scans))
	for _, scan := range request.Scans {
		if scan.SchemaVersion != buildinfo.ProtocolVersion {
			return fmt.Errorf("scan %q has unsupported schema version %q", scan.ScanID, scan.SchemaVersion)
		}
		if !isUUID(scan.ScanID) {
			return errors.New("scan_id must be UUID")
		}
		if _, exists := seen[scan.ScanID]; exists {
			return fmt.Errorf("duplicate scan_id %q", scan.ScanID)
		}
		seen[scan.ScanID] = struct{}{}
		if strings.TrimSpace(scan.Target) == "" {
			return fmt.Errorf("scan %q requires target", scan.ScanID)
		}
		if scan.Profile != "" && scan.Profile != "quick" && scan.Profile != "standard" && scan.Profile != "deep" {
			return fmt.Errorf("scan %q has unsupported profile %q", scan.ScanID, scan.Profile)
		}
		if scan.Mode != "" && scan.Mode != model.ScanModePublic && scan.Mode != model.ScanModeOwned {
			return fmt.Errorf("scan %q has unsupported mode %q", scan.ScanID, scan.Mode)
		}
		if scan.PreviousSnapshot != nil {
			encoded, err := json.Marshal(scan.PreviousSnapshot)
			if err != nil || len(encoded) > 4<<20 {
				return fmt.Errorf("scan %q previous_snapshot exceeds 4 MiB", scan.ScanID)
			}
		}
	}
	return nil
}

func maxParallelScans() (int, error) { return maxBatchParallelScans, nil }

func batchParallelScans(requested int) (int, error) {
	if requested == 0 {
		return maxBatchParallel, nil
	}
	if requested < 1 || requested > maxBatchParallel {
		return 0, fmt.Errorf("max_parallel_scans must be between 1 and %d", maxBatchParallel)
	}
	return requested, nil
}

func batchResourceLimits(request model.BatchLimits) (int, int, int64, int64, error) {
	if request.MaxBatchSize != 0 && (request.MaxBatchSize < 1 || request.MaxBatchSize > maxBatchScans) {
		return 0, 0, 0, 0, fmt.Errorf("max_batch_size must be 1..%d", maxBatchScans)
	}
	parallel, err := batchParallelScans(request.MaxParallelScans)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	processes := request.MaxParallelExternalProcesses
	if processes == 0 {
		processes = min(parallel, maxBatchProcesses)
	}
	if processes < 1 || processes > parallel || processes > maxBatchProcesses {
		return 0, 0, 0, 0, errors.New("max_parallel_external_processes exceeds batch hard limit")
	}
	temp := request.MaxTempBytes
	if temp == 0 {
		temp = maxBatchTempBytes
	}
	if temp < 16<<20 || temp > maxBatchTempBytes {
		return 0, 0, 0, 0, errors.New("max_temp_bytes outside 16 MiB..256 MiB")
	}
	output := request.MaxOutputBytes
	if output == 0 {
		output = maxBatchOutputBytes
	}
	if output < 1<<20 || output > maxBatchOutputBytes {
		return 0, 0, 0, 0, errors.New("max_output_bytes outside 1 MiB..64 MiB")
	}
	return parallel, processes, temp, output, nil
}

func isUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func writeBatchResult(path string, result model.BatchResult, limit int64) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errors.New("BatchResult exceeds output budget")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return nil
}
