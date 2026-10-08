package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestAggregateBatchSemantics(t *testing.T) {
	tests := []struct {
		name     string
		statuses []string
		want     model.BatchStatus
	}{
		{"all complete", []string{"complete", "complete"}, model.BatchStatusComplete},
		{"partial item", []string{"complete", "partial"}, model.BatchStatusPartial},
		{"failed item", []string{"complete", "failed"}, model.BatchStatusPartial},
		{"mixed complete and failed", []string{"complete", "failed"}, model.BatchStatusPartial},
		{"all failed", []string{"failed", "failed"}, model.BatchStatusFailed},
		{"all cancelled", []string{"cancelled", "cancelled"}, model.BatchStatusCancelled},
		{"mixed cancellation", []string{"cancelled", "complete"}, model.BatchStatusPartial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scans := make([]model.BatchScanResult, len(tt.statuses))
			for i, status := range tt.statuses {
				scans[i] = model.BatchScanResult{Status: status}
			}
			if got := aggregateBatch("b1000000-0000-4000-8000-000000000001", scans, time.Now(), time.Now()).Status; got != tt.want {
				t.Fatalf("aggregate status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBatchEventWriterFailureIsFatalAndPreventsFurtherEvents(t *testing.T) {
	writer := newBatchEventWriter(failingBatchWriter{}, "b1000000-0000-4000-8000-000000000001", 1<<20)
	if err := writer.emitBatch("batch.started", map[string]any{}); err == nil {
		t.Fatal("stdout failure was ignored")
	}
	if err := writer.emitBatch("batch.completed", map[string]any{}); err == nil {
		t.Fatal("writer accepted event after fatal stdout error")
	}
}

type failingBatchWriter struct{}

func (failingBatchWriter) Write([]byte) (int, error) { return 0, errors.New("stdout failure") }

func TestBatchEventWriterKeepsGlobalAndPerScanSequences(t *testing.T) {
	const batchID = "b1000000-0000-4000-8000-000000000001"
	const scanID = "c1000000-0000-4000-8000-000000000001"
	var output bytes.Buffer
	writer := newBatchEventWriter(&output, batchID, 1<<20)
	writer.setScans([]model.ScanRequest{{ScanID: scanID}})
	if err := writer.emitBatch("batch.started", map[string]any{"scan_count": 1}); err != nil {
		t.Fatal(err)
	}
	if err := writer.emitScan([]byte(`{"schema_version":"1","seq":1,"timestamp":"2026-10-07T00:00:00Z","scan_id":"` + scanID + `","type":"scan.started","data":{"target":"https://example.com","scan_id":"` + scanID + `","mode":"public"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.emitScan([]byte(`{"schema_version":"1","seq":2,"timestamp":"2026-10-07T00:00:00Z","scan_id":"` + scanID + `","type":"scan.completed","data":{"status":"complete"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.emitBatch("batch.completed", map[string]any{"scan_count": 1}); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(strings.NewReader(output.String()))
	var events []map[string]any
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("got %d batch events, want 4", len(events))
	}
	if events[0]["type"] != "batch.started" || events[0]["seq"] != float64(1) {
		t.Fatalf("unexpected first boundary: %#v", events[0])
	}
	scanEvent := events[1]
	if scanEvent["batch_protocol_version"] != buildinfo.BatchProtocolVersion || scanEvent["seq"] != float64(2) || scanEvent["scan_seq"] != float64(1) || scanEvent["scan_id"] != scanID {
		t.Fatalf("unexpected routed scan event: %#v", scanEvent)
	}
	if events[3]["type"] != "batch.completed" || events[3]["seq"] != float64(4) {
		t.Fatalf("unexpected final boundary: %#v", events[3])
	}
}

func TestValidateBatchRequestBoundsAndUniqueScanIDs(t *testing.T) {
	request := model.BatchRequest{
		ProtocolVersion: buildinfo.BatchProtocolVersion,
		BatchID:         "b1000000-0000-4000-8000-000000000001",
		Scans: []model.ScanRequest{{
			SchemaVersion: "1", ScanID: "c1000000-0000-4000-8000-000000000001",
			Target: "https://example.com", Profile: "standard", Mode: model.ScanModePublic,
		}},
	}
	if err := validateBatchRequest(request); err != nil {
		t.Fatalf("valid batch rejected: %v", err)
	}
	request.Scans = append(request.Scans, request.Scans[0])
	if err := validateBatchRequest(request); err == nil {
		t.Fatal("duplicate ScanRun IDs were accepted")
	}
	request.Scans = make([]model.ScanRequest, maxBatchDefaultSize+1)
	request.Limits = model.BatchLimits{}
	if err := validateBatchRequest(request); err == nil {
		t.Fatal("batch above Engine maximum was accepted")
	}
}

func TestBatchTerminalEventMatchesAggregateStatus(t *testing.T) {
	cases := []struct {
		status model.BatchStatus
		event  string
	}{
		{model.BatchStatusComplete, "batch.completed"},
		{model.BatchStatusPartial, "batch.completed"},
		{model.BatchStatusFailed, "batch.failed"},
		{model.BatchStatusCancelled, "batch.cancelled"},
	}
	for _, tc := range cases {
		t.Run(string(tc.status), func(t *testing.T) {
			result := model.BatchResult{Status: tc.status}
			writer := newBatchEventWriter(&bytes.Buffer{}, "b1000000-0000-4000-8000-000000000001", 1<<20)
			writer.setScans([]model.ScanRequest{{ScanID: "c1000000-0000-4000-8000-000000000001"}})
			if err := writer.emitBatch("batch.started", map[string]any{}); err != nil {
				t.Fatal(err)
			}
			terminalType := map[model.BatchStatus]string{model.BatchStatusComplete: "scan.completed", model.BatchStatusPartial: "scan.completed", model.BatchStatusFailed: "scan.failed", model.BatchStatusCancelled: "scan.cancelled"}[tc.status]
			scanStatus := map[model.BatchStatus]string{model.BatchStatusComplete: "complete", model.BatchStatusPartial: "partial", model.BatchStatusFailed: "failed", model.BatchStatusCancelled: "cancelled"}[tc.status]
			terminal := []byte(`{"schema_version":"1","seq":1,"scan_id":"c1000000-0000-4000-8000-000000000001","type":"scan.started","data":{}}`)
			if err := writer.emitScan(terminal); err != nil {
				t.Fatal(err)
			}
			terminal = []byte(`{"schema_version":"1","seq":2,"scan_id":"c1000000-0000-4000-8000-000000000001","type":"` + terminalType + `","data":{"status":"` + scanStatus + `"}}`)
			if err := writer.emitScan(terminal); err != nil {
				t.Fatal(err)
			}
			if err := writer.emitBatch(tc.event, result); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBatchCompletedRequiresAllItemsTerminalAndNoPostTerminalEvents(t *testing.T) {
	const batchID = "b1000000-0000-4000-8000-000000000001"
	const scanID = "c1000000-0000-4000-8000-000000000001"
	writer := newBatchEventWriter(&bytes.Buffer{}, batchID, 1<<20)
	writer.setScans([]model.ScanRequest{{ScanID: scanID}})
	if err := writer.emitBatch("batch.started", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	started := []byte(`{"schema_version":"1","seq":1,"scan_id":"` + scanID + `","type":"scan.started","data":{}}`)
	if err := writer.emitScan(started); err != nil {
		t.Fatal(err)
	}
	if err := writer.emitBatch("batch.completed", map[string]any{}); err == nil {
		t.Fatal("completed batch accepted before item terminal")
	}
	terminal := []byte(`{"schema_version":"1","seq":2,"scan_id":"` + scanID + `","type":"scan.completed","data":{"status":"complete"}}`)
	if err := writer.emitScan(terminal); err != nil {
		t.Fatal(err)
	}
	if err := writer.emitBatch("batch.completed", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := writer.emitScan([]byte(`{"schema_version":"1","seq":3,"scan_id":"` + scanID + `","type":"observation","data":{}}`)); err == nil {
		t.Fatal("event after batch terminal accepted")
	}
}

func TestBatchCLIPayloadsValidateAgainstSchemas(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "exposureguard")
	build := exec.Command("go", "build", "-o", binary, "./cmd/exposureguard")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build batch CLI: %v\n%s", err, output)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	request, err := json.Marshal(model.BatchRequest{ProtocolVersion: "1", BatchID: "b1000000-0000-4000-8000-000000000001", Limits: model.BatchLimits{MaxParallelScans: 1}, Scans: []model.ScanRequest{{SchemaVersion: "1", ScanID: "c1000000-0000-4000-8000-000000000001", Target: server.URL, Mode: model.ScanModePublic, Profile: "quick"}}})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "batch", "--request-json", "-", "--format", "jsonl", "--allow-private")
	cmd.Dir = repo
	cmd.Stdin = bytes.NewReader(request)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run batch CLI: %v\n%s\nstdout:\n%s", err, stderr.String(), stdout.String())
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	schemaDir := filepath.Join(repo, "schemas", "protocol-v1")
	for _, file := range []string{"scan-result.schema.json", "batch-event.schema.json", "batch-result.schema.json"} {
		data, err := os.ReadFile(filepath.Join(schemaDir, file))
		if err != nil {
			t.Fatal(err)
		}
		var schema any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource("https://exposureguard.dev/schemas/protocol-v1/"+file, schema); err != nil {
			t.Fatal(err)
		}
	}
	scanSchema, err := compiler.Compile("https://exposureguard.dev/schemas/protocol-v1/scan-result.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	eventSchema, err := compiler.Compile("https://exposureguard.dev/schemas/protocol-v1/batch-event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	resultSchema, err := compiler.Compile("https://exposureguard.dev/schemas/protocol-v1/batch-result.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	scanner.Buffer(make([]byte, 64*1024), maxBatchEventBytes)
	var events []map[string]any
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if err := eventSchema.Validate(event); err != nil {
			t.Fatalf("batch event rejected by schema: %v", err)
		}
		if data, ok := event["data"].(map[string]any); ok {
			if result, ok := data["result"]; ok {
				if err := scanSchema.Validate(result); err != nil {
					t.Fatalf("embedded ScanResult rejected by schema: %v", err)
				}
			}
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) < 3 || events[0]["type"] != "batch.started" || events[len(events)-1]["type"] != "batch.completed" {
		t.Fatalf("unexpected event boundaries: %#v", events)
	}
	var global int64
	scanSeq := make(map[string]int64)
	terminals := make(map[string]int)
	terminalCount := 0
	for _, event := range events {
		seq := int64(event["seq"].(float64))
		if seq != global+1 {
			t.Fatalf("global seq = %d after %d", seq, global)
		}
		global = seq
		if scanID, ok := event["scan_id"].(string); ok {
			local := int64(event["scan_seq"].(float64))
			if local != scanSeq[scanID]+1 {
				t.Fatalf("per-scan sequence for %s: got %d, after %d", scanID, local, scanSeq[scanID])
			}
			scanSeq[scanID] = local
			switch event["type"] {
			case "scan.completed", "scan.failed", "scan.cancelled":
				terminals[scanID]++
				terminalCount++
			}
		}
	}
	if terminalCount != 1 {
		t.Fatalf("scan terminal count = %d, want 1", terminalCount)
	}
	if terminals["c1000000-0000-4000-8000-000000000001"] != 1 {
		t.Fatalf("accepted scan terminal count = %d, want 1", terminals["c1000000-0000-4000-8000-000000000001"])
	}
	var result map[string]any
	for _, event := range events {
		if event["type"] != "batch.completed" && event["type"] != "batch.failed" && event["type"] != "batch.cancelled" {
			continue
		}
		data := event["data"].(map[string]any)
		result = data
		if err := resultSchema.Validate(result); err != nil {
			t.Fatalf("BatchResult rejected by schema: %v", err)
		}
	}
	if result == nil {
		t.Fatal("BatchResult missing from batch terminal event")
	}
	if events[len(events)-1]["type"] != "batch.completed" {
		t.Fatalf("completed batch terminal = %v, want batch.completed", events[len(events)-1]["type"])
	}
	if events[len(events)-2]["type"] != "scan.completed" {
		t.Fatalf("completed scan terminal = %v, want scan.completed", events[len(events)-2]["type"])
	}
}

func TestRunBatchAcceptedAllFailedHasExitZero(t *testing.T) {
	request := `{"batch_protocol_version":"1","batch_id":"b1000000-0000-4000-8000-000000000001","limits":{"max_parallel_scans":1},"scans":[{"schema_version":"1","scan_id":"c1000000-0000-4000-8000-000000000001","target":"https://example.com","mode":"public","profile":"deep"}]}`
	var output bytes.Buffer
	err := runBatchIO(t.Context(), &batchOptions{requestJSON: "-", format: "jsonl"}, strings.NewReader(request), &output)
	if err != nil {
		t.Fatalf("accepted all-failed workload changed process result: %v", err)
	}
	if !strings.Contains(output.String(), `"type":"batch.failed"`) || !strings.Contains(output.String(), `"status":"failed"`) {
		t.Fatalf("all-failed aggregate not reported: %s", output.String())
	}
}

func TestRunBatchCancellationIsCancelledAndExitsZero(t *testing.T) {
	request := `{"batch_protocol_version":"1","batch_id":"b1000000-0000-4000-8000-000000000004","limits":{"max_parallel_scans":1},"scans":[{"schema_version":"1","scan_id":"c1000000-0000-4000-8000-000000000041","target":"https://example.com","mode":"public","profile":"deep"}]}`
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var output bytes.Buffer
	if err := runBatchIO(ctx, &batchOptions{requestJSON: "-", format: "jsonl"}, strings.NewReader(request), &output); err != nil {
		t.Fatalf("normal cancellation returned process failure: %v", err)
	}
	if !strings.Contains(output.String(), `"type":"scan.cancelled"`) || !strings.Contains(output.String(), `"type":"batch.cancelled"`) || !strings.Contains(output.String(), `"status":"cancelled"`) {
		t.Fatalf("cancellation terminals/status mismatch: %s", output.String())
	}
}

func TestBatchEventOutputBudgetExhaustionIsFatal(t *testing.T) {
	writer := newBatchEventWriter(&bytes.Buffer{}, "b1000000-0000-4000-8000-000000000001", 1)
	if err := writer.emitBatch("batch.started", map[string]any{}); err == nil {
		t.Fatal("output budget exhaustion was ignored")
	}
	if writer.failure() == nil {
		t.Fatal("output budget exhaustion was not recorded as fatal")
	}
}

func TestRunBatchStdoutFailureIsRuntimeExitOne(t *testing.T) {
	request := `{"batch_protocol_version":"1","batch_id":"b1000000-0000-4000-8000-000000000001","scans":[{"schema_version":"1","scan_id":"c1000000-0000-4000-8000-000000000001","target":"https://example.com","mode":"public","profile":"deep"}]}`
	err := runBatchIO(t.Context(), &batchOptions{requestJSON: "-", format: "jsonl"}, strings.NewReader(request), failingBatchWriter{})
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("stdout failure exit = %v, want 1", err)
	}
}

func TestRunBatchInvalidRequestExitsTwo(t *testing.T) {
	var out bytes.Buffer
	opts := &batchOptions{requestJSON: "-", format: "jsonl"}
	err := runBatchIO(t.Context(), opts, strings.NewReader(`{"batch_protocol_version":"2"}`), &out)
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("invalid request exit = %v, want 2", err)
	}
	if out.Len() != 0 {
		t.Fatalf("invalid request emitted %d bytes before validation", out.Len())
	}
}

func TestBatchHardWorkloadAndResourceLimits(t *testing.T) {
	request := model.BatchRequest{Limits: model.BatchLimits{MaxBatchSize: 21}}
	if _, _, _, _, err := batchResourceLimits(request.Limits); err == nil {
		t.Fatal("max batch size >20 accepted")
	}
	for _, count := range []int{1, maxBatchDefaultSize} {
		request.Limits = model.BatchLimits{MaxBatchSize: count}
		if _, _, _, _, err := batchResourceLimits(request.Limits); err != nil {
			t.Fatalf("max batch size %d rejected: %v", count, err)
		}
	}
	request.Limits = model.BatchLimits{MaxParallelScans: 5}
	if _, _, _, _, err := batchResourceLimits(request.Limits); err == nil {
		t.Fatal("parallelism >4 accepted")
	}
}

func TestBatchParallelLimitDefaultsAndRejectsAboveHardLimit(t *testing.T) {
	if got, err := batchParallelScans(0); err != nil || got != maxBatchParallelScans {
		t.Fatalf("batchParallelScans(0) = %d, %v; want %d, nil", got, err, maxBatchParallelScans)
	}
	if _, err := batchParallelScans(maxBatchParallelScans + 1); err == nil {
		t.Fatal("parallelism above Engine ceiling was accepted")
	}
}
