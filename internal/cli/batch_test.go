package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/exposureguard/exposureguard/internal/buildinfo"
	"github.com/exposureguard/exposureguard/pkg/model"
)

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
	terminal := []byte(`{"schema_version":"1","seq":2,"scan_id":"` + scanID + `","type":"scan.completed","data":{}}`)
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

func TestRunBatchValidatesEnvelopeBeforeEmitting(t *testing.T) {
	var out bytes.Buffer
	opts := &batchOptions{requestJSON: "-", format: "jsonl"}
	err := runBatchIO(t.Context(), opts, strings.NewReader(`{"batch_protocol_version":"2"}`), &out)
	if err == nil {
		t.Fatal("unsupported request accepted")
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
