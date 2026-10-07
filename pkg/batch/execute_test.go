package batch

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestExecuteBoundsWorkersAndPreservesInputOrder(t *testing.T) {
	items := make([]int, 20)
	for i := range items {
		items[i] = i
	}
	var active, peak atomic.Int32
	results := Execute(context.Background(), items, 4, func(_ context.Context, value int) int {
		now := active.Add(1)
		for old := peak.Load(); now > old && !peak.CompareAndSwap(old, now); old = peak.Load() {
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		return value * 2
	})
	if got := peak.Load(); got > 4 || got < 2 {
		t.Fatalf("peak concurrency %d; want 2..4", got)
	}
	if len(results) != len(items) {
		t.Fatalf("got %d results for %d inputs", len(results), len(items))
	}
	for index, value := range results {
		if value != index*2 {
			t.Fatalf("result[%d]=%d", index, value)
		}
	}
}

func TestExecuteEmptyAndSingle(t *testing.T) {
	if got := Execute(context.Background(), []int(nil), 4, func(_ context.Context, value int) int { return value }); len(got) != 0 {
		t.Fatalf("empty result len %d", len(got))
	}
	got := Execute(context.Background(), []int{7}, 4, func(_ context.Context, value int) int { return value })
	if len(got) != 1 || got[0] != 7 {
		t.Fatalf("single result %#v", got)
	}
}
