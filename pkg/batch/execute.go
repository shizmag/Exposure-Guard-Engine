// Package batch provides bounded, FIFO execution for independent work items.
package batch

import (
	"context"
	"sync"
)

// Execute runs items with a fixed worker count and returns results in input order.
// Workers receive jobs FIFO; each result slot has one writer.
func Execute[T, R any](ctx context.Context, items []T, workers int, run func(context.Context, T) R) []R {
	if workers < 1 {
		workers = 1
	}
	if workers > len(items) {
		workers = len(items)
	}
	results := make([]R, len(items))
	if len(items) == 0 {
		return results
	}

	var pool sync.WaitGroup
	var nextIndex int
	var indexMu sync.Mutex
	pool.Add(workers)
	for range workers {
		go func() {
			defer pool.Done()
			for {
				indexMu.Lock()
				if nextIndex == len(items) {
					indexMu.Unlock()
					return
				}
				index := nextIndex
				nextIndex++
				item := items[index]
				indexMu.Unlock()
				results[index] = run(ctx, item)
			}
		}()
	}
	pool.Wait()
	return results
}
