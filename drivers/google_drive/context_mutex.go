package google_drive

import (
	"context"
	"sync"
	"time"
)

// lockContextMutex waits for a short local mutex while honoring cancellation.
// It is used for credential refreshes; authority state has its own lock.
func lockContextMutex(ctx context.Context, mutex *sync.Mutex) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if mutex.TryLock() {
			if err := ctx.Err(); err != nil {
				mutex.Unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
