package runtime

import (
	"context"
	"fmt"
	"time"
)

type heartbeatLoop struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error // Written before done closes; read only after joining.
}

// startHeartbeat sends promptly and owns every subsequent request. stop joins
// the loop so job heartbeats cannot race with terminal state transitions.
func startHeartbeat(ctx context.Context, interval time.Duration, beat func(context.Context) error, fail func(error)) *heartbeatLoop {
	ctx, cancel := context.WithCancel(ctx)
	h := &heartbeatLoop{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			if ctx.Err() != nil {
				return
			}
			if err := beat(ctx); err != nil {
				if ctx.Err() == nil {
					h.err = fmt.Errorf("heartbeat failed: %w", err)
					fail(h.err)
				}
				return
			}
			timer.Reset(interval)
		}
	}()
	return h
}

func (h *heartbeatLoop) stop() error {
	h.cancel()
	<-h.done
	return h.err
}
