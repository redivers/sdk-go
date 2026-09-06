package client

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"time"

	"connectrpc.com/connect"
	"github.com/redivers/sdk-go/internal/contract"
)

// isRetryableError returns true if the error is retryable.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// A canceled caller or per-attempt deadline is local control flow, even when
	// Connect wraps it as a DeadlineExceeded RPC error.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Connect errors survive wrapping by the operation that failed.
	var rpcErr *connect.Error
	if errors.As(err, &rpcErr) {
		switch rpcErr.Code() {
		case connect.CodeResourceExhausted, connect.CodeUnavailable, connect.CodeDeadlineExceeded:
			return true
		default:
			return false
		}
	}

	var netErr net.Error
	return errors.As(err, &netErr)
}

// backoffDuration calculates the backoff duration for a given attempt.
// Attempt is 1-indexed (first retry is attempt 1).
func backoffDuration(p contract.RetryPolicy, attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}

	backoff := float64(p.InitialBackoff) * math.Pow(p.BackoffMultiplier, float64(attempt-1))
	if p.Jitter {
		// Add up to 25% jitter before capping the final delay.
		jitter := backoff * 0.25 * rand.Float64()
		backoff += jitter
	}
	if backoff > float64(p.MaxBackoff) {
		backoff = float64(p.MaxBackoff)
	}

	return time.Duration(backoff)
}

// retry executes the function using a policy already validated by the runtime.
func retry(p contract.RetryPolicy, ctx context.Context, fn func() error) error {
	var lastErr error

	for attempt := 1; attempt <= p.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if !isRetryableError(err) {
			return err
		}

		if attempt < p.MaxAttempts {
			backoff := backoffDuration(p, attempt)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	return fmt.Errorf("retry failed after %d attempts: %w", p.MaxAttempts, lastErr)
}
