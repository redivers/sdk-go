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

// isRetryableStatus returns true if the status code is retryable.
func isRetryableStatus(p contract.RetryPolicy, statusCode int) bool {
	for _, code := range p.RetryableStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

// isRetryableError returns true if the error is retryable.
func isRetryableError(p contract.RetryPolicy, err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Connect errors survive wrapping by the operation that failed. Translate
	// transient codes to the existing policy's HTTP statuses.
	var rpcErr *connect.Error
	if errors.As(err, &rpcErr) {
		switch rpcErr.Code() {
		case connect.CodeResourceExhausted:
			return isRetryableStatus(p, 429)
		case connect.CodeUnavailable:
			return isRetryableStatus(p, 503)
		case connect.CodeDeadlineExceeded:
			return isRetryableStatus(p, 504)
		default:
			return false
		}
	}

	// Check for network errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	return false
}

// backoffDuration calculates the backoff duration for a given attempt.
// Attempt is 1-indexed (first retry is attempt 1).
func backoffDuration(p contract.RetryPolicy, attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}

	backoff := float64(p.InitialBackoff) * math.Pow(p.BackoffMultiplier, float64(attempt-1))
	if backoff > float64(p.MaxBackoff) {
		backoff = float64(p.MaxBackoff)
	}

	if p.Jitter {
		// Add up to 25% jitter
		jitter := backoff * 0.25 * rand.Float64()
		backoff += jitter
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

		// Check if error is retryable
		if !isRetryableError(p, err) {
			return err
		}

		// Don't sleep on the last attempt
		if attempt < p.MaxAttempts {
			backoff := backoffDuration(p, attempt)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	return &retryExhaustedError{
		Err:        lastErr,
		Attempt:    p.MaxAttempts,
		MaxAttempt: p.MaxAttempts,
	}
}

// retryExhaustedError preserves the final backend cause for classification.
type retryExhaustedError struct {
	Err                 error
	Attempt, MaxAttempt int
}

func (e *retryExhaustedError) Error() string {
	return fmt.Sprintf("retryable error (attempt %d/%d, retry in 0s): %v", e.Attempt, e.MaxAttempt, e.Err)
}
func (e *retryExhaustedError) Unwrap() error { return e.Err }
