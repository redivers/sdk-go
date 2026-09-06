package client

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/redivers/sdk-go/internal/contract"
)

func TestRetryPolicyWrappedConnectErrors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		wantCalls int
	}{
		{"unavailable", connect.NewError(connect.CodeUnavailable, errors.New("offline")), 3},
		{"rate limited", connect.NewError(connect.CodeResourceExhausted, errors.New("busy")), 3},
		{"upstream timeout", connect.NewError(connect.CodeDeadlineExceeded, errors.New("upstream timed out")), 3},
		{"attempt deadline", connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded), 1},
		{"stale run", connect.NewError(connect.CodeFailedPrecondition, errors.New("stale")), 1},
		{"auth", connect.NewError(connect.CodeUnauthenticated, errors.New("invalid token")), 1},
		{"validation", connect.NewError(connect.CodeInvalidArgument, errors.New("invalid target")), 1},
		{"local cancellation", context.Canceled, 1},
		{"local deadline", context.DeadlineExceeded, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := contract.DefaultRetryPolicy()
			p.MaxAttempts, p.InitialBackoff, p.MaxBackoff = 3, 0, 0
			calls := 0
			err := retry(p, context.Background(), func() error {
				calls++
				return fmt.Errorf("push domains: %w", tc.err)
			})
			if calls != tc.wantCalls {
				t.Fatalf("got %d requests, want %d", calls, tc.wantCalls)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("lost original error: %v", err)
			}
		})
	}
}

func TestIsRetryableError(t *testing.T) {
	// nil error
	if isRetryableError(nil) {
		t.Error("nil error should not be retryable")
	}

	// Retryable Connect error
	if !isRetryableError(connect.NewError(connect.CodeResourceExhausted, errors.New("backend error"))) {
		t.Error("429 Connect error should be retryable")
	}

	// Non-retryable Connect error
	if isRetryableError(connect.NewError(connect.CodeInvalidArgument, errors.New("backend error"))) {
		t.Error("400 Connect error should not be retryable")
	}

	// Network error
	if !isRetryableError(&mockNetError{}) {
		t.Error("net.Error should be retryable")
	}

	// Local context errors should not be retried even though a deadline error is a net.Error.
	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		if isRetryableError(err) {
			t.Errorf("local context error should not be retryable: %v", err)
		}
	}

	// Generic error
	if isRetryableError(errors.New("generic")) {
		t.Error("generic error should not be retryable")
	}
}

// mockNetError implements net.Error for testing.
type mockNetError struct{}

func (*mockNetError) Error() string { return "network error" }

func (*mockNetError) Timeout() bool { return true }

func (*mockNetError) Temporary() bool { return true }

func TestBackoffDuration(t *testing.T) {
	p := contract.RetryPolicy{
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        1 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            false,
	}

	// attempt <= 0 returns 0
	if d := backoffDuration(p, 0); d != 0 {
		t.Errorf("attempt 0: got %v, want 0", d)
	}

	// attempt 1 = InitialBackoff
	if d := backoffDuration(p, 1); d != 100*time.Millisecond {
		t.Errorf("attempt 1: got %v, want 100ms", d)
	}

	// attempt 2 = 100ms * 2 = 200ms
	if d := backoffDuration(p, 2); d != 200*time.Millisecond {
		t.Errorf("attempt 2: got %v, want 200ms", d)
	}

	// attempt 3 = 100ms * 4 = 400ms
	if d := backoffDuration(p, 3); d != 400*time.Millisecond {
		t.Errorf("attempt 3: got %v, want 400ms", d)
	}

	// Capped at MaxBackoff
	if d := backoffDuration(p, 10); d != 1*time.Second {
		t.Errorf("attempt 10: got %v, want 1s (capped)", d)
	}
}

func TestBackoffDuration_WithJitter(t *testing.T) {
	p := contract.RetryPolicy{
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        10 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
	}

	// With jitter, result should be >= base (jitter only adds)
	for i := 0; i < 50; i++ {
		d := backoffDuration(p, 1)
		if d < 100*time.Millisecond {
			t.Errorf("jitter produced value below base: %v", d)
		}
		// Max jitter is 25%, so max = 125ms
		if d > 125*time.Millisecond {
			t.Errorf("jitter exceeded 25%%: %v", d)
		}
	}
}

func TestBackoffDurationJitterHonorsMaximum(t *testing.T) {
	p := contract.RetryPolicy{
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        100 * time.Millisecond,
		BackoffMultiplier: 2,
		Jitter:            true,
	}
	for i := 0; i < 50; i++ {
		if got := backoffDuration(p, 1); got > p.MaxBackoff {
			t.Fatalf("jittered backoff = %v, want at most %v", got, p.MaxBackoff)
		}
	}
}

func TestRetryPolicySuccess(t *testing.T) {
	p := contract.RetryPolicy{MaxAttempts: 1}
	calls := 0
	err := retry(p, context.Background(), func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryPolicyRetryThenSuccess(t *testing.T) {
	p := contract.RetryPolicy{
		MaxAttempts:       3,
		InitialBackoff:    1 * time.Millisecond,
		MaxBackoff:        10 * time.Millisecond,
		BackoffMultiplier: 1.0,
	}
	calls := 0
	err := retry(p, context.Background(), func() error {
		calls++
		if calls < 3 {
			return connect.NewError(connect.CodeUnavailable, errors.New("backend error"))
		}
		return nil
	})
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestRetryPolicyNonRetryableError(t *testing.T) {
	p := contract.RetryPolicy{
		MaxAttempts:    5,
		InitialBackoff: 1 * time.Millisecond,
	}
	calls := 0
	err := retry(p, context.Background(), func() error {
		calls++
		return connect.NewError(connect.CodeInvalidArgument, errors.New("backend error")) // not retryable
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("expected 1 call (no retry), got %d", calls)
	}
}

func TestRetryPolicyMaxAttemptsExceeded(t *testing.T) {
	p := contract.RetryPolicy{
		MaxAttempts:       3,
		InitialBackoff:    1 * time.Millisecond,
		MaxBackoff:        10 * time.Millisecond,
		BackoffMultiplier: 1.0,
	}
	calls := 0
	cause := connect.NewError(connect.CodeResourceExhausted, errors.New("backend error"))
	err := retry(p, context.Background(), func() error {
		calls++
		return cause
	})

	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}

	if !errors.Is(err, cause) || err.Error() != "retry failed after 3 attempts: resource_exhausted: backend error" {
		t.Fatalf("retry diagnostics lost: %v", err)
	}
}

func TestRetryPolicyContextCancelled(t *testing.T) {
	p := contract.RetryPolicy{
		MaxAttempts:       10,
		InitialBackoff:    1 * time.Second,
		MaxBackoff:        10 * time.Second,
		BackoffMultiplier: 2.0,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := retry(p, ctx, func() error {
		return connect.NewError(connect.CodeResourceExhausted, errors.New("backend error"))
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestRetryPolicyCancellationDuringAttemptWins(t *testing.T) {
	p := contract.RetryPolicy{MaxAttempts: 1}
	ctx, cancel := context.WithCancel(context.Background())
	err := retry(p, ctx, func() error {
		cancel()
		return connect.NewError(connect.CodeUnavailable, errors.New("offline"))
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost after attempt: %v", err)
	}
}
