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

func TestRetryPolicyConnectStatusOverride(t *testing.T) {
	p := contract.DefaultRetryPolicy()
	p.RetryableStatusCodes = []int{429}
	if isRetryableError(p, connect.NewError(connect.CodeUnavailable, errors.New("offline"))) {
		t.Fatal("retried unavailable despite custom status policy")
	}
}

func TestIsRetryableStatus(t *testing.T) {
	p := contract.DefaultRetryPolicy()

	retryable := []int{429, 502, 503, 504}
	for _, code := range retryable {
		if !isRetryableStatus(p, code) {
			t.Errorf("expected %d to be retryable", code)
		}
	}

	notRetryable := []int{200, 400, 401, 404, 500}
	for _, code := range notRetryable {
		if isRetryableStatus(p, code) {
			t.Errorf("expected %d to not be retryable", code)
		}
	}
}

func TestIsRetryableError(t *testing.T) {
	p := contract.DefaultRetryPolicy()

	// nil error
	if isRetryableError(p, nil) {
		t.Error("nil error should not be retryable")
	}

	// Retryable Connect error
	if !isRetryableError(p, connect.NewError(connect.CodeResourceExhausted, errors.New("backend error"))) {
		t.Error("429 Connect error should be retryable")
	}

	// Non-retryable Connect error
	if isRetryableError(p, connect.NewError(connect.CodeInvalidArgument, errors.New("backend error"))) {
		t.Error("400 Connect error should not be retryable")
	}

	// Network error
	if !isRetryableError(p, &mockNetError{}) {
		t.Error("net.Error should be retryable")
	}

	// Generic error
	if isRetryableError(p, errors.New("generic")) {
		t.Error("generic error should not be retryable")
	}
}

// mockNetError implements net.Error for testing.
type mockNetError struct{}

func (e *mockNetError) Error() string { return "network error" }

func (e *mockNetError) Timeout() bool { return true }

func (e *mockNetError) Temporary() bool { return true }

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

func TestRetryPolicy_Success(t *testing.T) {
	p := contract.NoRetry()
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

func TestRetryPolicy_RetryThenSuccess(t *testing.T) {
	p := contract.RetryPolicy{
		MaxAttempts:          3,
		InitialBackoff:       1 * time.Millisecond,
		MaxBackoff:           10 * time.Millisecond,
		BackoffMultiplier:    1.0,
		RetryableStatusCodes: []int{503},
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

func TestRetryPolicy_NonRetryableError(t *testing.T) {
	p := contract.RetryPolicy{
		MaxAttempts:          5,
		InitialBackoff:       1 * time.Millisecond,
		RetryableStatusCodes: []int{429},
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

func TestRetryPolicy_MaxAttemptsExceeded(t *testing.T) {
	p := contract.RetryPolicy{
		MaxAttempts:          3,
		InitialBackoff:       1 * time.Millisecond,
		MaxBackoff:           10 * time.Millisecond,
		BackoffMultiplier:    1.0,
		RetryableStatusCodes: []int{429},
	}
	calls := 0
	err := retry(p, context.Background(), func() error {
		calls++
		return connect.NewError(connect.CodeResourceExhausted, errors.New("backend error"))
	})

	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}

	var retryErr *retryExhaustedError
	if !errors.As(err, &retryErr) {
		t.Fatalf("expected *retryExhaustedError, got %T", err)
	}
	if retryErr.Attempt != 3 || retryErr.MaxAttempt != 3 {
		t.Errorf("expected attempt 3/3, got %d/%d", retryErr.Attempt, retryErr.MaxAttempt)
	}
}

func TestRetryPolicy_ContextCancelled(t *testing.T) {
	p := contract.RetryPolicy{
		MaxAttempts:          10,
		InitialBackoff:       1 * time.Second,
		MaxBackoff:           10 * time.Second,
		BackoffMultiplier:    2.0,
		RetryableStatusCodes: []int{429},
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

func TestRetryExhaustedErrorUnwrap(t *testing.T) {
	cause := errors.New("unavailable")
	err := &retryExhaustedError{Err: cause, Attempt: 3, MaxAttempt: 3}
	if !errors.Is(err, cause) || err.Error() != "retryable error (attempt 3/3, retry in 0s): unavailable" {
		t.Fatalf("retry diagnostics lost: %v", err)
	}
}
