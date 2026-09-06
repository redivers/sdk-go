package contract

import "time"

// RetryPolicy configures retry behavior for transient errors.
type RetryPolicy struct {
	// MaxAttempts is the maximum number of attempts (including the first).
	// Default: 5
	MaxAttempts int

	// InitialBackoff is the wait time before the first retry.
	// Default: 1s
	InitialBackoff time.Duration

	// MaxBackoff is the maximum wait time between retries.
	// Default: 60s
	MaxBackoff time.Duration

	// BackoffMultiplier is the multiplier for exponential backoff.
	// Default: 2.0
	BackoffMultiplier float64

	// Jitter adds randomness to backoff to prevent thundering herd.
	// Default: true
	Jitter bool
}

// DefaultRetryPolicy returns sensible defaults for production use.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       5,
		InitialBackoff:    1 * time.Second,
		MaxBackoff:        60 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
	}
}
