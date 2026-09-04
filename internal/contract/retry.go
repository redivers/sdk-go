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

	// RetryableStatusCodes are HTTP status codes that trigger retry.
	// Default: [429, 502, 503, 504]
	RetryableStatusCodes []int
}

// DefaultRetryPolicy returns sensible defaults for production use.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       5,
		InitialBackoff:    1 * time.Second,
		MaxBackoff:        60 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
		RetryableStatusCodes: []int{
			429, // Too Many Requests
			502, // Bad Gateway
			503, // Service Unavailable
			504, // Gateway Timeout
		},
	}
}

// AggressiveRetryPolicy returns a policy with more retries for daemon mode.
func AggressiveRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       10,
		InitialBackoff:    2 * time.Second,
		MaxBackoff:        120 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
		RetryableStatusCodes: []int{
			429, 502, 503, 504,
		},
	}
}

// NoRetry returns a policy that disables retry (fail on first error).
func NoRetry() RetryPolicy {
	return RetryPolicy{
		MaxAttempts: 1,
	}
}
