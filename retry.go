package rediver

import "github.com/redivers/sdk-go/internal/contract"

// RetryPolicy configures retry behavior for transient errors.
type RetryPolicy = contract.RetryPolicy

// DefaultRetryPolicy returns sensible defaults for production use.
func DefaultRetryPolicy() RetryPolicy {
	return contract.DefaultRetryPolicy()
}

// AggressiveRetryPolicy returns a policy with more retries for daemon mode.
func AggressiveRetryPolicy() RetryPolicy {
	return contract.AggressiveRetryPolicy()
}

// NoRetry returns a policy that disables retry (fail on first error).
func NoRetry() RetryPolicy {
	return contract.NoRetry()
}
