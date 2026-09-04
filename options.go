package rediver

import (
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/redivers/sdk-go/internal/runtime"
)

type agentConfig = runtime.Config

// Option configures an Agent before local validation in NewAgent.
type Option func(*agentConfig)

// WithServerURL overrides REDIVER_URL and the default API server URL.
func WithServerURL(serverURL string) Option {
	return func(c *agentConfig) { c.ServerURL = serverURL }
}

// WithHTTPClient supplies the HTTP client used for all RPCs. It must not be nil.
func WithHTTPClient(client *http.Client) Option {
	return func(c *agentConfig) { c.HTTPClient = client }
}

// WithMaxConcurrency sets the positive maximum number of simultaneous jobs.
func WithMaxConcurrency(maxConcurrency int) Option {
	return func(c *agentConfig) { c.MaxConcurrency = maxConcurrency }
}

// WithPollInterval sets the positive interval between polling rounds.
func WithPollInterval(interval time.Duration) Option {
	return func(c *agentConfig) { c.PollInterval = interval }
}

// WithHeartbeatInterval sets the positive interval between runner heartbeats.
func WithHeartbeatInterval(interval time.Duration) Option {
	return func(c *agentConfig) { c.HeartbeatInterval = interval }
}

// WithJobHeartbeatInterval sets the positive interval between job heartbeats.
func WithJobHeartbeatInterval(interval time.Duration) Option {
	return func(c *agentConfig) { c.JobHeartbeatInterval = interval }
}

// WithShutdownTimeout bounds how long Run drains active jobs after cancellation.
func WithShutdownTimeout(timeout time.Duration) Option {
	return func(c *agentConfig) { c.ShutdownTimeout = timeout }
}

// WithRequestTimeout bounds each RPC. Allow over 30s for the server's long poll.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(c *agentConfig) { c.RequestTimeout = timeout }
}

// WithRunnerID supplies an existing runner ID when registering with the server.
func WithRunnerID(runnerID string) Option {
	return func(c *agentConfig) { c.RunnerID = runnerID }
}

// WithHostname overrides the local hostname sent during registration.
func WithHostname(hostname string) Option {
	return func(c *agentConfig) { c.Hostname = hostname }
}

// WithIPAddress supplies optional IPv4 or IPv6 registration metadata.
// The default is empty; the SDK does not discover an address automatically.
func WithIPAddress(ipAddress string) Option {
	return func(c *agentConfig) { c.IPAddress = ipAddress }
}

// WithVersion overrides the SDK version sent during registration.
func WithVersion(version string) Option {
	return func(c *agentConfig) { c.Version = version }
}

// WithLogger supplies the structured logger. It must not be nil.
func WithLogger(logger *slog.Logger) Option {
	return func(c *agentConfig) { c.Logger = logger }
}

// WithRetryPolicy sets retries for operations that can safely be repeated.
// Status codes are copied when creating and applying the option.
func WithRetryPolicy(policy RetryPolicy) Option {
	policy.RetryableStatusCodes = slices.Clone(policy.RetryableStatusCodes)
	return func(c *agentConfig) {
		c.RetryPolicy = policy
		c.RetryPolicy.RetryableStatusCodes = slices.Clone(policy.RetryableStatusCodes)
	}
}

// WithRetryDefault enables the default bounded exponential retry policy.
func WithRetryDefault() Option { return WithRetryPolicy(DefaultRetryPolicy()) }

// WithRetryAggressive enables a policy with more attempts and longer backoffs.
func WithRetryAggressive() Option { return WithRetryPolicy(AggressiveRetryPolicy()) }

// WithNoRetry disables automatic retries.
func WithNoRetry() Option { return WithRetryPolicy(NoRetry()) }
