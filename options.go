package rediver

import (
	"log/slog"
	"net/http"
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

// WithShutdownTimeout bounds how long Run drains active jobs after cancellation.
func WithShutdownTimeout(timeout time.Duration) Option {
	return func(c *agentConfig) { c.ShutdownTimeout = timeout }
}

// WithRequestTimeout bounds each RPC. Allow over 30s for the server's long poll.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(c *agentConfig) { c.RequestTimeout = timeout }
}

// WithLogger supplies the structured logger. It must not be nil.
func WithLogger(logger *slog.Logger) Option {
	return func(c *agentConfig) { c.Logger = logger }
}

// WithStrictCoverage requires every target assigned by a job to reach a
// terminal per-target outcome (uploaded observations, an explicit target
// error, or both) before that job may complete cleanly. A scan that returns
// nil without reporting every assigned target fails the whole job instead
// (ErrIncompleteCoverage), so the backend retries the missing targets on a
// later job. Duplicate emissions for the same target do not add coverage;
// one target's reported error never fails the rest of the batch. Off by
// default; intended for finite one-shot scanners (see Agent.RunOnce).
func WithStrictCoverage() Option {
	return func(c *agentConfig) { c.StrictCoverage = true }
}
