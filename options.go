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
