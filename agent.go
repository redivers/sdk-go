package rediver

import (
	"context"
	"fmt"

	"github.com/redivers/sdk-go/internal/runtime"
)

// Agent registers a runner and executes jobs assigned to its network token.
// Each Agent supports one lifecycle invocation; construct a new Agent to restart.
type Agent struct {
	runner *runtime.Agent
}

// NewAgent validates local configuration without making network requests.
// Empty token and server URL configuration use REDIVER_TOKEN and REDIVER_URL.
func NewAgent(token string, scanner Scanner, opts ...Option) (*Agent, error) {
	cfg := runtime.DefaultConfig(sdkVersion)
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option", ErrInvalidConfig)
		}
		opt(&cfg)
	}
	runner, err := runtime.NewAgent(token, scanner, cfg)
	if err != nil {
		return nil, err
	}
	return &Agent{runner: runner}, nil
}

// Run polls continuously with bounded job concurrency. Parent cancellation
// drains active work up to the shutdown timeout; Stop cancels it immediately.
func (a *Agent) Run(ctx context.Context) error { return a.runner.Run(ctx) }

// RunOnce registers, polls once and scans the assigned target batch.
// It returns ErrNoJobAvailable when the backend has no job to assign.
func (a *Agent) RunOnce(ctx context.Context) error { return a.runner.RunOnce(ctx) }

// Stop is idempotent and immediately cancels polling and active scanner work.
// Wait for Run or RunOnce to return for cleanup to finish.
func (a *Agent) Stop() { a.runner.Stop() }
