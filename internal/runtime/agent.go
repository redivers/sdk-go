package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/redivers/sdk-go/internal/client"
	"github.com/redivers/sdk-go/internal/contract"
)

// Agent owns registration and the lifetime of one scanner runner.
type Agent struct {
	cfg      Config
	scanner  contract.Scanner
	client   *client.Client
	mu       sync.Mutex
	started  bool
	stopped  bool
	runnerID string
	stop     func()
}

// NewAgent validates configuration locally before constructing the RPC client.
func NewAgent(token string, scanner contract.Scanner, cfg Config) (*Agent, error) {
	if err := validateScanner(scanner); err != nil {
		return nil, err
	}
	if token == "" {
		token = os.Getenv("REDIVER_TOKEN")
	}
	if strings.TrimSpace(token) == "" || strings.IndexFunc(token, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("%w: network agent token is required and must be a valid HTTP header", contract.ErrInvalidConfig)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Agent{
		cfg:     cfg,
		scanner: scanner,
		client:  client.New(token, cfg.ServerURL, cfg.HTTPClient, cfg.RequestTimeout, cfg.RetryPolicy),
	}, nil
}

func validateScanner(scanner contract.Scanner) error {
	if scanner == nil {
		return fmt.Errorf("%w: scanner is required", contract.ErrInvalidConfig)
	}
	value := reflect.ValueOf(scanner)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return fmt.Errorf("%w: scanner must not be nil", contract.ErrInvalidConfig)
		}
	}
	return nil
}

func (a *Agent) currentRunnerID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.runnerID
}

// Stop immediately cancels polling and active scan work.
func (a *Agent) Stop() {
	a.mu.Lock()
	a.stopped = true
	stop := a.stop
	a.mu.Unlock()
	if stop != nil {
		stop()
	}
}

type agentSession struct {
	work       context.Context
	poll       context.Context
	cancelWork context.CancelCauseFunc
	cancelPoll context.CancelFunc
}

func (s *agentSession) cancel(err error) { s.cancelWork(err); s.cancelPoll() }

func (a *Agent) terminalContext(s *agentSession) (context.Context, context.CancelFunc) {
	timeout := min(a.cfg.RequestTimeout, a.cfg.ShutdownTimeout)
	// A terminal transition gets its own budget after local cancellation.
	return context.WithTimeout(context.WithoutCancel(s.work), timeout)
}

func (a *Agent) withSession(ctx context.Context, drain bool, run func(*agentSession) error) (err error) {
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return contract.ErrAlreadyRunning
	}
	a.started = true
	if a.stopped {
		a.mu.Unlock()
		return context.Canceled
	}
	base := ctx
	if drain {
		base = context.WithoutCancel(ctx)
	}
	work, cancelWork := context.WithCancelCause(base)
	poll, cancelPoll := context.WithCancel(ctx)
	s := &agentSession{work: work, poll: poll, cancelWork: cancelWork, cancelPoll: cancelPoll}
	a.stop = func() { s.cancel(context.Canceled) }
	a.mu.Unlock()
	defer func() { s.cancel(context.Canceled); a.mu.Lock(); a.stop = nil; a.mu.Unlock() }()
	runnerID, err := a.client.Register(s.poll, client.Registration{Hostname: a.cfg.Hostname, Version: a.cfg.Version})
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.runnerID = runnerID
	a.mu.Unlock()
	runner := startHeartbeat(s.work, a.cfg.HeartbeatInterval, func(ctx context.Context) error {
		return a.client.Heartbeat(ctx, a.currentRunnerID())
	}, func(err error) { s.cancel(fmt.Errorf("runner heartbeat: %w", err)) })
	defer func() { err = errors.Join(err, runner.stop()) }()
	return run(s)
}
