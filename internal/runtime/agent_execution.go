package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/redivers/sdk-go/internal/client"
	"github.com/redivers/sdk-go/internal/contract"
)

// RunOnce registers, polls once and executes the returned assignment.
func (a *Agent) RunOnce(ctx context.Context) error {
	return a.withSession(ctx, false, func(s *agentSession) error {
		job, err := a.client.Poll(s.poll)
		if err != nil {
			return err
		}
		if job == nil {
			return contract.ErrNoJobAvailable
		}
		return a.execute(s, job)
	})
}

func (a *Agent) execute(s *agentSession, job *client.Assignment) error {
	if err := a.client.Start(s.work, job); err != nil {
		return a.startFailure(s, job, err)
	}
	scanErr := a.scan(s.work, job)
	terminalCtx, terminalCancel := a.terminalContext(s)
	defer terminalCancel()
	var terminalErr error
	if scanErr == nil {
		terminalErr = a.client.Complete(terminalCtx, job)
	} else {
		terminalErr = a.client.Fail(terminalCtx, job, scanErr)
	}
	if err := errors.Join(scanErr, terminalErr); err != nil {
		return fmt.Errorf("job %s: execution failed: %w", job.ID(), err)
	}
	return nil
}

func (a *Agent) scan(ctx context.Context, job *client.Assignment) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)
	if err := job.PrepareTargets(); err != nil {
		return err
	}
	emitter := newResultEmitter(ctx, job, a.client, cancel)
	defer emitter.close()
	beats := startHeartbeat(ctx, a.cfg.JobHeartbeatInterval, func(ctx context.Context) error {
		return a.client.JobHeartbeat(ctx, job)
	}, func(err error) { cancel(fmt.Errorf("job heartbeat: %w", err)) })
	targets := job.Targets()
	result := make(chan error, 1)
	go func() { result <- invokeScanner(a.scanner, ctx, targets, emitter) }()
	var scanErr error
	select {
	case scanErr = <-result:
	case <-ctx.Done():
		scanErr = context.Cause(ctx)
	}
	// Seal admission and drain emissions/heartbeats before the terminal callback.
	scanErr = errors.Join(scanErr, emitter.finish(), beats.stop())
	// Fatal causes can arrive while the last upload or heartbeat is draining.
	if ctx.Err() != nil {
		scanErr = errors.Join(scanErr, context.Cause(ctx))
	}
	return scanErr
}

func (a *Agent) startFailure(s *agentSession, job *client.Assignment, cause error) error {
	var terminalErr error
	// Poll has claimed the run. Release ordinary failed starts, but do not
	// mutate runs that the backend says are stale or inaccessible.
	if !client.IsStaleRunError(cause) {
		ctx, cancel := a.terminalContext(s)
		defer cancel()
		terminalErr = a.client.Fail(ctx, job, cause)
	}
	return fmt.Errorf("job %s: start failed: %w", job.ID(), errors.Join(cause, terminalErr))
}

func invokeScanner(scanner contract.Scanner, ctx context.Context, targets []contract.Target, emitter contract.Emitter) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("scanner panic: %v", recovered)
		}
	}()
	return scanner.Scan(ctx, targets, emitter)
}
