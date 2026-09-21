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
	// Correlates every job with its runner for both Run and RunOnce; RunOnce
	// otherwise emits no SDK log line of its own on a clean success.
	a.cfg.Logger.InfoContext(s.work, "network scan job started", "job_id", job.ID(), "runner_id", a.currentRunnerID())
	scanErr := a.scan(s.work, job)
	if scanErr == nil {
		scanErr = a.coverageError(s.work, job)
	}
	terminalCtx, terminalCancel := a.terminalContext(s)
	defer terminalCancel()
	var terminalErr error
	if scanErr == nil {
		terminalErr = a.client.Complete(terminalCtx, job)
	} else {
		terminalErr = a.client.Fail(terminalCtx, job, scanErr)
	}
	outcome := "completed"
	if scanErr != nil {
		outcome = "failed"
	}
	a.cfg.Logger.InfoContext(s.work, "network scan job finished", "job_id", job.ID(), "runner_id", a.currentRunnerID(), "outcome", outcome)
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

// coverageError reports ErrIncompleteCoverage when strict coverage is enabled
// and the scan returned without a terminal outcome for every assigned target.
// The full missing-target list goes only to the local log: the returned error
// becomes JobCompletedRequest.error_message, which the backend can copy onto
// every requeued target row, so an uncapped list of asset scan IDs would write
// megabytes across a large job's rows.
func (a *Agent) coverageError(ctx context.Context, job *client.Assignment) error {
	if !a.cfg.StrictCoverage || job.FullyCovered() {
		return nil
	}
	missing := job.MissingTargets()
	a.cfg.Logger.ErrorContext(ctx, "network scan job missing target coverage", "job_id", job.ID(), "missing_targets", missing)
	return fmt.Errorf("%w: %s", contract.ErrIncompleteCoverage, summarizeMissingTargets(missing))
}

// missingTargetsPreviewLimit bounds how many asset scan IDs the coverage error
// message names directly; the rest are counted only.
const missingTargetsPreviewLimit = 5

func summarizeMissingTargets(missing []string) string {
	if len(missing) <= missingTargetsPreviewLimit {
		return fmt.Sprintf("%d target(s) unreported: %v", len(missing), missing)
	}
	return fmt.Sprintf("%d target(s) unreported; first %d: %v", len(missing), missingTargetsPreviewLimit, missing[:missingTargetsPreviewLimit])
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
