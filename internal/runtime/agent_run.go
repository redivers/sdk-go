package runtime

import (
	"context"
	"errors"
	"time"

	"github.com/redivers/sdk-go/internal/client"
	"github.com/redivers/sdk-go/internal/contract"
)

// Run polls with bounded concurrency, logging individual job failures and
// continuing to other jobs. Authentication, runner heartbeat, malformed claims
// and nontransient poll errors stop the run. Parent cancellation drains active jobs for WithShutdownTimeout;
// Stop cancels their contexts immediately. Terminal reporting receives a
// separate budget bounded by the smaller request and shutdown timeouts.
func (a *Agent) Run(ctx context.Context) error {
	return a.withSession(ctx, true, func(s *agentSession) error { return a.run(s) })
}

func (a *Agent) run(s *agentSession) error {
	type jobResult struct {
		jobID, runID string
		err          error
	}
	results := make(chan jobResult, a.cfg.MaxConcurrency)
	active := 0
	var resultErr error
	consume := func(result jobResult) {
		active--
		if result.err != nil {
			a.cfg.Logger.ErrorContext(s.work, "network scan job failed", "job_id", result.jobID, "run_id", result.runID, "error", result.err)
			if client.IsAuthenticationError(result.err) {
				resultErr = errors.Join(resultErr, result.err)
				s.cancel(result.err)
			} else if errors.Is(result.err, contract.ErrInvalidJob) {
				resultErr = errors.Join(resultErr, result.err)
				s.cancelPoll()
			}
		}
	}
	waitPoll := func() bool {
		timer := time.NewTimer(a.cfg.PollInterval)
		defer timer.Stop()
		for {
			select {
			case <-s.poll.Done():
				return false
			case result := <-results:
				consume(result)
			case <-timer.C:
				return true
			}
		}
	}
	polling := true
	for polling && s.poll.Err() == nil {
		if active == a.cfg.MaxConcurrency {
			select {
			case err := <-results:
				consume(err)
			case <-s.poll.Done():
			}
			continue
		}
		select {
		case err := <-results:
			consume(err)
			continue
		default:
		}
		job, err := a.client.Poll(s.poll)
		if err != nil {
			if s.poll.Err() != nil {
				break
			}
			if client.IsTransientPollError(err) {
				a.cfg.Logger.WarnContext(s.work, "network scan poll failed", "error", err)
				polling = waitPoll()
				continue
			}
			resultErr = errors.Join(resultErr, err)
			if client.IsAuthenticationError(err) {
				s.cancel(err)
			}
			break
		}
		if job != nil {
			active++
			go func() {
				err := a.execute(s, job)
				results <- jobResult{jobID: job.ID(), runID: job.RunID(), err: err}
				if client.IsAuthenticationError(err) {
					s.cancel(err)
				}
			}()
			continue
		}
		polling = waitPoll()
	}
	s.cancelPoll()
	timer := time.NewTimer(a.cfg.ShutdownTimeout)
	defer timer.Stop()
	for active > 0 {
		select {
		case err := <-results:
			consume(err)
		case <-timer.C:
			s.cancelWork(context.DeadlineExceeded)
			resultErr = errors.Join(resultErr, context.DeadlineExceeded)
			// Canceled jobs close their emitters and join their heartbeat loops.
			// Failure reporting uses its own bounded cleanup budget.
			for active > 0 {
				consume(<-results)
			}
		}
	}
	if cause := context.Cause(s.work); cause != nil && !errors.Is(cause, context.Canceled) {
		resultErr = errors.Join(resultErr, cause)
	}
	return resultErr
}
