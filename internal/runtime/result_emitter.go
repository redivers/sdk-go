package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/redivers/sdk-go/internal/client"
	"github.com/redivers/sdk-go/internal/contract"
)

type resultEmitter struct {
	// The state lock remains available while conversion and I/O hold emitMu,
	// so closing can cancel the operation it needs to interrupt.
	emitMu     sync.Mutex
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelCauseFunc
	cancelScan context.CancelCauseFunc
	job        *client.Assignment
	client     *client.Client
	closed     bool
	firstErr   error
}

var _ contract.Emitter = (*resultEmitter)(nil)

func newResultEmitter(ctx context.Context, job *client.Assignment, backend *client.Client, cancelScan context.CancelCauseFunc) *resultEmitter {
	ctx, cancel := context.WithCancelCause(ctx)
	return &resultEmitter{ctx: ctx, cancel: cancel, cancelScan: cancelScan, job: job, client: backend}
}

func (e *resultEmitter) EmitDomains(results ...contract.DNSResult) error {
	return e.emit("EmitDomains", func(ctx context.Context, backend *client.Client, job *client.Assignment) error {
		return backend.PushDomains(ctx, job, results...)
	})
}

func (e *resultEmitter) EmitServices(results ...contract.ServiceResult) error {
	return e.emit("EmitServices", func(ctx context.Context, backend *client.Client, job *client.Assignment) error {
		return backend.PushServices(ctx, job, results...)
	})
}

func (e *resultEmitter) EmitFindings(results ...contract.FindingResult) error {
	return e.emit("EmitFindings", func(ctx context.Context, backend *client.Client, job *client.Assignment) error {
		return backend.PushFindings(ctx, job, results...)
	})
}

func (e *resultEmitter) fail(err error) error {
	if e.firstErr == nil {
		e.firstErr = err
	}
	return err
}

func (e *resultEmitter) emit(name string, upload func(context.Context, *client.Client, *client.Assignment) error) error {
	e.emitMu.Lock()
	defer e.emitMu.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			// A scanner may recover this panic itself; the job must remain failed.
			e.mu.Lock()
			e.fail(fmt.Errorf("rediver: %s panic: %v", name, recovered))
			e.mu.Unlock()
			panic(recovered)
		}
	}()
	e.mu.Lock()
	if err := e.emissionState(); err != nil {
		e.mu.Unlock()
		return err
	}
	backend, job, cancelScan := e.client, e.job, e.cancelScan
	e.mu.Unlock()
	err := upload(e.ctx, backend, job)
	e.mu.Lock()
	if err == nil {
		err = context.Cause(e.ctx)
	}
	if err != nil {
		err = e.fail(fmt.Errorf("rediver: %s: %w", name, err))
	}
	e.mu.Unlock()
	if cancelScan != nil && client.IsStaleRunError(err) {
		cancelScan(err)
	}
	return err
}

func (e *resultEmitter) emissionState() error {
	if e.firstErr != nil {
		return e.firstErr
	}
	if e.closed {
		if err := context.Cause(e.ctx); err != nil {
			return err
		}
		return fmt.Errorf("rediver: result emission is closed")
	}
	if err := context.Cause(e.ctx); err != nil {
		return e.fail(err)
	}
	return nil
}

// finish closes admission before waiting for an already active call to drain.
func (e *resultEmitter) finish() error {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	e.emitMu.Lock()
	defer e.emitMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	return errors.Join(e.firstErr, context.Cause(e.ctx))
}

func (e *resultEmitter) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	e.job, e.client, e.cancelScan = nil, nil, nil
	e.cancel(fmt.Errorf("rediver: result emission is closed"))
}
