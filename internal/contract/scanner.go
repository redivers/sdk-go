package contract

import "context"

// Scanner processes all unfinished targets of one backend job in a single call.
// The token selects the scanner kind. Implementations emit one final result for
// every supplied target and return nil only after the whole batch is scanned.
// Every result type may use empty Items to report no observations; the backend
// applies its own result validation. Join any goroutines that use the emitter
// before returning.
type Scanner interface {
	Scan(context.Context, []Target, Emitter) error
}

// ScanFunc adapts a function to Scanner.
type ScanFunc func(context.Context, []Target, Emitter) error

// Scan invokes the batch handler.
func (f ScanFunc) Scan(ctx context.Context, targets []Target, emitter Emitter) error {
	return f(ctx, targets, emitter)
}
