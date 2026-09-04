package rediver

import "github.com/redivers/sdk-go/internal/contract"

// Emitter uploads observations for the current Scan invocation. Each method
// accepts per-target result sets; expand a slice with the ... operator.
// Only the method matching the backend job's scanner kind may be used.
//
// On that method, zero arguments or empty observations emit nothing. A result
// set still requires an original Target even when its observations are empty.
// Emitting never completes a target; a successful Scan completes the job.
// ErrorMessage is not uploaded until the backend protocol supports it and does
// not affect job status. Results containing only ErrorMessage emit nothing.
//
// Methods are safe for concurrent calls and snapshot observations before
// returning. A nil error acknowledges backend persistence. Calls are serialized
// per job, including uploads, to provide backpressure. Each call allows at most
// 100,000 observations and a 64 MiB encoded request; no cumulative limit applies.
// Finish all emitting goroutines before Scan returns. Errors remain sticky:
// ignoring an emission error still fails the pending scan batch.
type Emitter = contract.Emitter

// Result groups observations for one original input Target. ErrorMessage is
// optional and reserved for future protocol support; it is not uploaded yet.
type Result[T any] = contract.Result[T]

// DNSResult groups DNS observations for one original input Target. Multiple
// emissions for the same target are supported. Its own-domain record is optional
// in each call, may appear at most once across that call's wrappers, and is never
// synthesized. Repeated descendant observations are preserved within a call.
// Records are complete observations:
// repeated records across calls replace previous metadata rather than merge it.
type DNSResult = Result[DNSRecord]

// ServiceResult groups service observations for one original input Target.
// A service with an empty Host uses the original assignment's host.
type ServiceResult = Result[Service]

// FindingResult groups vulnerability observations for one original input Target.
type FindingResult = Result[Finding]
