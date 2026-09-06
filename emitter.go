package rediver

import "github.com/redivers/sdk-go/internal/contract"

// Emitter uploads observations for the current Scan invocation. Each method
// accepts per-target result sets; expand a slice with the ... operator.
// Only the method matching the backend job's scanner kind may be used.
//
// On that method, zero arguments emit nothing. Every supplied result is the
// complete final outcome for its original Target. Empty Items with no
// ErrorMessage reports no observations and is still uploaded. A non-nil
// ErrorMessage reports a final failure for that target and cannot accompany
// Items. Return an error from Scan to report a transient whole-job failure.
//
// Methods are safe for concurrent calls and snapshot observations before
// returning. Each call with one or more results uploads immediately and waits
// for backend acknowledgement. Calls are serialized per job to provide
// backpressure. The first accepted push terminalizes each included target; emit
// each target once, as soon as its scan finishes. The backend ignores later
// pushes for that target. Finish all emitting goroutines before Scan returns.
// Errors remain sticky: ignoring an emission error still fails the pending scan
// batch.
type Emitter = contract.Emitter

// Result reports the complete final outcome for one original input Target.
// Empty Items with no ErrorMessage reports no observations and is still
// uploaded. A result may contain Items or ErrorMessage, never both.
type Result[T any] = contract.Result[T]

// DNSResult reports the complete DNS outcome for one original input Target.
// The SDK does not require or synthesize the assigned domain's record; backend
// validation decides which payloads it accepts. Repeated descendant observations
// are preserved. Records are complete observations; backend projection replaces
// scanner-owned metadata rather than merging it.
type DNSResult = Result[DNSRecord]

// ServiceResult reports the complete service outcome for one original input
// Target.
// A service with an empty Host uses the original assignment's host.
type ServiceResult = Result[Service]

// FindingResult reports the complete vulnerability outcome for one original
// input Target.
type FindingResult = Result[Finding]
