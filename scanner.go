package rediver

import "github.com/redivers/sdk-go/internal/contract"

// Scanner processes all unfinished targets of one backend job in a single call.
// The token selects the scanner kind. Implementations emit observations against
// the supplied targets and return nil only after the whole batch is scanned.
// Join any goroutines that use the emitter before returning.
type Scanner = contract.Scanner

// ScanFunc adapts a function to Scanner.
type ScanFunc = contract.ScanFunc
