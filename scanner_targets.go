package rediver

import "github.com/redivers/sdk-go/internal/contract"

// Target describes one assignment in the batch supplied to Scanner.Scan.
// Keep the original value (or a copy) in emitted result sets; constructing a new
// Target does not preserve its private assignment reference. Displayed fields
// may be changed locally without redirecting emitted observations.
//
// Domain is used for DNS scanning; Host, Port and URL identify network services.
// Ports and Rate are populated for service discovery. Rate is one shared
// per-job probe budget, not a separate budget for each target. The scanner must
// enforce that budget across the batch. Each target owns its Ports slice.
type Target = contract.Target
