package client

import (
	"fmt"
	"slices"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
)

// Assignment retains the private decoded job and its original target registry.
// Target references never point back here, so retaining a target retains no job.
type Assignment struct {
	job            *pb.Job
	targets        []contract.Target
	prepared       bool
	preparationErr error
}

func (a *Assignment) ID() string    { return a.job.GetJobId() }
func (a *Assignment) RunID() string { return a.job.GetRunId() }

// PrepareTargets runs synchronously after Start and before scanner publication.
// The result is stable on repeated calls; references are never regenerated.
func (a *Assignment) PrepareTargets() error {
	if a.prepared {
		return a.preparationErr
	}
	a.prepared = true
	a.targets, a.preparationErr = scannerTargets(a.job)
	return a.preparationErr
}

// Targets returns independent values and port slices with unchanged references.
func (a *Assignment) Targets() []contract.Target {
	targets := slices.Clone(a.targets)
	for i := range targets {
		targets[i].Ports = slices.Clone(targets[i].Ports)
	}
	return targets
}

func (a *Assignment) validatePush(kind pb.Scanner) error {
	if a == nil || !a.prepared || a.preparationErr != nil {
		return fmt.Errorf("rediver: result emission requires a prepared assignment")
	}
	if a.job.Scanner != kind {
		return fmt.Errorf("rediver: %s results are unsupported for %s", kind, a.job.Scanner)
	}
	return nil
}

func (a *Assignment) resolveTarget(target contract.Target) (int, error) {
	if index, ok := contract.ResolveTarget(target, a.targets); ok {
		return index, nil
	}
	return 0, fmt.Errorf("rediver: emit requires an original target from this Scan invocation")
}
