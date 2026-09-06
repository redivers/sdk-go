package contract

// Target describes one assignment in the batch supplied to Scanner.Scan.
// Keep the original value (or a copy) in emitted result sets; constructing a new
// Target does not preserve its private assignment reference. Displayed fields
// may be changed locally without redirecting emitted observations.
//
// Domain is used for DNS scanning; Host, Port and URL identify network services.
// Ports and Rate are populated for service discovery. Rate is one shared
// per-job probe budget, not a separate budget for each target. The scanner must
// enforce that budget across the batch. Each target owns its Ports slice.
type Target struct {
	Domain string
	Host   string
	Port   int
	URL    string
	Ports  []int
	Rate   int

	ref *targetReference
}

// References have no pointer back to a job or its results, so keeping a target
// after Scan returns cannot keep the SDK's assignment data alive.
type targetReference struct {
	index int
}

// BindTarget gives a native target a fresh assignment reference. Bind each target
// once while preparing an assignment; copies then retain the same reference.
func BindTarget(target Target, index int) Target {
	target.ref = &targetReference{index: index}
	return target
}

// ResolveTarget returns the target's index only when its reference belongs to
// the original assignment registry. Displayed fields never determine identity.
func ResolveTarget(target Target, originals []Target) (int, bool) {
	if target.ref == nil {
		return 0, false
	}
	index := target.ref.index
	if index < 0 || index >= len(originals) || originals[index].ref != target.ref {
		return 0, false
	}
	return index, true
}
