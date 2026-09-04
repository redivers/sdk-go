package client

import (
	"fmt"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
)

// Limits apply to one typed push, including all original target echoes.
const (
	maxEmissionBytes   = 64 << 20
	maxEmissionRecords = 100_000
)

type emissionGroup[T any] struct {
	target       *pb.JobTarget
	observations []T
}

// Validate all references and the total count before allocating conversions.
// Preserve first-appearance order while combining wrappers for one target; the
// wire protocol accepts each target only once within a request.
func groupEmissionResults[T any](a *Assignment, results []contract.Result[T]) ([]emissionGroup[T], error) {
	count := 0
	for index, result := range results {
		if _, err := a.resolveTarget(result.Target); err != nil {
			return nil, fmt.Errorf("result %d: %w", index, err)
		}
		if len(result.Items) > maxEmissionRecords-count {
			return nil, fmt.Errorf("rediver: results exceed the per-call limit (100000 records)")
		}
		count += len(result.Items)
	}
	if count == 0 {
		return nil, nil
	}
	var groups []emissionGroup[T]
	positions := make(map[int]int)
	for _, result := range results {
		if len(result.Items) == 0 {
			continue
		}
		index, _ := a.resolveTarget(result.Target)
		position, exists := positions[index]
		if !exists {
			position = len(groups)
			positions[index] = position
			groups = append(groups, emissionGroup[T]{target: a.job.Targets[index]})
		}
		groups[position].observations = append(groups[position].observations, result.Items...)
	}
	return groups, nil
}
