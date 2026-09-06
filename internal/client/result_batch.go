package client

import (
	"fmt"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
)

type emissionGroup[T any] struct {
	target       *pb.JobTarget
	errorMessage *string
	observations []T
}

// Validate all references before allocating conversions.
// Preserve first-appearance order while combining wrappers for one target; the
// wire protocol accepts each target only once within a request. Keep groups
// with no observations or error because they are explicit successful outcomes.
func groupEmissionResults[T any](a *Assignment, results []contract.Result[T]) ([]emissionGroup[T], error) {
	for index, result := range results {
		if _, err := a.resolveTarget(result.Target); err != nil {
			return nil, fmt.Errorf("result %d: %w", index, err)
		}
		if result.ErrorMessage != nil && len(result.Items) > 0 {
			return nil, fmt.Errorf("rediver: result %d cannot contain both ErrorMessage and Items", index)
		}
	}
	var groups []emissionGroup[T]
	positions := make(map[int]int)
	for resultIndex, result := range results {
		index, _ := a.resolveTarget(result.Target)
		position, exists := positions[index]
		if !exists {
			position = len(groups)
			positions[index] = position
			groups = append(groups, emissionGroup[T]{target: a.job.Targets[index]})
		}
		group := &groups[position]
		if result.ErrorMessage != nil {
			if group.errorMessage != nil {
				return nil, fmt.Errorf("rediver: result %d repeats ErrorMessage for the same target", resultIndex)
			}
			if len(group.observations) > 0 {
				return nil, fmt.Errorf("rediver: result %d conflicts with Items for the same target", resultIndex)
			}
			message := *result.ErrorMessage
			group.errorMessage = &message
			continue
		}
		if len(result.Items) == 0 {
			continue
		}
		if group.errorMessage != nil {
			return nil, fmt.Errorf("rediver: result %d conflicts with ErrorMessage for the same target", resultIndex)
		}
		group.observations = append(group.observations, result.Items...)
	}
	return groups, nil
}
