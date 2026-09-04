package client

import (
	"fmt"
	"math"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func optionalResultString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func resultInt32(value int, field string) (int32, error) {
	if int64(value) < math.MinInt32 || int64(value) > math.MaxInt32 {
		return 0, fmt.Errorf("rediver: %s is outside the int32 range", field)
	}
	return int32(value), nil
}

func resultPort(value int, field string) (int32, error) {
	if value < 1 || value > 65535 {
		return 0, fmt.Errorf("rediver: %s must be between 1 and 65535", field)
	}
	return int32(value), nil
}

func resultTimestamp(value time.Time, field string) (*timestamppb.Timestamp, error) {
	if value.IsZero() {
		return nil, nil
	}
	stamp := timestamppb.New(value)
	if err := stamp.CheckValid(); err != nil {
		return nil, fmt.Errorf("rediver: %s is invalid: %w", field, err)
	}
	return stamp, nil
}

func ptr[T any](value T) *T { return &value }
