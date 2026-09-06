package rediver_test

import (
	"errors"
	"fmt"
	"testing"

	rediver "github.com/redivers/sdk-go"
)

func TestSDKSentinelErrorsRemainDistinctThroughWrapping(t *testing.T) {
	sentinels := []struct {
		err     error
		message string
	}{
		{rediver.ErrInvalidConfig, "rediver: invalid configuration"},
		{rediver.ErrInvalidJob, "rediver: invalid job"},
		{rediver.ErrNoJobAvailable, "rediver: no job available"},
		{rediver.ErrAlreadyRunning, "rediver: agent already running"},
	}
	for index, sentinel := range sentinels {
		t.Run(sentinel.message, func(t *testing.T) {
			if sentinel.err.Error() != sentinel.message {
				t.Fatalf("message = %q, want %q", sentinel.err, sentinel.message)
			}
			wrapped := fmt.Errorf("operation: %w", sentinel.err)
			joined := errors.Join(errors.New("other failure"), wrapped)
			if !errors.Is(joined, sentinel.err) {
				t.Fatal("sentinel identity was lost through wrapping")
			}
			for otherIndex, other := range sentinels {
				if otherIndex != index && errors.Is(joined, other.err) {
					t.Fatalf("sentinel also matched %q", other.err)
				}
			}
		})
	}
}
