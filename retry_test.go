package rediver_test

import (
	"reflect"
	"testing"
	"time"

	rediver "github.com/redivers/sdk-go"
)

func TestRetryPolicyPresets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy rediver.RetryPolicy
		want   rediver.RetryPolicy
	}{
		{"default", rediver.DefaultRetryPolicy(), rediver.RetryPolicy{
			MaxAttempts: 5, InitialBackoff: time.Second, MaxBackoff: time.Minute,
			BackoffMultiplier: 2, Jitter: true, RetryableStatusCodes: []int{429, 502, 503, 504},
		}},
		{"aggressive", rediver.AggressiveRetryPolicy(), rediver.RetryPolicy{
			MaxAttempts: 10, InitialBackoff: 2 * time.Second, MaxBackoff: 2 * time.Minute,
			BackoffMultiplier: 2, Jitter: true, RetryableStatusCodes: []int{429, 502, 503, 504},
		}},
		{"disabled", rediver.NoRetry(), rediver.RetryPolicy{MaxAttempts: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !reflect.DeepEqual(tc.policy, tc.want) {
				t.Fatalf("policy = %#v, want %#v", tc.policy, tc.want)
			}
		})
	}
}

func TestRetryPolicyPresetsHaveIndependentStatusCodes(t *testing.T) {
	for name, preset := range map[string]func() rediver.RetryPolicy{
		"default": rediver.DefaultRetryPolicy, "aggressive": rediver.AggressiveRetryPolicy,
	} {
		t.Run(name, func(t *testing.T) {
			first, second := preset(), preset()
			first.RetryableStatusCodes[0] = 418
			if second.RetryableStatusCodes[0] != 429 || preset().RetryableStatusCodes[0] != 429 {
				t.Fatal("changing one preset modified another policy")
			}
		})
	}
}
