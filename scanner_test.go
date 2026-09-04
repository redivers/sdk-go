package rediver_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	rediver "github.com/redivers/sdk-go"
)

// One downstream implementation serves any job assigned by its backend token.
type customScanner struct{ scan rediver.ScanFunc }

func (s *customScanner) Scan(ctx context.Context, targets []rediver.Target, emit rediver.Emitter) error {
	return s.scan(ctx, targets, emit)
}

var (
	_ rediver.Scanner = (*customScanner)(nil)
	_ rediver.Scanner = rediver.ScanFunc(nil)
)

func TestScanFuncForwardsBatchAndResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	targets := []rediver.Target{{Domain: "one.example"}, {Domain: "two.example"}}
	emit := &recordingEmitter{}
	wantErr := errors.New("scanner failed")
	calls := 0
	scanner := rediver.ScanFunc(func(gotCtx context.Context, gotTargets []rediver.Target, gotEmit rediver.Emitter) error {
		calls++
		if gotCtx != ctx || gotEmit != emit || !reflect.DeepEqual(gotTargets, targets) {
			t.Fatal("ScanFunc changed the context, emitter or batch")
		}
		return wantErr
	})
	if err := scanner.Scan(ctx, targets, emit); err != wantErr {
		t.Fatalf("error = %v, want original scanner error", err)
	}
	if calls != 1 {
		t.Fatalf("scanner called %d times, want once for the complete batch", calls)
	}
}
