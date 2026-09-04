package runtime

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestJobError_Error_WithWrapped(t *testing.T) {
	err := &jobError{JobID: "j1", Message: "fail", Err: io.EOF}
	want := "job j1: fail: EOF"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestJobError_Error_WithoutWrapped(t *testing.T) {
	err := &jobError{JobID: "j1", Message: "fail"}
	want := "job j1: fail"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestJobError_Unwrap(t *testing.T) {
	inner := io.EOF
	err := &jobError{JobID: "j1", Message: "fail", Err: inner}
	if !errors.Is(err, io.EOF) {
		t.Error("JobError should unwrap to inner error")
	}
}

func TestJobErrorCanBeFoundThroughWrapping(t *testing.T) {
	jobErr := &jobError{JobID: "j1", Message: "fail"}
	wrapped := fmt.Errorf("outer: %w", jobErr)
	var target *jobError
	if !errors.As(wrapped, &target) || target.JobID != "j1" {
		t.Fatalf("job diagnostics lost through wrapping: %v", wrapped)
	}
}
