package client

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"
)

func TestAuthenticationErrorsRemainFatalInJoinedTargetErrors(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeUnauthenticated, connect.CodePermissionDenied} {
		err := fmt.Errorf("job failed: %w", errors.Join(
			connect.NewError(connect.CodeUnavailable, errors.New("first target")),
			fmt.Errorf("report failure: %w", connect.NewError(code, errors.New("token rejected"))),
		))
		if !IsAuthenticationError(err) || !IsStaleRunError(err) {
			t.Errorf("joined %s error was masked", code)
		}
	}
	for _, err := range []error{nil, context.Canceled, errors.Join(errors.New("scan failed"), connect.NewError(connect.CodeUnavailable, errors.New("unavailable")))} {
		if IsAuthenticationError(err) || IsStaleRunError(err) {
			t.Errorf("ordinary error classified as fatal: %v", err)
		}
	}
}
