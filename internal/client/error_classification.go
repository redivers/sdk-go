package client

import (
	"connectrpc.com/connect"
)

// A job may join failures from several targets and its terminal callback.
// CodeOf returns the first Connect error; fatal classification must inspect all
// branches so a transient scan error cannot hide a later token rejection.
func hasConnectCode(err error, codes ...connect.Code) bool {
	if err == nil {
		return false
	}
	code := connect.CodeOf(err)
	for _, expected := range codes {
		if code == expected {
			return true
		}
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range wrapped.Unwrap() {
			if hasConnectCode(child, codes...) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return hasConnectCode(wrapped.Unwrap(), codes...)
	}
	return false
}

func IsAuthenticationError(err error) bool {
	return hasConnectCode(err, connect.CodeUnauthenticated, connect.CodePermissionDenied)
}
func IsStaleRunError(err error) bool {
	return hasConnectCode(err, connect.CodeFailedPrecondition, connect.CodeNotFound, connect.CodeUnauthenticated, connect.CodePermissionDenied)
}
func IsTransientPollError(err error) bool {
	if IsStaleRunError(err) {
		return false
	}
	return hasConnectCode(err, connect.CodeUnavailable, connect.CodeResourceExhausted, connect.CodeDeadlineExceeded) || isRetryableError(err)
}
