package rediver

import "github.com/redivers/sdk-go/internal/contract"

// Sentinel errors for common failure scenarios.
var (
	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = contract.ErrInvalidConfig

	// ErrInvalidJob indicates the job data is invalid or malformed.
	ErrInvalidJob = contract.ErrInvalidJob

	// ErrNoJobAvailable indicates no pending jobs are available.
	// This is not necessarily an error in one-shot mode.
	ErrNoJobAvailable = contract.ErrNoJobAvailable

	// ErrAlreadyRunning is returned when a lifecycle method is called on an Agent
	// that has already started. Agents are one-shot; create a new Agent to restart.
	ErrAlreadyRunning = contract.ErrAlreadyRunning
)
