package contract

import "errors"

// Sentinel errors for common failure scenarios.
var (
	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("rediver: invalid configuration")

	// ErrInvalidJob indicates the job data is invalid or malformed.
	ErrInvalidJob = errors.New("rediver: invalid job")

	// ErrNoJobAvailable indicates no pending jobs are available.
	// This is not necessarily an error in one-shot mode.
	ErrNoJobAvailable = errors.New("rediver: no job available")

	// ErrAlreadyRunning is returned when a lifecycle method is called on an Agent
	// that has already started. Agents are one-shot; create a new Agent to restart.
	ErrAlreadyRunning = errors.New("rediver: agent already running")

	// ErrIncompleteCoverage indicates a scan returned without reaching a terminal
	// per-target outcome for every assigned target while strict coverage is
	// enabled. The job is failed instead of completed so the backend retries the
	// missing targets on a later job.
	ErrIncompleteCoverage = errors.New("rediver: scan did not report every assigned target")
)
