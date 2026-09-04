package runtime

import "fmt"

type jobError struct {
	JobID   string
	Message string
	Err     error
}

func (e *jobError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("job %s: %s: %v", e.JobID, e.Message, e.Err)
	}
	return fmt.Sprintf("job %s: %s", e.JobID, e.Message)
}

func (e *jobError) Unwrap() error { return e.Err }
