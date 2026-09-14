package client

import (
	"context"
	"fmt"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
)

// Poll claims one job; a lost response must not transparently claim another.
func (c *Client) Poll(ctx context.Context) (*Assignment, error) {
	response, err := c.rpc.JobPoll(ctx, connect.NewRequest(&pb.JobPollRequest{}))
	if err != nil {
		return nil, fmt.Errorf("poll job: %w", err)
	}
	if response.Msg.Job == nil {
		return nil, nil
	}
	if err := validateJob(response.Msg.Job); err != nil {
		return nil, err
	}
	return &Assignment{job: response.Msg.Job}, nil
}

func (c *Client) Start(ctx context.Context, assignment *Assignment) error {
	response, err := c.rpc.JobStart(ctx, connect.NewRequest(&pb.JobStartRequest{JobId: assignment.ID()}))
	if err != nil {
		return err
	}
	if !response.Msg.Success {
		return fmt.Errorf("start rejected: %s", response.Msg.GetMessage())
	}
	return nil
}

func (c *Client) JobHeartbeat(ctx context.Context, assignment *Assignment) error {
	return c.retry(ctx, func(ctx context.Context) error {
		_, err := c.rpc.JobHeartbeat(ctx, connect.NewRequest(&pb.JobHeartbeatRequest{JobId: assignment.ID()}))
		return err
	})
}

// Complete closes the job as a clean run: every target the scanner never
// reported is taken as finished, because the scanner had its chance at each.
func (c *Client) Complete(ctx context.Context, assignment *Assignment) error {
	return c.close(ctx, assignment, nil)
}

// Fail closes the job as a broken run. Every target the scanner never concluded
// goes back to be carried by a later job until its attempts run out. It reports
// trouble with the run itself; a verdict about one target belongs on that
// target's result message, which is never retried.
func (c *Client) Fail(ctx context.Context, assignment *Assignment, cause error) error {
	message := cause.Error()
	return c.close(ctx, assignment, &message)
}

// close is the one call that ends a job. errorMessage nil is a clean close,
// non-nil a broken one — the backend has no second RPC for the broken case.
func (c *Client) close(ctx context.Context, assignment *Assignment, errorMessage *string) error {
	response, err := c.rpc.JobCompleted(ctx, connect.NewRequest(&pb.JobCompletedRequest{
		JobId:        assignment.ID(),
		ErrorMessage: errorMessage,
	}))
	if err != nil {
		if errorMessage != nil {
			return fmt.Errorf("report job failure: %w", err)
		}
		return fmt.Errorf("complete job: %w", err)
	}
	if !response.Msg.Success {
		if errorMessage != nil {
			return fmt.Errorf("failure rejected: %s", response.Msg.GetMessage())
		}
		return fmt.Errorf("completion rejected: %s", response.Msg.GetMessage())
	}
	return nil
}
