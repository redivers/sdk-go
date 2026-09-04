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
	response, err := c.rpc.JobStart(ctx, connect.NewRequest(&pb.JobStartRequest{JobId: assignment.ID(), RunId: assignment.RunID()}))
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
		_, err := c.rpc.JobHeartbeat(ctx, connect.NewRequest(&pb.JobHeartbeatRequest{JobId: assignment.ID(), RunId: assignment.RunID()}))
		return err
	})
}

func (c *Client) Complete(ctx context.Context, assignment *Assignment) error {
	response, err := c.rpc.JobCompleted(ctx, connect.NewRequest(&pb.JobCompletedRequest{JobId: assignment.ID(), RunId: assignment.RunID()}))
	if err != nil {
		return fmt.Errorf("complete job: %w", err)
	}
	if !response.Msg.Success {
		return fmt.Errorf("completion rejected: %s", response.Msg.GetMessage())
	}
	return nil
}

func (c *Client) Fail(ctx context.Context, assignment *Assignment, cause error) error {
	response, err := c.rpc.JobFailure(ctx, connect.NewRequest(&pb.JobFailureRequest{JobId: assignment.ID(), RunId: assignment.RunID(), ErrorMessage: cause.Error()}))
	if err != nil {
		return fmt.Errorf("report job failure: %w", err)
	}
	if !response.Msg.Success {
		return fmt.Errorf("failure rejected: %s", response.Msg.GetMessage())
	}
	return nil
}
