package client

import (
	"context"
	"errors"
	"fmt"
	"strings"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
)

// Registration contains native runner metadata, with empty values omitted.
type Registration struct{ RunnerID, Hostname, IPAddress, Version string }

func (c *Client) Register(ctx context.Context, metadata Registration) (string, error) {
	request := &pb.RegisterRequest{RunnerId: optionalResultString(metadata.RunnerID), Hostname: optionalResultString(metadata.Hostname), IpAddress: optionalResultString(metadata.IPAddress), Version: optionalResultString(metadata.Version)}
	var runnerID string
	err := c.retry(ctx, func(ctx context.Context) error {
		response, err := c.rpc.Register(ctx, connect.NewRequest(request))
		if err != nil {
			return err
		}
		if strings.TrimSpace(response.Msg.RunnerId) == "" {
			return errors.New("registration returned an empty runner ID")
		}
		runnerID = response.Msg.RunnerId
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("register runner: %w", err)
	}
	return runnerID, nil
}

func (c *Client) Heartbeat(ctx context.Context, runnerID string) error {
	return c.retry(ctx, func(ctx context.Context) error {
		_, err := c.rpc.Heartbeat(ctx, connect.NewRequest(&pb.HeartbeatRequest{RunnerId: runnerID}))
		return err
	})
}
