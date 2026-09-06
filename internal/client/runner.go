package client

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
)

// Registration contains SDK-owned runner metadata, with empty values omitted.
type Registration struct{ Hostname, Version string }

func (c *Client) Register(ctx context.Context, metadata Registration) (string, error) {
	// Keep one candidate across retries so a lost acknowledgement cannot create
	// another runner when hostname metadata is unavailable.
	candidateID, err := newRunnerID()
	if err != nil {
		return "", fmt.Errorf("generate runner ID: %w", err)
	}
	request := &pb.RegisterRequest{RunnerId: &candidateID, Hostname: optionalResultString(metadata.Hostname), Version: optionalResultString(metadata.Version)}
	var runnerID string
	err = c.retry(ctx, func(ctx context.Context) error {
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

func newRunnerID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:]), nil
}

func (c *Client) Heartbeat(ctx context.Context, runnerID string) error {
	return c.retry(ctx, func(ctx context.Context) error {
		_, err := c.rpc.Heartbeat(ctx, connect.NewRequest(&pb.HeartbeatRequest{RunnerId: runnerID}))
		return err
	})
}
