package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
	"github.com/redivers/sdk-go/internal/contract"
)

func TestRegistrationPreservesMetadataPresenceAndReturnedRunnerID(t *testing.T) {
	for _, filled := range []bool{false, true} {
		metadata := Registration{}
		if filled {
			metadata = Registration{Hostname: "host", Version: "v1"}
		}
		s := &clientTestServer{register: func(_ context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
			if len(req.GetRunnerId()) != 36 {
				t.Errorf("candidate runner ID = %q", req.GetRunnerId())
			}
			if filled {
				if req.IpAddress != nil || req.GetHostname() != metadata.Hostname || req.GetVersion() != metadata.Version {
					t.Errorf("metadata=%v", req)
				}
			} else if req.Hostname != nil || req.IpAddress != nil || req.Version != nil {
				t.Error("empty metadata lost absence")
			}
			return &pb.RegisterResponse{RunnerId: "runner-server"}, nil
		}}
		c := newTestClient(t, s)
		id, err := c.Register(context.Background(), metadata)
		if err != nil || id != "runner-server" {
			t.Fatalf("registration=%q,%v", id, err)
		}
		if err := c.Heartbeat(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRegistrationReusesCandidateRunnerIDAcrossRetries(t *testing.T) {
	var candidates []string
	s := &clientTestServer{register: func(_ context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
		candidates = append(candidates, req.GetRunnerId())
		if len(candidates) == 1 {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("acknowledgement lost"))
		}
		return &pb.RegisterResponse{RunnerId: req.GetRunnerId()}, nil
	}}
	server := startClientServer(t, s)
	c := New("network-token", server.URL, server.Client(), time.Second, contract.RetryPolicy{MaxAttempts: 2})
	runnerID, err := c.Register(context.Background(), Registration{})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0] == "" || candidates[0] != candidates[1] || runnerID != candidates[0] {
		t.Fatalf("registration candidates = %v; returned runner = %q", candidates, runnerID)
	}
}

func TestRegistrationRejectsBlankRunnerID(t *testing.T) {
	c := newTestClient(t, &clientTestServer{register: func(context.Context, *pb.RegisterRequest) (*pb.RegisterResponse, error) {
		return &pb.RegisterResponse{RunnerId: " \t"}, nil
	}})
	if _, err := c.Register(context.Background(), Registration{}); err == nil || !strings.Contains(err.Error(), "empty runner ID") {
		t.Fatalf("registration=%v", err)
	}
}
