package client

import (
	"context"
	"strings"
	"testing"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
)

func TestRegistrationPreservesMetadataPresenceAndReturnedRunnerID(t *testing.T) {
	for _, filled := range []bool{false, true} {
		metadata := Registration{}
		if filled {
			metadata = Registration{RunnerID: "candidate", Hostname: "host", IPAddress: "192.0.2.1", Version: "v1"}
		}
		s := &clientTestServer{register: func(_ context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
			if filled {
				if req.GetRunnerId() != metadata.RunnerID || req.GetHostname() != metadata.Hostname || req.GetIpAddress() != metadata.IPAddress || req.GetVersion() != metadata.Version {
					t.Errorf("metadata=%v", req)
				}
			} else if req.RunnerId != nil || req.Hostname != nil || req.IpAddress != nil || req.Version != nil {
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

func TestRegistrationRejectsBlankRunnerID(t *testing.T) {
	c := newTestClient(t, &clientTestServer{register: func(context.Context, *pb.RegisterRequest) (*pb.RegisterResponse, error) {
		return &pb.RegisterResponse{RunnerId: " \t"}, nil
	}})
	if _, err := c.Register(context.Background(), Registration{}); err == nil || !strings.Contains(err.Error(), "empty runner ID") {
		t.Fatalf("registration=%v", err)
	}
}
