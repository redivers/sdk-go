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

func TestPollReturnsPrivateValidatedAssignment(t *testing.T) {
	for _, variant := range []string{"empty", "valid", "malformed", "invalid ports"} {
		t.Run(variant, func(t *testing.T) {
			s := &clientTestServer{job: clientTestJob()}
			switch variant {
			case "empty":
				s.job = nil
			case "malformed":
				s.job.RunId = ""
			case "invalid ports":
				s.job.Options.GetServiceDiscover().Ports = "80-"
			}
			c := newTestClient(t, s)
			a, err := c.Poll(context.Background())
			switch variant {
			case "empty":
				if err != nil || a != nil {
					t.Fatalf("empty poll=%v,%v", a, err)
				}
			case "malformed":
				if !errors.Is(err, contract.ErrInvalidJob) || a != nil {
					t.Fatalf("malformed poll=%v,%v", a, err)
				}
			default:
				if err != nil || a == nil || a.ID() != s.job.JobId || a.RunID() != s.job.RunId {
					t.Fatalf("polled identity=%v,%v", a, err)
				}
				if len(a.Targets()) != 0 {
					t.Fatal("Poll prepared targets before Start")
				}
				if err := c.Start(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				err = a.PrepareTargets()
				if (variant == "invalid ports") != errors.Is(err, contract.ErrInvalidJob) {
					t.Fatalf("prepare error=%v", err)
				}
			}
		})
	}
}

func TestRPCsPreserveRetryEligibility(t *testing.T) {
	unavailable := connect.NewError(connect.CodeUnavailable, errors.New("try later"))
	for _, name := range []string{"register", "heartbeat", "poll", "start", "job-heartbeat", "completed", "failure"} {
		t.Run(name, func(t *testing.T) {
			s := &clientTestServer{
				register:     func(context.Context, *pb.RegisterRequest) (*pb.RegisterResponse, error) { return nil, unavailable },
				heartbeat:    func(context.Context, *pb.HeartbeatRequest) error { return unavailable },
				poll:         func(context.Context) (*pb.Job, error) { return nil, unavailable },
				start:        func(context.Context, *pb.JobStartRequest) (*pb.JobStartResponse, error) { return nil, unavailable },
				jobHeartbeat: func(context.Context, *pb.JobHeartbeatRequest) error { return unavailable },
				completed: func(context.Context, *pb.JobCompletedRequest) (*pb.JobCompletedResponse, error) {
					return nil, unavailable
				},
				failure: func(context.Context, *pb.JobFailureRequest) (*pb.JobFailureResponse, error) { return nil, unavailable },
			}
			server := startClientServer(t, s)
			policy := contract.RetryPolicy{MaxAttempts: 3, RetryableStatusCodes: []int{503}}
			c := New("network-token", server.URL, server.Client(), time.Second, policy)
			a := preparedAssignment(t, clientTestJob())
			ctx := context.Background()
			var err error
			want := 1
			switch name {
			case "register":
				_, err = c.Register(ctx, Registration{})
				want = 3
			case "heartbeat":
				err = c.Heartbeat(ctx, "runner-server")
				want = 3
			case "poll":
				_, err = c.Poll(ctx)
			case "start":
				err = c.Start(ctx, a)
			case "job-heartbeat":
				err = c.JobHeartbeat(ctx, a)
				want = 3
			case "completed":
				err = c.Complete(ctx, a)
			case "failure":
				err = c.Fail(ctx, a, errors.New("scanner failed"))
			}
			if connect.CodeOf(err) != connect.CodeUnavailable || s.count(name) != want {
				t.Fatalf("%s error=%v calls=%d want=%d", name, err, s.count(name), want)
			}
		})
	}
}

func TestTerminalAcknowledgementRejectionsAreErrors(t *testing.T) {
	s := &clientTestServer{
		start: func(context.Context, *pb.JobStartRequest) (*pb.JobStartResponse, error) {
			return &pb.JobStartResponse{Message: ptr("no start")}, nil
		},
		completed: func(context.Context, *pb.JobCompletedRequest) (*pb.JobCompletedResponse, error) {
			return &pb.JobCompletedResponse{Message: ptr("no complete")}, nil
		},
		failure: func(context.Context, *pb.JobFailureRequest) (*pb.JobFailureResponse, error) {
			return &pb.JobFailureResponse{Message: ptr("no failure")}, nil
		},
	}
	c := newTestClient(t, s)
	a := preparedAssignment(t, clientTestJob())
	ctx := context.Background()
	for _, err := range []error{c.Start(ctx, a), c.Complete(ctx, a), c.Fail(ctx, a, errors.New("scan"))} {
		if err == nil || !strings.Contains(err.Error(), "rejected:") {
			t.Fatalf("rejection lost: %v", err)
		}
	}
}
