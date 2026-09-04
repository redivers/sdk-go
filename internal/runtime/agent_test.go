package runtime

import (
	"github.com/redivers/sdk-go/internal/contract"

	"buf.build/gen/go/rediver/api/connectrpc/go/networkscan/networkscanconnect"
	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

func waitAgentSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scanner")
	}
}

func waitAgentError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("agent failed to terminate")
		return nil
	}
}

func TestAgentCancellationAndStopUseLiveFailureContext(t *testing.T) {
	for _, mode := range []string{"parent cancellation", "Stop RunOnce"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &agentServer{job: agentTestJob(), failure: func(ctx context.Context, req *pb.JobFailureRequest) (*pb.JobFailureResponse, error) {
				if ctx.Err() != nil {
					t.Error("failure callback inherited canceled work context")
				}
				if req.JobId != "job-original" || req.RunId != "run-original" {
					t.Error("failure lost run identity")
				}
				return &pb.JobFailureResponse{Success: true}, nil
			}}
			a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
				if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}}); err != nil {
					return err
				}
				close(started)
				<-ctx.Done()
				return ctx.Err()
			})
			done := make(chan error, 1)
			go func() {
				done <- a.RunOnce(ctx)
			}()
			waitAgentSignal(t, started)
			if err := a.RunOnce(context.Background()); !errors.Is(err, contract.ErrAlreadyRunning) {
				t.Errorf("concurrent run = %v", err)
			}
			if mode == "parent cancellation" {
				cancel()
			} else {
				a.Stop()
				a.Stop()
			}
			if err := waitAgentError(t, done); !errors.Is(err, context.Canceled) {
				t.Errorf("canceled job = %v", err)
			}
			if s.count("failure") != 1 || s.count("completed") != 0 || s.count("push") != 1 {
				t.Errorf("failure/completed/push = %d/%d/%d", s.count("failure"), s.count("completed"), s.count("push"))
			}
		})
	}
}

func TestAgentRunnerHeartbeatFailureStopsPollingAndWork(t *testing.T) {
	started := make(chan struct{})
	s := &agentServer{job: agentTestJob(), heartbeat: func(ctx context.Context, _ *pb.HeartbeatRequest) error {
		select {
		case <-started:
			return connect.NewError(connect.CodeUnauthenticated, errors.New("token revoked"))
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
		if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}}); err != nil {
			return err
		}
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	done := make(chan error, 1)
	go func() { done <- a.Run(context.Background()) }()
	if err := waitAgentError(t, done); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("runner failure = %v", err)
	}
	if s.count("poll") != 1 || s.count("heartbeat") != 1 || s.count("failure") != 1 || s.count("completed") != 0 || s.count("push") != 1 {
		t.Errorf("runner failure events = %v", s.events)
	}
}

// agentServer exercises the generated HTTP boundary, including authentication.
type agentServer struct {
	networkscanconnect.UnimplementedScannerServiceHandler
	t            *testing.T
	mu           sync.Mutex
	events       []string
	job          *pb.Job
	register     func(context.Context, *pb.RegisterRequest) (*pb.RegisterResponse, error)
	poll         func(context.Context) (*pb.Job, error)
	start        func(context.Context, *pb.JobStartRequest) (*pb.JobStartResponse, error)
	push         func(context.Context, *pb.PushServicesRequest) (*pb.PushServicesResponse, error)
	heartbeat    func(context.Context, *pb.HeartbeatRequest) error
	jobHeartbeat func(context.Context, *pb.JobHeartbeatRequest) error
	completed    func(context.Context, *pb.JobCompletedRequest) (*pb.JobCompletedResponse, error)
	failure      func(context.Context, *pb.JobFailureRequest) (*pb.JobFailureResponse, error)
}

func (s *agentServer) record(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *agentServer) count(event string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e == event {
			n++
		}
	}
	return n
}

func (s *agentServer) identity(jobID, runID string) {
	s.t.Helper()
	if jobID != "job-original" || runID != "run-original" {
		s.t.Errorf("callback identity = %q/%q", jobID, runID)
	}
}

func (s *agentServer) Register(ctx context.Context, req *connect.Request[pb.RegisterRequest]) (*connect.Response[pb.RegisterResponse], error) {
	s.record("register")
	if s.register != nil {
		out, err := s.register(ctx, req.Msg)
		return connect.NewResponse(out), err
	}
	return connect.NewResponse(&pb.RegisterResponse{RunnerId: "runner-server"}), nil
}

func (s *agentServer) Heartbeat(ctx context.Context, req *connect.Request[pb.HeartbeatRequest]) (*connect.Response[pb.HeartbeatResponse], error) {
	s.record("heartbeat")
	if req.Msg.RunnerId != "runner-server" {
		s.t.Errorf("heartbeat runner = %q", req.Msg.RunnerId)
	}
	var err error
	if s.heartbeat != nil {
		err = s.heartbeat(ctx, req.Msg)
	}
	return connect.NewResponse(&pb.HeartbeatResponse{}), err
}

func (s *agentServer) JobPoll(ctx context.Context, _ *connect.Request[pb.JobPollRequest]) (*connect.Response[pb.JobPollResponse], error) {
	s.record("poll")
	job := s.job
	var err error
	if s.poll != nil {
		job, err = s.poll(ctx)
	}
	return connect.NewResponse(&pb.JobPollResponse{Job: job}), err
}

func (s *agentServer) JobStart(ctx context.Context, req *connect.Request[pb.JobStartRequest]) (*connect.Response[pb.JobStartResponse], error) {
	s.record("start")
	if s.start != nil {
		out, err := s.start(ctx, req.Msg)
		return connect.NewResponse(out), err
	}
	s.identity(req.Msg.JobId, req.Msg.RunId)
	return connect.NewResponse(&pb.JobStartResponse{Success: true}), nil
}

func (s *agentServer) JobHeartbeat(ctx context.Context, req *connect.Request[pb.JobHeartbeatRequest]) (*connect.Response[pb.JobHeartbeatResponse], error) {
	s.record("job-heartbeat")
	var err error
	if s.jobHeartbeat != nil {
		err = s.jobHeartbeat(ctx, req.Msg)
	} else {
		s.identity(req.Msg.JobId, req.Msg.RunId)
	}
	return connect.NewResponse(&pb.JobHeartbeatResponse{}), err
}

func (s *agentServer) PushServices(ctx context.Context, req *connect.Request[pb.PushServicesRequest]) (*connect.Response[pb.PushServicesResponse], error) {
	s.record("push")
	s.identity(req.Msg.JobId, req.Msg.RunId)
	if s.push != nil {
		out, err := s.push(ctx, req.Msg)
		return connect.NewResponse(out), err
	}
	return connect.NewResponse(&pb.PushServicesResponse{Success: true}), nil
}

func (s *agentServer) JobCompleted(ctx context.Context, req *connect.Request[pb.JobCompletedRequest]) (*connect.Response[pb.JobCompletedResponse], error) {
	s.record("completed")
	if s.completed != nil {
		out, err := s.completed(ctx, req.Msg)
		return connect.NewResponse(out), err
	}
	s.identity(req.Msg.JobId, req.Msg.RunId)
	return connect.NewResponse(&pb.JobCompletedResponse{Success: true}), nil
}

func (s *agentServer) JobFailure(ctx context.Context, req *connect.Request[pb.JobFailureRequest]) (*connect.Response[pb.JobFailureResponse], error) {
	s.record("failure")
	if s.failure != nil {
		out, err := s.failure(ctx, req.Msg)
		return connect.NewResponse(out), err
	}
	s.identity(req.Msg.JobId, req.Msg.RunId)
	if req.Msg.ErrorMessage == "" {
		s.t.Error("failure missing error message")
	}
	return connect.NewResponse(&pb.JobFailureResponse{Success: true}), nil
}

func agentTestJob() *pb.Job {
	return &pb.Job{JobId: "job-original", RunId: "run-original", Scanner: pb.Scanner_SCANNER_SERVICE_DISCOVER,
		Options: &pb.JobOptions{Value: &pb.JobOptions_ServiceDiscover{ServiceDiscover: &pb.ServiceDiscoverOption{Ports: "80,443", Rate: 10}}},
		Targets: []*pb.JobTarget{{AssetScanId: ptr("asset-original"), Host: ptr("example.com")}}}
}

func newAgentTest(t *testing.T, s *agentServer, handler func(context.Context, []contract.Target, contract.Emitter) error, opts ...func(*Config)) *Agent {
	t.Helper()
	s.t = t
	_, h := networkscanconnect.NewScannerServiceHandler(s)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != "network-token" {
			t.Errorf("X-Token = %q", r.Header.Get("X-Token"))
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected Authorization header")
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	cfg := DefaultConfig("test")
	cfg.ServerURL, cfg.HTTPClient, cfg.RetryPolicy = server.URL, server.Client(), contract.NoRetry()
	cfg.HeartbeatInterval, cfg.JobHeartbeatInterval = 10*time.Millisecond, 10*time.Millisecond
	cfg.PollInterval, cfg.RequestTimeout, cfg.ShutdownTimeout = time.Millisecond, time.Second, time.Second
	for _, configure := range opts {
		configure(&cfg)
	}
	agent, err := NewAgent("network-token", contract.ScanFunc(handler), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func transportTestScanner() contract.Scanner {
	return contract.ScanFunc(func(context.Context, []contract.Target, contract.Emitter) error { return nil })
}

type nilTransportScanner struct{}

func (*nilTransportScanner) Scan(context.Context, []contract.Target, contract.Emitter) error {
	return nil
}

func TestAgentTransportTokenEnvironmentAndExplicitPrecedence(t *testing.T) {
	t.Setenv("REDIVER_TOKEN", "environment-token")
	for _, test := range []struct{ name, token, want string }{
		{"environment fallback", "", "environment-token"},
		{"explicit override", "explicit-token", "explicit-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &agentServer{t: t}
			_, handler := networkscanconnect.NewScannerServiceHandler(s)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Values("X-Token"); !slices.Equal(got, []string{test.want}) {
					t.Errorf("X-Token values = %q, want exactly %q", got, test.want)
				}
				if got := r.Header.Values("Authorization"); len(got) != 0 {
					t.Errorf("unexpected Authorization values: %q", got)
				}
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			t.Setenv("REDIVER_URL", server.URL)
			cfg := DefaultConfig("test")
			cfg.HTTPClient, cfg.RetryPolicy = server.Client(), contract.NoRetry()
			agent, err := NewAgent(test.token, transportTestScanner(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.RunOnce(context.Background()); !errors.Is(err, contract.ErrNoJobAvailable) {
				t.Fatalf("RunOnce: %v", err)
			}
			if s.count("register") != 1 || s.count("poll") != 1 {
				t.Errorf("authenticated lifecycle: register=%d, poll=%d", s.count("register"), s.count("poll"))
			}
		})
	}
}

func ptr[T any](value T) *T { return &value }

func TestValidateScannerRejectsNilImplementations(t *testing.T) {
	var scanner *nilTransportScanner
	for _, tc := range []struct {
		name    string
		scanner contract.Scanner
	}{
		{"interface", nil}, {"pointer", scanner}, {"function", contract.ScanFunc(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateScanner(tc.scanner); !errors.Is(err, contract.ErrInvalidConfig) {
				t.Fatalf("invalid implementation accepted: %v", err)
			}
		})
	}
	if err := validateScanner(transportTestScanner()); err != nil {
		t.Fatalf("valid scanner rejected: %v", err)
	}
}
