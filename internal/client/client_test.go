package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"buf.build/gen/go/rediver/api/connectrpc/go/networkscan/networkscanconnect"
	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
)

// clientTestServer exercises the generated HTTP boundary, including authentication.
type clientTestServer struct {
	networkscanconnect.UnimplementedScannerServiceHandler
	t            *testing.T
	mu           sync.Mutex
	events       []string
	job          *pb.Job
	register     func(context.Context, *pb.RegisterRequest) (*pb.RegisterResponse, error)
	poll         func(context.Context) (*pb.Job, error)
	start        func(context.Context, *pb.JobStartRequest) (*pb.JobStartResponse, error)
	onPush       func(http.Header, proto.Message)
	domains      func(context.Context, *pb.PushDomainsRequest) (*pb.PushDomainsResponse, error)
	findings     func(context.Context, *pb.PushFindingsRequest) (*pb.PushFindingsResponse, error)
	push         func(context.Context, *pb.PushServicesRequest) (*pb.PushServicesResponse, error)
	heartbeat    func(context.Context, *pb.HeartbeatRequest) error
	jobHeartbeat func(context.Context, *pb.JobHeartbeatRequest) error
	completed    func(context.Context, *pb.JobCompletedRequest) (*pb.JobCompletedResponse, error)
	failure      func(context.Context, *pb.JobFailureRequest) (*pb.JobFailureResponse, error)
}

func (s *clientTestServer) record(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *clientTestServer) count(event string) int {
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

func (s *clientTestServer) identity(jobID, runID string) {
	s.t.Helper()
	if jobID != "job-original" || runID != "run-original" {
		s.t.Errorf("callback identity = %q/%q", jobID, runID)
	}
}

func (s *clientTestServer) Register(ctx context.Context, req *connect.Request[pb.RegisterRequest]) (*connect.Response[pb.RegisterResponse], error) {
	s.record("register")
	if s.register != nil {
		out, err := s.register(ctx, req.Msg)
		return connect.NewResponse(out), err
	}
	return connect.NewResponse(&pb.RegisterResponse{RunnerId: "runner-server"}), nil
}

func (s *clientTestServer) Heartbeat(ctx context.Context, req *connect.Request[pb.HeartbeatRequest]) (*connect.Response[pb.HeartbeatResponse], error) {
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

func (s *clientTestServer) JobPoll(ctx context.Context, _ *connect.Request[pb.JobPollRequest]) (*connect.Response[pb.JobPollResponse], error) {
	s.record("poll")
	job := s.job
	var err error
	if s.poll != nil {
		job, err = s.poll(ctx)
	}
	return connect.NewResponse(&pb.JobPollResponse{Job: job}), err
}

func (s *clientTestServer) JobStart(ctx context.Context, req *connect.Request[pb.JobStartRequest]) (*connect.Response[pb.JobStartResponse], error) {
	s.record("start")
	if s.start != nil {
		out, err := s.start(ctx, req.Msg)
		return connect.NewResponse(out), err
	}
	s.identity(req.Msg.JobId, req.Msg.RunId)
	return connect.NewResponse(&pb.JobStartResponse{Success: true}), nil
}

func (s *clientTestServer) JobHeartbeat(ctx context.Context, req *connect.Request[pb.JobHeartbeatRequest]) (*connect.Response[pb.JobHeartbeatResponse], error) {
	s.record("job-heartbeat")
	var err error
	if s.jobHeartbeat != nil {
		err = s.jobHeartbeat(ctx, req.Msg)
	} else {
		s.identity(req.Msg.JobId, req.Msg.RunId)
	}
	return connect.NewResponse(&pb.JobHeartbeatResponse{}), err
}

func (s *clientTestServer) PushServices(ctx context.Context, req *connect.Request[pb.PushServicesRequest]) (*connect.Response[pb.PushServicesResponse], error) {
	s.record("push")
	if s.onPush != nil {
		s.onPush(req.Header(), req.Msg)
	}
	s.identity(req.Msg.JobId, req.Msg.RunId)
	if s.push != nil {
		out, err := s.push(ctx, req.Msg)
		return connect.NewResponse(out), err
	}
	return connect.NewResponse(&pb.PushServicesResponse{Success: true}), nil
}

func (s *clientTestServer) JobCompleted(ctx context.Context, req *connect.Request[pb.JobCompletedRequest]) (*connect.Response[pb.JobCompletedResponse], error) {
	s.record("completed")
	if s.completed != nil {
		out, err := s.completed(ctx, req.Msg)
		return connect.NewResponse(out), err
	}
	s.identity(req.Msg.JobId, req.Msg.RunId)
	return connect.NewResponse(&pb.JobCompletedResponse{Success: true}), nil
}

func (s *clientTestServer) JobFailure(ctx context.Context, req *connect.Request[pb.JobFailureRequest]) (*connect.Response[pb.JobFailureResponse], error) {
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

func clientTestJob() *pb.Job {
	return &pb.Job{JobId: "job-original", RunId: "run-original", Scanner: pb.Scanner_SCANNER_SERVICE_DISCOVER,
		Options: &pb.JobOptions{Value: &pb.JobOptions_ServiceDiscover{ServiceDiscover: &pb.ServiceDiscoverOption{Ports: "80,443", Rate: 10}}},
		Targets: []*pb.JobTarget{{AssetScanId: ptr("asset-original"), Host: ptr("example.com")}}}
}

func (s *clientTestServer) PushDomains(ctx context.Context, req *connect.Request[pb.PushDomainsRequest]) (*connect.Response[pb.PushDomainsResponse], error) {
	s.record("push")
	if s.onPush != nil {
		s.onPush(req.Header(), req.Msg)
	}
	if s.domains != nil {
		result, err := s.domains(ctx, req.Msg)
		return connect.NewResponse(result), err
	}
	return connect.NewResponse(&pb.PushDomainsResponse{Success: true}), nil
}
func (s *clientTestServer) PushFindings(ctx context.Context, req *connect.Request[pb.PushFindingsRequest]) (*connect.Response[pb.PushFindingsResponse], error) {
	s.record("push")
	if s.onPush != nil {
		s.onPush(req.Header(), req.Msg)
	}
	if s.findings != nil {
		result, err := s.findings(ctx, req.Msg)
		return connect.NewResponse(result), err
	}
	return connect.NewResponse(&pb.PushFindingsResponse{Success: true}), nil
}
func startClientServer(t *testing.T, handler *clientTestServer) *httptest.Server {
	t.Helper()
	handler.t = t
	_, h := networkscanconnect.NewScannerServiceHandler(handler)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != "network-token" || r.Header.Get("Authorization") != "" {
			t.Errorf("invalid authentication headers: X-Token %q Authorization %q", r.Header.Get("X-Token"), r.Header.Get("Authorization"))
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}
func newTestClient(t *testing.T, handler *clientTestServer) *Client {
	t.Helper()
	server := startClientServer(t, handler)
	return New("network-token", server.URL, server.Client(), time.Second, contract.RetryPolicy{MaxAttempts: 1})
}

func ptr[T any](value T) *T { return &value }

type transportRoundTripFunc func(*http.Request) (*http.Response, error)

func (f transportRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestClientTransportRequestTimeoutCancelsCustomClientRegistration(t *testing.T) {
	canceled := make(chan struct{})
	s := &clientTestServer{register: func(ctx context.Context, _ *pb.RegisterRequest) (*pb.RegisterResponse, error) {
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	requestContext := make(chan context.Context, 1)
	client := &http.Client{Timeout: 0, Transport: transportRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		select {
		case requestContext <- req.Context():
		default:
		}
		return transport.RoundTrip(req)
	})}
	server := startClientServer(t, s)
	agent := New("network-token", server.URL, client, 50*time.Millisecond, contract.RetryPolicy{MaxAttempts: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, err := agent.Register(ctx, Registration{})
	if connect.CodeOf(err) != connect.CodeDeadlineExceeded {
		t.Fatalf("blocking registration: got %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("request timeout did not bound custom client: %v", elapsed)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("server registration context was not canceled")
	}
	if s.count("register") != 1 || s.count("poll") != 0 {
		t.Errorf("deadline lifecycle: register=%d, poll=%d", s.count("register"), s.count("poll"))
	}
	if client.Timeout != 0 {
		t.Errorf("agent mutated custom HTTP client timeout: %v", client.Timeout)
	}
	select {
	case ctx := <-requestContext:
		if ctx.Err() == nil {
			t.Error("custom transport request context remains active after the timeout")
		}
	default:
		t.Error("registration bypassed the supplied HTTP client's transport")
	}
}

func TestClientTransportRegistrationRetriesRespectAttemptLimit(t *testing.T) {
	s := &clientTestServer{register: func(context.Context, *pb.RegisterRequest) (*pb.RegisterResponse, error) {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("try again"))
	}}
	policy := contract.RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond, BackoffMultiplier: 1}
	server := startClientServer(t, s)
	agent := New("network-token", server.URL, server.Client(), time.Second, policy)
	_, err := agent.Register(context.Background(), Registration{})
	if connect.CodeOf(err) != connect.CodeUnavailable || !strings.Contains(err.Error(), "retry failed after 3 attempts") {
		t.Fatalf("registration retries: got %v, want exhausted three-attempt policy", err)
	}
	if s.count("register") != 3 || s.count("poll") != 0 {
		t.Errorf("retry lifecycle: register=%d, poll=%d", s.count("register"), s.count("poll"))
	}
}

func TestClientTransportRegistrationRetryGetsFreshRequestTimeout(t *testing.T) {
	const (
		requestTimeout = 500 * time.Millisecond
		retryBackoff   = 25 * time.Millisecond
	)
	type callerContextKey struct{}
	callerKey := callerContextKey{}

	var calls atomic.Int32
	s := &clientTestServer{register: func(context.Context, *pb.RegisterRequest) (*pb.RegisterResponse, error) {
		if calls.Add(1) == 1 {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("retry registration"))
		}
		return &pb.RegisterResponse{RunnerId: "runner-server"}, nil
	}}
	server := startClientServer(t, s)
	requestContexts := make(chan context.Context, 2)
	transport := server.Client().Transport
	httpClient := &http.Client{Transport: transportRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requestContexts <- req.Context()
		return transport.RoundTrip(req)
	})}
	policy := contract.RetryPolicy{MaxAttempts: 2, InitialBackoff: retryBackoff, MaxBackoff: retryBackoff, BackoffMultiplier: 1}
	agent := New("network-token", server.URL, httpClient, requestTimeout, policy)
	ctx := context.WithValue(context.Background(), callerKey, "registration-caller")
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	runnerID, err := agent.Register(ctx, Registration{})
	if err != nil {
		t.Fatalf("registration retry: %v", err)
	}
	if runnerID != "runner-server" {
		t.Fatalf("registration runner = %q, want runner-server", runnerID)
	}
	if calls.Load() != 2 {
		t.Fatalf("registration calls = %d, want initial attempt and one retry", calls.Load())
	}

	first, second := <-requestContexts, <-requestContexts
	firstDeadline, firstOK := first.Deadline()
	secondDeadline, secondOK := second.Deadline()
	if !firstOK || !secondOK {
		t.Fatalf("registration request deadlines present = %t/%t, want true/true", firstOK, secondOK)
	}
	if extension := secondDeadline.Sub(firstDeadline); extension < retryBackoff/2 {
		t.Errorf("retry deadline extension = %v, want a fresh %v request timeout", extension, requestTimeout)
	}
	if first.Value(callerKey) != "registration-caller" || second.Value(callerKey) != "registration-caller" {
		t.Error("registration attempts did not derive from the caller context")
	}
}

func TestClientTransportRejectsRedirectWithoutForwardingToken(t *testing.T) {
	var redirected, original atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original.Add(1)
		if r.Header.Get("X-Token") != "network-token" {
			t.Error("original registration request was missing its token")
		}
		http.Redirect(w, r, destination.URL+networkscanconnect.ScannerServiceRegisterProcedure, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	agent := New("network-token", source.URL, client, time.Second, contract.RetryPolicy{MaxAttempts: 1})
	if _, err := agent.Register(context.Background(), Registration{}); err == nil {
		t.Fatal("redirected registration unexpectedly succeeded")
	}
	if original.Load() != 1 || redirected.Load() != 0 {
		t.Errorf("redirect requests: original=%d, destination=%d; token must stay at the configured origin", original.Load(), redirected.Load())
	}
}
