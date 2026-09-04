package runtime

import (
	"github.com/redivers/sdk-go/internal/client"
	"github.com/redivers/sdk-go/internal/contract"

	"buf.build/gen/go/rediver/api/connectrpc/go/networkscan/networkscanconnect"
	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
	"context"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAgentPreservesFatalUploadCauseArrivingDuringDrain(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	scanReturned, drainHeartbeat := make(chan struct{}), make(chan struct{})
	var heartbeatOnce, releaseOnce sync.Once
	releaseUpload := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseUpload()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server := &agentServer{job: agentTestJob(), push: func(ctx context.Context, _ *pb.PushServicesRequest) (*pb.PushServicesResponse, error) {
		close(started)
		select {
		case <-release:
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("token revoked during drain"))
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, jobHeartbeat: func(context.Context, *pb.JobHeartbeatRequest) error {
		select {
		case <-scanReturned:
			heartbeatOnce.Do(func() { close(drainHeartbeat) })
		default:
		}
		return nil
	}}
	uploadDone := make(chan error, 1)
	scanErr := errors.New("scanner cleanup failed")
	agent := newAgentTest(t, server, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
		go func() {
			uploadDone <- emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}})
		}()
		select {
		case <-started:
		case <-ctx.Done():
			return ctx.Err()
		}
		// An earlier ordinary error must not mask a fatal upload error that
		// arrives while the runtime waits for an active emission to settle.
		defer close(scanReturned)
		return scanErr
	})
	done := make(chan error, 1)
	go func() { done <- agent.RunOnce(ctx) }()
	waitAgentSignal(t, scanReturned)
	waitAgentSignal(t, drainHeartbeat)
	if server.count("completed") != 0 || server.count("failure") != 0 {
		t.Error("terminal callback ran before the active upload settled")
	}
	releaseUpload()
	if err := waitAgentError(t, uploadDone); !client.IsAuthenticationError(err) {
		t.Fatalf("upload lost authentication cause: %v", err)
	}
	if err := waitAgentError(t, done); !client.IsAuthenticationError(err) || !errors.Is(err, scanErr) {
		t.Fatalf("runtime did not preserve both scanner and authentication errors: %v", err)
	}
	if server.count("completed") != 0 || server.count("failure") != 1 {
		t.Fatalf("completed/failure = %d/%d", server.count("completed"), server.count("failure"))
	}
}

func TestAgentRunOnceLifecycleAndCapturedIdentity(t *testing.T) {
	s := &agentServer{job: agentTestJob()}
	s.register = func(_ context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
		if req.GetRunnerId() != "runner-requested" || req.GetHostname() != "scanner-host" || req.GetVersion() != "v-test" || req.GetIpAddress() != "192.0.2.10" {
			t.Errorf("registration metadata = %v", req)
		}
		return &pb.RegisterResponse{RunnerId: "runner-server"}, nil
	}
	s.push = func(_ context.Context, req *pb.PushServicesRequest) (*pb.PushServicesResponse, error) {
		if len(req.Results) != 1 || req.Results[0].Target.GetHost() != "example.com" ||
			len(req.Results[0].Services) != 1 || req.Results[0].Services[0].Host != "example.com" {
			t.Errorf("native target mutation changed upload identity: %v", req.Results)
		}
		return &pb.PushServicesResponse{Success: true}, nil
	}
	a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
		if s.count("start") != 1 {
			t.Error("handler invoked before start acknowledgement")
		}
		if len(targets) != 1 {
			return errors.New("expected one assigned target")
		}
		if targets[0].Host != "example.com" || targets[0].Rate != 10 || !slices.Equal(targets[0].Ports, []int{80, 443}) {
			t.Errorf("native target options = %+v", targets[0])
		}
		targets[0].Host, targets[0].Rate = "mutated.example.com", 999
		targets[0].Ports[0] = 1234
		time.Sleep(35 * time.Millisecond)
		return emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}})
	}, func(cfg *Config) { cfg.RunnerID = "runner-requested" }, func(cfg *Config) { cfg.Hostname = "scanner-host" }, func(cfg *Config) { cfg.Version = "v-test" }, func(cfg *Config) { cfg.IPAddress = "192.0.2.10" })
	if err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.RunnerID() != "runner-server" {
		t.Errorf("RunnerID = %q", a.RunnerID())
	}
	for _, event := range []string{"register", "poll", "start", "push", "completed"} {
		if n := s.count(event); n != 1 {
			t.Errorf("%s count = %d", event, n)
		}
	}
	if s.count("failure") != 0 || s.count("heartbeat") == 0 || s.count("job-heartbeat") == 0 {
		t.Errorf("events = %v", s.events)
	}
	beats := s.count("heartbeat") + s.count("job-heartbeat")
	time.Sleep(25 * time.Millisecond)
	if got := s.count("heartbeat") + s.count("job-heartbeat"); got != beats {
		t.Error("heartbeat continued after RunOnce returned")
	}
	if err := a.RunOnce(context.Background()); !errors.Is(err, contract.ErrAlreadyRunning) {
		t.Errorf("second lifecycle = %v", err)
	}
}

func TestAgentRunOnceNoJobAndPollIsNotRetried(t *testing.T) {
	for _, pollErr := range []error{nil, connect.NewError(connect.CodeUnavailable, errors.New("lost claim response"))} {
		s := &agentServer{poll: func(context.Context) (*pb.Job, error) { return nil, pollErr }}
		a := newAgentTest(t, s, func(context.Context, []contract.Target, contract.Emitter) error {
			t.Error("unexpected handler")
			return nil
		}, func(cfg *Config) {
			cfg.RetryPolicy = contract.RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond, BackoffMultiplier: 1, RetryableStatusCodes: []int{503}}
		})
		err := a.RunOnce(context.Background())
		if pollErr == nil && !errors.Is(err, contract.ErrNoJobAvailable) {
			t.Errorf("no work = %v", err)
		}
		if pollErr != nil && connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("poll error = %v", err)
		}
		if s.count("poll") != 1 || s.count("start") != 0 {
			t.Errorf("poll/start = %d/%d", s.count("poll"), s.count("start"))
		}
	}
}

func TestAgentRejectsStartBeforeHandler(t *testing.T) {
	s := &agentServer{job: agentTestJob(), start: func(context.Context, *pb.JobStartRequest) (*pb.JobStartResponse, error) {
		return &pb.JobStartResponse{Message: ptr("stale claim")}, nil
	}}
	a := newAgentTest(t, s, func(context.Context, []contract.Target, contract.Emitter) error {
		t.Error("rejected job executed")
		return nil
	})
	if err := a.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "stale claim") {
		t.Errorf("start error = %v", err)
	}
	if s.count("completed") != 0 || s.count("push") != 0 {
		t.Errorf("rejected start emitted results")
	}
}

func TestAgentExecutionFailuresAreReported(t *testing.T) {
	for _, tc := range []struct {
		name       string
		handler    func(context.Context, []contract.Target, contract.Emitter) error
		rejectPush bool
		wantError  string
		wantPushes int
	}{
		{name: "scanner error", wantError: "scan failed", handler: func(context.Context, []contract.Target, contract.Emitter) error { return errors.New("scan failed") }},
		{name: "panic", wantError: "scanner panic", handler: func(context.Context, []contract.Target, contract.Emitter) error { panic("scanner panic") }},
		{name: "ignored upload", rejectPush: true, wantError: "rejected", wantPushes: 1, handler: func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
			_ = emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}})
			return nil
		}},
		{name: "error after accepted upload", wantError: "local cleanup failed", wantPushes: 1, handler: func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
			if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}}); err != nil {
				return err
			}
			return errors.New("local cleanup failed")
		}},
		{name: "panic after accepted upload", wantError: "cleanup panic", wantPushes: 1, handler: func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
			if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}}); err != nil {
				return err
			}
			panic("cleanup panic")
		}},
		{name: "ignored validation after accepted upload", wantError: "original target", wantPushes: 1, handler: func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
			if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}}); err != nil {
				return err
			}
			_ = emit.EmitServices(contract.ServiceResult{})
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &agentServer{job: agentTestJob(), failure: func(_ context.Context, req *pb.JobFailureRequest) (*pb.JobFailureResponse, error) {
				if !strings.Contains(req.ErrorMessage, tc.wantError) {
					t.Errorf("reported failure = %q, want %q", req.ErrorMessage, tc.wantError)
				}
				return &pb.JobFailureResponse{Success: true}, nil
			}}
			if tc.rejectPush {
				s.push = func(context.Context, *pb.PushServicesRequest) (*pb.PushServicesResponse, error) {
					return &pb.PushServicesResponse{}, nil
				}
			}
			a := newAgentTest(t, s, tc.handler)
			if err := a.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("execution error = %v, want %q", err, tc.wantError)
			}
			if s.count("poll") != 1 {
				t.Error("RunOnce did not claim exactly one job")
			}
			if s.count("failure") != 1 || s.count("completed") != 0 || s.count("push") != tc.wantPushes {
				t.Errorf("failure/completed/push = %d/%d/%d, want 1/0/%d", s.count("failure"), s.count("completed"), s.count("push"), tc.wantPushes)
			}
		})
	}
}

func TestAgentCompletionRejectedAndNeverRetried(t *testing.T) {
	for _, terminalErr := range []error{nil, connect.NewError(connect.CodeUnavailable, errors.New("lost terminal response"))} {
		s := &agentServer{job: agentTestJob(), completed: func(context.Context, *pb.JobCompletedRequest) (*pb.JobCompletedResponse, error) {
			return &pb.JobCompletedResponse{Message: ptr("terminal rejected")}, terminalErr
		}}
		a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
			return emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}})
		}, func(cfg *Config) { cfg.RetryPolicy = contract.DefaultRetryPolicy() })
		if err := a.RunOnce(context.Background()); err == nil {
			t.Fatal("completion failure lost")
		}
		if s.count("completed") != 1 || s.count("failure") != 0 {
			t.Error("terminal transition retried or replaced")
		}
	}
}

func TestAgentInvalidJobNeverStarts(t *testing.T) {
	for _, mutate := range []func(*pb.Job){func(j *pb.Job) { j.RunId = "" }, func(j *pb.Job) { j.Scanner = pb.Scanner_SCANNER_SUBDOMAIN }, func(j *pb.Job) { j.Targets = nil }, func(j *pb.Job) {
		j.Options = &pb.JobOptions{Value: &pb.JobOptions_Subdomain{Subdomain: &pb.SubdomainOption{}}}
	}} {
		job := agentTestJob()
		mutate(job)
		s := &agentServer{job: job}
		a := newAgentTest(t, s, func(context.Context, []contract.Target, contract.Emitter) error {
			t.Error("invalid job executed")
			return nil
		})
		if err := a.RunOnce(context.Background()); !errors.Is(err, contract.ErrInvalidJob) {
			t.Errorf("invalid job = %v", err)
		}
		if s.count("start") != 0 {
			t.Error("invalid job started")
		}
	}
}

func TestAgentServiceTargetPreparationFailsAfterStart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*pb.Job)
	}{
		{"missing options", func(job *pb.Job) { job.Options = nil }},
		{"invalid ports", func(job *pb.Job) { job.Options.GetServiceDiscover().Ports = "80-" }},
		{"invalid rate", func(job *pb.Job) { job.Options.GetServiceDiscover().Rate = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := agentTestJob()
			tc.mutate(job)
			server := &agentServer{job: job}
			agent := newAgentTest(t, server, func(context.Context, []contract.Target, contract.Emitter) error {
				t.Error("invalid service input reached the scanner")
				return nil
			})
			if err := agent.RunOnce(context.Background()); err == nil {
				t.Fatal("invalid service options were accepted")
			}
			if server.count("start") != 1 || server.count("failure") != 1 || server.count("completed") != 0 || server.count("push") != 0 {
				t.Fatalf("start/failure/completed/push = %d/%d/%d/%d; want 1/1/0/0", server.count("start"), server.count("failure"), server.count("completed"), server.count("push"))
			}
		})
	}
}

func TestAgentSuccessfulEmptyScanCompletesWithoutPushes(t *testing.T) {
	job := agentTestJob()
	job.Targets = append(job.Targets, &pb.JobTarget{AssetScanId: ptr("asset-second"), Host: ptr("second.example.com")})
	s := &agentServer{job: job}
	a := newAgentTest(t, s, func(context.Context, []contract.Target, contract.Emitter) error { return nil })
	if err := a.RunOnce(context.Background()); err != nil {
		t.Fatalf("successful empty scan: %v", err)
	}
	if s.count("push") != 0 || s.count("completed") != 1 || s.count("failure") != 0 {
		t.Errorf("push/completed/failure = %d/%d/%d", s.count("push"), s.count("completed"), s.count("failure"))
	}
}

func TestAgentRepeatedUploadsDoNotCompleteBeforeScanReturns(t *testing.T) {
	accepted, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s := &agentServer{job: agentTestJob()}
	a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
		for _, port := range []int{80, 443} {
			if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: port}}}); err != nil {
				return err
			}
		}
		close(accepted)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	done := make(chan error, 1)
	go func() { done <- a.RunOnce(ctx) }()
	waitAgentSignal(t, accepted)
	if s.count("push") != 2 || s.count("completed") != 0 || s.count("failure") != 0 {
		t.Errorf("while scanning, push/completed/failure = %d/%d/%d", s.count("push"), s.count("completed"), s.count("failure"))
	}
	close(release)
	if err := waitAgentError(t, done); err != nil {
		t.Fatal(err)
	}
	if s.count("completed") != 1 || s.count("failure") != 0 {
		t.Errorf("completed/failure = %d/%d", s.count("completed"), s.count("failure"))
	}
}

func TestAgentDrainsActiveUploadBeforeTerminalCallback(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "acknowledged"
		if reject {
			name = "rejected"
		}
		t.Run(name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			scanReturned, drainHeartbeat := make(chan struct{}), make(chan struct{})
			var releaseOnce, heartbeatOnce sync.Once
			releaseUpload := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseUpload()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			s := &agentServer{job: agentTestJob(), push: func(ctx context.Context, _ *pb.PushServicesRequest) (*pb.PushServicesResponse, error) {
				close(started)
				select {
				case <-release:
					return &pb.PushServicesResponse{Success: !reject}, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}, jobHeartbeat: func(context.Context, *pb.JobHeartbeatRequest) error {
				select {
				case <-scanReturned:
					heartbeatOnce.Do(func() { close(drainHeartbeat) })
				default:
				}
				return nil
			}}
			pushDone := make(chan error, 1)
			a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
				// Deliberately return with an upload active to verify the runtime
				// drains an uncooperative scanner before reporting its outcome.
				go func() {
					pushDone <- emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}})
				}()
				select {
				case <-started:
					close(scanReturned)
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			done := make(chan error, 1)
			go func() { done <- a.RunOnce(ctx) }()
			waitAgentSignal(t, scanReturned)
			waitAgentSignal(t, drainHeartbeat)
			if s.count("completed") != 0 || s.count("failure") != 0 {
				t.Error("terminal callback ran before upload acknowledgement")
			}
			releaseUpload()
			pushErr, runErr := waitAgentError(t, pushDone), waitAgentError(t, done)
			if reject {
				if pushErr == nil || runErr == nil || !strings.Contains(runErr.Error(), "rejected") {
					t.Errorf("ignored drain error: push=%v, run=%v", pushErr, runErr)
				}
				if s.count("failure") != 1 || s.count("completed") != 0 {
					t.Error("rejected upload did not fail the job")
				}
			} else {
				if pushErr != nil || runErr != nil {
					t.Errorf("acknowledged upload: push=%v, run=%v", pushErr, runErr)
				}
				if s.count("completed") != 1 || s.count("failure") != 0 {
					t.Error("successful drain did not complete the job")
				}
			}
		})
	}
}

func TestAgentStartFailureReleasesClaim(t *testing.T) {
	for _, tc := range []struct {
		name        string
		startErr    error
		wantFailure int
	}{
		{name: "rejected acknowledgement", wantFailure: 1},
		{name: "lost start response", startErr: connect.NewError(connect.CodeUnavailable, errors.New("connection lost")), wantFailure: 1},
		{name: "stale claim", startErr: connect.NewError(connect.CodeFailedPrecondition, errors.New("stale run")), wantFailure: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &agentServer{job: agentTestJob(), start: func(context.Context, *pb.JobStartRequest) (*pb.JobStartResponse, error) {
				return &pb.JobStartResponse{Message: ptr("start rejected")}, tc.startErr
			}}
			a := newAgentTest(t, s, func(context.Context, []contract.Target, contract.Emitter) error {
				t.Error("rejected start ran handler")
				return nil
			})
			if err := a.RunOnce(context.Background()); err == nil {
				t.Fatal("lost start error")
			}
			if s.count("failure") != tc.wantFailure || s.count("start") != 1 {
				t.Errorf("failure/start = %d/%d", s.count("failure"), s.count("start"))
			}
		})
	}
}

func TestAgentStaleUploadCancelsIgnoringHandler(t *testing.T) {
	s := &agentServer{job: agentTestJob(), push: func(context.Context, *pb.PushServicesRequest) (*pb.PushServicesResponse, error) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("stale upload run"))
	}}
	a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
		_ = emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}})
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.RunOnce(ctx) }()
	err := waitAgentError(t, done)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("lost stale upload error: %v", err)
	}
	if s.count("push") != 1 || s.count("completed") != 0 {
		t.Error("stale upload retried or completed")
	}
}

func TestAgentStaleHeartbeatCancelsWorkWithoutRetry(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeFailedPrecondition, connect.CodeNotFound, connect.CodeUnauthenticated, connect.CodePermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			accepted := make(chan struct{})
			s := &agentServer{job: agentTestJob(), jobHeartbeat: func(ctx context.Context, _ *pb.JobHeartbeatRequest) error {
				select {
				case <-accepted:
				case <-ctx.Done():
					return ctx.Err()
				}
				return connect.NewError(code, errors.New("lease lost"))
			}}
			a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
				if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}}); err != nil {
					return err
				}
				close(accepted)
				<-ctx.Done()
				return ctx.Err()
			}, func(cfg *Config) { cfg.RetryPolicy = contract.AggressiveRetryPolicy() })
			done := make(chan error, 1)
			go func() { done <- a.RunOnce(context.Background()) }()
			err := waitAgentError(t, done)
			if connect.CodeOf(err) != code {
				t.Errorf("heartbeat error = %v", err)
			}
			if s.count("job-heartbeat") != 1 || s.count("completed") != 0 || s.count("failure") != 1 || s.count("push") != 1 {
				t.Errorf("stale heartbeat continued: %v", s.events)
			}
		})
	}
}

func TestScannerAcknowledgesConcurrentFindingsBeforeWholeBatchReturns(t *testing.T) {
	job := scannerAPIJob(pb.Scanner_SCANNER_VULNERABILITY)
	// Identical hosts must remain distinct assignments, including empty targets.
	job.Targets = append(job.Targets,
		&pb.JobTarget{AssetScanId: ptr("second"), Host: ptr("example.com"), Port: ptr(int32(8443)), Url: ptr("")},
		&pb.JobTarget{AssetScanId: ptr("empty"), Host: ptr("example.com"), Port: ptr(int32(9443))},
	)
	server := &scannerAPIServer{job: job}
	acknowledged, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		if len(targets) != 3 {
			return errors.New("bulk engine needs every job target")
		}
		errs := make(chan error, 8)
		var workers sync.WaitGroup
		for i := range 8 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				errs <- emit.EmitFindings(contract.FindingResult{Target: targets[i%2], Findings: []contract.Finding{
					{Name: fmt.Sprintf("finding-%d", i), Severity: contract.SeverityHigh},
				}})
			}()
		}
		workers.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				return err
			}
		}
		close(acknowledged)
		<-release
		return nil
	})
	agent := newScannerAPIAgent(t, server, scanner)
	done := make(chan error, 1)
	go func() { done <- runScannerAPIOnce(t, agent) }()
	select {
	case <-acknowledged:
	case <-time.After(3 * time.Second):
		t.Fatal("scanner did not receive acknowledgements")
	}
	server.mu.Lock()
	pushes := len(server.findings)
	server.mu.Unlock()
	if pushes != 8 || server.completed.Load() != 0 {
		t.Fatalf("before Scan returned: pushes=%d completed=%d; want 8/0", pushes, server.completed.Load())
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("job did not finish after scanner returned")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.findings) != 8 || server.completed.Load() != 1 {
		t.Fatalf("pushes/completions = %d/%d", len(server.findings), server.completed.Load())
	}
	seen := map[string]bool{}
	counts := map[string]int{}
	for _, req := range server.findings {
		if len(req.Results) != 1 {
			t.Fatalf("unexpected result count: %v", req)
		}
		result := req.Results[0]
		original := job.Targets[0]
		if result.Target.GetAssetScanId() == "second" {
			original = job.Targets[1]
		}
		assertScannerAPIIdentity(t, req.JobId, req.RunId, result.Target, original)
		if len(result.Findings) != 1 {
			t.Errorf("one Emit call sent %d findings; want 1", len(result.Findings))
		}
		counts[result.Target.GetAssetScanId()] += len(result.Findings)
		for _, finding := range result.Findings {
			if seen[finding.Name] {
				t.Errorf("duplicate finding %q", finding.Name)
			}
			seen[finding.Name] = true
		}
	}
	if len(seen) != 8 {
		t.Errorf("lost concurrent observations: %v", seen)
	}
	if counts["asset-original"] != 4 || counts["second"] != 4 || counts["empty"] != 0 {
		t.Errorf("assignment counts = %v", counts)
	}
}

func TestScannerCompletesEveryUnobservedBatchTarget(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			job := scannerAPIJob(kind)
			second := scannerAPIJob(kind).Targets[0]
			second.AssetScanId = ptr("second-empty")
			job.Targets = append(job.Targets, second)
			server := &scannerAPIServer{job: job}
			scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
				if len(targets) != 2 {
					return errors.New("incomplete input batch")
				}
				// Empty outer result sets and empty inner observations are no-ops.
				switch kind {
				case pb.Scanner_SCANNER_SUBDOMAIN:
					return errors.Join(
						emit.EmitDomains(), emit.EmitDomains([]contract.DNSResult(nil)...), emit.EmitDomains([]contract.DNSResult{}...),
						emit.EmitDomains(contract.DNSResult{Target: targets[0]}, contract.DNSResult{Target: targets[1], Records: []contract.DNSRecord{}}),
					)
				case pb.Scanner_SCANNER_SERVICE_DISCOVER:
					return errors.Join(
						emit.EmitServices(), emit.EmitServices([]contract.ServiceResult(nil)...), emit.EmitServices([]contract.ServiceResult{}...),
						emit.EmitServices(contract.ServiceResult{Target: targets[0]}, contract.ServiceResult{Target: targets[1], Services: []contract.Service{}}),
					)
				default:
					return errors.Join(
						emit.EmitFindings(), emit.EmitFindings([]contract.FindingResult(nil)...), emit.EmitFindings([]contract.FindingResult{}...),
						emit.EmitFindings(contract.FindingResult{Target: targets[0]}, contract.FindingResult{Target: targets[1], Findings: []contract.Finding{}}),
					)
				}
			})
			if err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner)); err != nil {
				t.Fatal(err)
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if len(server.domains)+len(server.services)+len(server.findings) != 0 || server.completed.Load() != 1 {
				t.Fatal("empty scan must complete its job without any Push request")
			}
		})
	}
}

func TestScannerCancellationRetainsAcknowledgedResultsAndRejectsLateEmissions(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	returned := make(chan error, 1)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	server := &scannerAPIServer{job: scannerAPIServiceBatch()}
	var calls atomic.Int32
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		calls.Add(1)
		if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 80}}}); err != nil {
			returned <- err
			return err
		}
		close(entered)
		// Deliberately noncooperative engine: late emits cannot finalize
		// canceled assignments, even after the Agent has already returned.
		<-release
		err := emit.EmitServices(contract.ServiceResult{Target: targets[1], Services: []contract.Service{{Port: 443}}})
		returned <- err
		return nil
	})
	agent := newScannerAPIAgent(t, server, scanner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- agent.RunOnce(ctx) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("scanner was not called")
	}
	server.mu.Lock()
	pushes := len(server.services)
	server.mu.Unlock()
	if pushes != 1 || server.completed.Load() != 0 {
		t.Fatalf("first emission was not uploaded before cancellation: pushes=%d complete=%d", pushes, server.completed.Load())
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SDK waited indefinitely for canceled scan logic")
	}
	unblock()
	select {
	case err := <-returned:
		if err == nil {
			t.Error("late emit succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("scanner did not return after release")
	}
	if calls.Load() != 1 || server.completed.Load() != 0 || server.failed.Load() != 1 {
		t.Errorf("canceled lifecycle: scans=%d complete=%d failure=%d", calls.Load(), server.completed.Load(), server.failed.Load())
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.services) != 1 || len(server.services[0].Results) != 1 || len(server.services[0].Results[0].Services) != 1 {
		t.Fatalf("canceled scan changed acknowledged results: %v", server.services)
	}
	req := server.services[0]
	assertScannerAPIIdentity(t, req.JobId, req.RunId, req.Results[0].Target, server.job.Targets[0])
	if req.Results[0].Services[0].Port != 80 {
		t.Errorf("acknowledged service changed: %v", req.Results[0].Services)
	}
}

func TestScannerCancellationInterruptsInFlightEmission(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var attempts atomic.Int32
	server := &scannerAPIServer{
		job: scannerAPIJob(pb.Scanner_SCANNER_SERVICE_DISCOVER),
		serviceError: func(*pb.PushServicesRequest) error {
			if attempts.Add(1) == 2 {
				close(entered)
				<-release
			}
			return nil
		},
	}
	emitted := make(chan error, 1)
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 80}}}); err != nil {
			return err
		}
		err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}})
		emitted <- err
		return err
	})
	agent := newScannerAPIAgent(t, server, scanner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- agent.RunOnce(ctx) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("second emission did not reach the backend")
	}
	select {
	case err := <-emitted:
		t.Fatalf("EmitServices returned before the backend acknowledged: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-emitted:
		if err == nil {
			t.Error("in-flight emission succeeded after cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not interrupt the in-flight emission")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancellation error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SDK waited indefinitely for an unacknowledged emission")
	}
	if attempts.Load() != 2 || server.completed.Load() != 0 || server.failed.Load() != 1 {
		t.Errorf("canceled upload lifecycle: attempts=%d complete=%d failure=%d", attempts.Load(), server.completed.Load(), server.failed.Load())
	}
}

func TestScannerRejectsEmissionsAfterSuccessfulReturn(t *testing.T) {
	var retainedEmit contract.Emitter
	var retainedTarget contract.Target
	server := &scannerAPIServer{job: scannerAPIJob(pb.Scanner_SCANNER_SERVICE_DISCOVER)}
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		retainedEmit, retainedTarget = emit, targets[0]
		return nil
	})
	if err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner)); err != nil {
		t.Fatal(err)
	}
	if err := retainedEmit.EmitServices(contract.ServiceResult{Target: retainedTarget, Services: []contract.Service{{Port: 443}}}); err == nil {
		t.Fatal("emitter remained open after Scan completed")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.services) != 0 || server.completed.Load() != 1 || server.failed.Load() != 0 {
		t.Error("late emission changed the already completed job")
	}
}

func scannerAPIServiceBatch() *pb.Job {
	job := scannerAPIJob(pb.Scanner_SCANNER_SERVICE_DISCOVER)
	job.Targets = []*pb.JobTarget{
		{AssetScanId: ptr("first-asset"), Host: ptr("first.example.com"), Url: ptr("")},
		{AssetScanId: ptr("second-asset"), Host: ptr("second.example.com"), Domain: ptr("")},
		{AssetScanId: ptr("empty-asset"), Host: ptr("empty.example.com"), Port: ptr(int32(443))},
	}
	return job
}

func TestScannerReceivesWholeBatchOnceAndPreservesAssignment(t *testing.T) {
	job := scannerAPIServiceBatch()
	original := proto.Clone(job).(*pb.Job)
	server := &scannerAPIServer{job: job}
	var calls atomic.Int32
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		calls.Add(1)
		if len(targets) != 3 {
			return errors.New("SDK did not supply the complete target batch")
		}
		for i, target := range targets {
			if target.Host != original.Targets[i].GetHost() || target.Rate != 25 || !reflect.DeepEqual(target.Ports, []int{80, 81, 82, 443}) {
				t.Errorf("target %d input = %+v", i, target)
			}
		}
		targets[0].Ports[0] = 65535
		if targets[1].Ports[0] != 80 {
			t.Error("one target's ports mutation leaked into its sibling")
		}
		// Public scan fields are editable values; attribution uses the original
		// private reference, including optional presence and assigned host.
		first := targets[0]
		first.Host, first.URL, first.Port = "unrelated.example.net", "https://changed.invalid", 444
		if err := emit.EmitServices(contract.ServiceResult{Target: first, Services: []contract.Service{{Port: 80}}}); err != nil {
			return err
		}
		return emit.EmitServices(contract.ServiceResult{Target: targets[1], Services: []contract.Service{{Port: 443}}})
	})
	agent := newScannerAPIAgent(t, server, scanner)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := agent.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || server.completed.Load() != 1 || server.failed.Load() != 0 {
		t.Fatalf("scan/complete/fail = %d/%d/%d", calls.Load(), server.completed.Load(), server.failed.Load())
	}
	if !proto.Equal(job, original) {
		t.Errorf("RunOnce mutated backend fixture's job: %v", job)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.services) != 2 {
		t.Fatalf("pushes = %v; want one push per nonempty Emit call", server.services)
	}
	for i, req := range server.services {
		if len(req.Results) != 1 {
			t.Fatalf("push %d results = %v", i, req.Results)
		}
		result := req.Results[0]
		assertScannerAPIIdentity(t, req.JobId, req.RunId, result.Target, original.Targets[i])
		if len(result.Services) != 1 || result.Services[0].Host != original.Targets[i].GetHost() {
			t.Errorf("service attribution changed: %v", result.Services)
		}
	}
}

func TestScannerBatchErrorPreservesAcknowledgedResults(t *testing.T) {
	server := &scannerAPIServer{job: scannerAPIServiceBatch()}
	failure := errors.New("bulk engine did not finish")
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		for _, target := range targets {
			if err := emit.EmitServices(contract.ServiceResult{Target: target, Services: []contract.Service{{Port: 443}}}); err != nil {
				return err
			}
		}
		return failure
	})
	err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner))
	if !errors.Is(err, failure) || server.completed.Load() != 0 || server.failed.Load() != 1 {
		t.Fatalf("scan error lifecycle: err=%v complete=%d failure=%d", err, server.completed.Load(), server.failed.Load())
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.services) != 3 {
		t.Errorf("failed batch lost acknowledged observations: %v", server.services)
	}
	if len(server.failures) != 1 || server.failures[0].JobId != server.job.JobId || server.failures[0].RunId != server.job.RunId || !strings.Contains(server.failures[0].ErrorMessage, failure.Error()) {
		t.Errorf("failure callback = %v", server.failures)
	}
}

func TestScannerUploadErrorIsImmediateAndSticky(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeUnauthenticated} {
		t.Run(code.String(), func(t *testing.T) {
			var calls, attempts atomic.Int32
			var emissionErr, stickyErr error
			scanReturned := make(chan struct{})
			server := &scannerAPIServer{job: scannerAPIServiceBatch(), serviceError: func(*pb.PushServicesRequest) error {
				if attempts.Add(1) == 1 {
					return connect.NewError(code, errors.New("first target upload failed"))
				}
				return nil
			}}
			scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
				defer close(scanReturned)
				calls.Add(1)
				emissionErr = emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}})
				stickyErr = emit.EmitServices(contract.ServiceResult{Target: targets[1], Services: []contract.Service{{Port: 80}}})
				return nil
			})
			err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner))
			// Stale-run errors cancel execution immediately, so wait for the
			// cooperative scanner before examining its recorded emission errors.
			select {
			case <-scanReturned:
			case <-time.After(time.Second):
				t.Fatal("scanner did not return after its failed emission")
			}
			var rpcErr *connect.Error
			if !errors.As(emissionErr, &rpcErr) || connect.CodeOf(err) != code || !errors.Is(stickyErr, emissionErr) || !errors.Is(err, rpcErr) {
				t.Fatalf("upload errors emit/sticky/run = %v/%v/%v; want %v", emissionErr, stickyErr, err, code)
			}
			if calls.Load() != 1 || attempts.Load() != 1 || server.completed.Load() != 0 {
				t.Errorf("scan/upload/complete = %d/%d/%d; want 1/1/0", calls.Load(), attempts.Load(), server.completed.Load())
			}
		})
	}
}

func TestScannerPanicPreservesAcknowledgedResults(t *testing.T) {
	server := &scannerAPIServer{job: scannerAPIJob(pb.Scanner_SCANNER_SERVICE_DISCOVER)}
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		if err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Services: []contract.Service{{Port: 443}}}); err != nil {
			return err
		}
		panic("scanner exploded")
	})
	err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner))
	if err == nil || !strings.Contains(err.Error(), "scanner exploded") || server.failed.Load() != 1 || server.completed.Load() != 0 {
		t.Fatalf("panic lifecycle: err=%v failure=%d completion=%d", err, server.failed.Load(), server.completed.Load())
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.services) != 1 {
		t.Errorf("panicking scan lost acknowledged results: %v", server.services)
	}
}

func TestScannerRunsAllKindsThroughSameInterfaceAndFunction(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		for _, adapter := range []string{"interface", "function"} {
			t.Run(kind.String()+"/"+adapter, func(t *testing.T) {
				server := &scannerAPIServer{job: scannerAPIJob(kind)}
				var calls atomic.Int32
				scanner := scannerAPIHandler(t, kind, adapter, &calls, false)
				if err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner)); err != nil {
					t.Fatal(err)
				}
				if calls.Load() != 1 || server.started.Load() != 1 || server.completed.Load() != 1 || server.failed.Load() != 0 {
					t.Fatalf("scan/start/complete/fail = %d/%d/%d/%d", calls.Load(), server.started.Load(), server.completed.Load(), server.failed.Load())
				}
				assertScannerAPIPayload(t, server, false)
			})
		}
	}
}

func TestScannerCompletesEmptyResults(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			server := &scannerAPIServer{job: scannerAPIJob(kind)}
			var calls atomic.Int32
			scanner := scannerAPIHandler(t, kind, "function", &calls, true)
			if err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner)); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 || server.completed.Load() != 1 || server.failed.Load() != 0 {
				t.Fatal("a successful empty scan did not complete its target and job")
			}
			assertScannerAPIPayload(t, server, true)
		})
	}
}

func scannerAPIHandler(t *testing.T, kind pb.Scanner, adapter string, calls *atomic.Int32, empty bool) contract.Scanner {
	t.Helper()
	fn := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		calls.Add(1)
		if len(targets) != 1 {
			t.Errorf("input targets = %+v", targets)
			return errors.New("unexpected target count")
		}
		target := targets[0]
		switch kind {
		case pb.Scanner_SCANNER_SUBDOMAIN:
			if target.Domain != "example.com" {
				t.Errorf("domain input = %+v", target)
			}
			if !empty {
				// A descendant-only chunk must not invent parent metadata.
				return emit.EmitDomains(contract.DNSResult{Target: target, Records: []contract.DNSRecord{
					{Domain: "www.example.com", IPs: []string{"192.0.2.3"}},
				}})
			}
		case pb.Scanner_SCANNER_SERVICE_DISCOVER:
			if target.Host != "example.com" || target.Rate != 25 || !reflect.DeepEqual(target.Ports, []int{80, 81, 82, 443}) {
				t.Errorf("service input = %+v", target)
			}
			if !empty {
				return emit.EmitServices(contract.ServiceResult{Target: target, Services: []contract.Service{{Port: 443}}})
			}
		case pb.Scanner_SCANNER_VULNERABILITY:
			if target.Host != "example.com" || target.Port != 443 || target.URL != "https://example.com/login" {
				t.Errorf("vulnerability input = %+v", target)
			}
			if !empty {
				return emit.EmitFindings(contract.FindingResult{Target: target, Findings: []contract.Finding{
					{Name: "Observed vulnerability", Severity: contract.SeverityHigh},
				}})
			}
		}
		return nil
	})
	if adapter == "interface" {
		return &customScanner{scan: fn}
	}
	return fn
}

func assertScannerAPIPayload(t *testing.T, s *scannerAPIServer, empty bool) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if empty {
		if len(s.domains)+len(s.services)+len(s.findings) != 0 {
			t.Fatal("empty scan sent an observation Push request")
		}
		return
	}
	switch s.job.Scanner {
	case pb.Scanner_SCANNER_SUBDOMAIN:
		if len(s.domains) != 1 || len(s.domains[0].Results) != 1 {
			t.Fatalf("expected one DNS target push, got %v", s.domains)
		}
		req, result := s.domains[0], s.domains[0].Results[0]
		assertScannerAPIIdentity(t, req.JobId, req.RunId, result.Target, s.job.Targets[0])
		if len(result.Domains) != 1 {
			t.Fatalf("DNS results = %v", result.Domains)
		}
		record := result.Domains[0]
		if record.Domain != "www.example.com" || !reflect.DeepEqual(record.Ips, []string{"192.0.2.3"}) {
			t.Errorf("DNS observation changed or SDK invented a parent record: %v", record)
		}
	case pb.Scanner_SCANNER_SERVICE_DISCOVER:
		if len(s.services) != 1 || len(s.services[0].Results) != 1 {
			t.Fatalf("expected one service target push, got %v", s.services)
		}
		req, result := s.services[0], s.services[0].Results[0]
		assertScannerAPIIdentity(t, req.JobId, req.RunId, result.Target, s.job.Targets[0])
		if len(result.Services) != 1 || result.Services[0].Host != "example.com" || result.Services[0].Port != 443 {
			t.Errorf("service mapping/host attribution = %v", result.Services)
		}
	case pb.Scanner_SCANNER_VULNERABILITY:
		if len(s.findings) != 1 || len(s.findings[0].Results) != 1 {
			t.Fatalf("expected one finding target push, got %v", s.findings)
		}
		req, result := s.findings[0], s.findings[0].Results[0]
		assertScannerAPIIdentity(t, req.JobId, req.RunId, result.Target, s.job.Targets[0])
		if len(result.Findings) != 1 || result.Findings[0].Name != "Observed vulnerability" || result.Findings[0].Severity != pb.FindingSeverity_FINDING_SEVERITY_HIGH {
			t.Errorf("finding mapping = %v", result.Findings)
		}
	}
}

// The fixture uses the published Connect handler, so tests exercise wire mapping.
type scannerAPIServer struct {
	networkscanconnect.UnimplementedScannerServiceHandler
	job          *pb.Job
	started      atomic.Int32
	completed    atomic.Int32
	failed       atomic.Int32
	mu           sync.Mutex
	domains      []*pb.PushDomainsRequest
	services     []*pb.PushServicesRequest
	findings     []*pb.PushFindingsRequest
	failures     []*pb.JobFailureRequest
	serviceError func(*pb.PushServicesRequest) error
}

func (s *scannerAPIServer) Register(context.Context, *connect.Request[pb.RegisterRequest]) (*connect.Response[pb.RegisterResponse], error) {
	return connect.NewResponse(&pb.RegisterResponse{RunnerId: "runner"}), nil
}

func (s *scannerAPIServer) Heartbeat(context.Context, *connect.Request[pb.HeartbeatRequest]) (*connect.Response[pb.HeartbeatResponse], error) {
	return connect.NewResponse(&pb.HeartbeatResponse{}), nil
}

func (s *scannerAPIServer) JobPoll(context.Context, *connect.Request[pb.JobPollRequest]) (*connect.Response[pb.JobPollResponse], error) {
	return connect.NewResponse(&pb.JobPollResponse{Job: proto.Clone(s.job).(*pb.Job)}), nil
}

func (s *scannerAPIServer) JobStart(context.Context, *connect.Request[pb.JobStartRequest]) (*connect.Response[pb.JobStartResponse], error) {
	s.started.Add(1)
	return connect.NewResponse(&pb.JobStartResponse{Success: true}), nil
}

func (s *scannerAPIServer) JobHeartbeat(context.Context, *connect.Request[pb.JobHeartbeatRequest]) (*connect.Response[pb.JobHeartbeatResponse], error) {
	return connect.NewResponse(&pb.JobHeartbeatResponse{}), nil
}

func (s *scannerAPIServer) JobCompleted(context.Context, *connect.Request[pb.JobCompletedRequest]) (*connect.Response[pb.JobCompletedResponse], error) {
	s.completed.Add(1)
	return connect.NewResponse(&pb.JobCompletedResponse{Success: true}), nil
}

func (s *scannerAPIServer) JobFailure(_ context.Context, req *connect.Request[pb.JobFailureRequest]) (*connect.Response[pb.JobFailureResponse], error) {
	s.failed.Add(1)
	s.mu.Lock()
	s.failures = append(s.failures, proto.Clone(req.Msg).(*pb.JobFailureRequest))
	s.mu.Unlock()
	return connect.NewResponse(&pb.JobFailureResponse{Success: true}), nil
}

func (s *scannerAPIServer) PushDomains(_ context.Context, req *connect.Request[pb.PushDomainsRequest]) (*connect.Response[pb.PushDomainsResponse], error) {
	s.mu.Lock()
	s.domains = append(s.domains, proto.Clone(req.Msg).(*pb.PushDomainsRequest))
	s.mu.Unlock()
	return connect.NewResponse(&pb.PushDomainsResponse{Success: true}), nil
}

func (s *scannerAPIServer) PushServices(_ context.Context, req *connect.Request[pb.PushServicesRequest]) (*connect.Response[pb.PushServicesResponse], error) {
	s.mu.Lock()
	s.services = append(s.services, proto.Clone(req.Msg).(*pb.PushServicesRequest))
	s.mu.Unlock()
	var err error
	if s.serviceError != nil {
		err = s.serviceError(req.Msg)
	}
	return connect.NewResponse(&pb.PushServicesResponse{Success: true}), err
}

func (s *scannerAPIServer) PushFindings(_ context.Context, req *connect.Request[pb.PushFindingsRequest]) (*connect.Response[pb.PushFindingsResponse], error) {
	s.mu.Lock()
	s.findings = append(s.findings, proto.Clone(req.Msg).(*pb.PushFindingsRequest))
	s.mu.Unlock()
	return connect.NewResponse(&pb.PushFindingsResponse{Success: true}), nil
}

func newScannerAPIAgent(t *testing.T, server *scannerAPIServer, scanner contract.Scanner, opts ...func(*Config)) *Agent {
	t.Helper()
	_, handler := networkscanconnect.NewScannerServiceHandler(server)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != "token" || r.Header.Get("Authorization") != "" {
			t.Errorf("incorrect networkscan authentication headers")
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(httpServer.Close)
	cfg := DefaultConfig("test")
	cfg.ServerURL, cfg.HTTPClient, cfg.RetryPolicy = httpServer.URL, httpServer.Client(), contract.NoRetry()
	cfg.RequestTimeout, cfg.ShutdownTimeout = time.Second, time.Second
	cfg.HeartbeatInterval, cfg.JobHeartbeatInterval = time.Hour, time.Hour
	for _, configure := range opts {
		configure(&cfg)
	}
	agent, err := NewAgent("token", scanner, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func runScannerAPIOnce(t *testing.T, agent *Agent) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return agent.RunOnce(ctx)
}

func scannerAPIJob(kind pb.Scanner) *pb.Job {
	target := &pb.JobTarget{AssetScanId: ptr("asset-original"), Url: ptr("")}
	job := &pb.Job{JobId: "job-original", RunId: "run-original", Scanner: kind, Targets: []*pb.JobTarget{target}}
	switch kind {
	case pb.Scanner_SCANNER_SUBDOMAIN:
		target.Domain, target.Host = ptr("example.com"), ptr("")
	case pb.Scanner_SCANNER_SERVICE_DISCOVER:
		target.Host, target.Domain = ptr("example.com"), ptr("")
		job.Options = &pb.JobOptions{Value: &pb.JobOptions_ServiceDiscover{ServiceDiscover: &pb.ServiceDiscoverOption{Ports: "80-82,443,80", Rate: 25}}}
	case pb.Scanner_SCANNER_VULNERABILITY:
		target.Host, target.Port, target.Url = ptr("example.com"), ptr(int32(443)), ptr("https://example.com/login")
	}
	return job
}

func assertScannerAPIIdentity(t *testing.T, jobID, runID string, target, original *pb.JobTarget) {
	t.Helper()
	if jobID != "job-original" || runID != "run-original" {
		t.Errorf("result identity = %q/%q", jobID, runID)
	}
	if !proto.Equal(target, original) {
		t.Errorf("original target/presence changed: got %v; want %v", target, original)
	}
}

type customScanner struct{ scan contract.ScanFunc }

func (s *customScanner) Scan(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
	return s.scan(ctx, targets, emit)
}
