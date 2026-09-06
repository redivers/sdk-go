package runtime

import (
	"github.com/redivers/sdk-go/internal/client"
	"github.com/redivers/sdk-go/internal/contract"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunCancelsOtherJobsWhenTerminalAuthErrorFollowsScanError(t *testing.T) {
	var polls atomic.Int32
	secondStarted := make(chan struct{})
	secondCanceled := make(chan struct{})
	server := &agentServer{
		poll: func(ctx context.Context) (*pb.Job, error) {
			index := polls.Add(1)
			if index > 2 {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			job := agentTestJob()
			job.JobId, job.RunId = fmt.Sprintf("job-%d", index), fmt.Sprintf("run-%d", index)
			job.Targets[0].Host = ptr(fmt.Sprintf("host-%d.example.com", index))
			return job, nil
		},
		start: func(context.Context, *pb.JobStartRequest) (*pb.JobStartResponse, error) {
			return &pb.JobStartResponse{Success: true}, nil
		},
		jobHeartbeat: func(context.Context, *pb.JobHeartbeatRequest) error { return nil },
		failure: func(context.Context, *pb.JobFailureRequest) (*pb.JobFailureResponse, error) {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("token revoked"))
		},
	}
	agent := newAgentTest(t, server, func(ctx context.Context, targets []contract.Target, _ contract.Emitter) error {
		if targets[0].Host == "host-1.example.com" {
			select {
			case <-secondStarted:
				return connect.NewError(connect.CodeUnavailable, errors.New("scanner upstream failed"))
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		close(secondStarted)
		<-ctx.Done()
		close(secondCanceled)
		return ctx.Err()
	}, func(cfg *Config) { cfg.MaxConcurrency = 2 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()
	select {
	case <-secondCanceled:
	case <-time.After(2 * time.Second):
		t.Error("terminal authentication rejection did not promptly cancel the other job")
		agent.Stop()
	}
	select {
	case err := <-done:
		if !client.IsAuthenticationError(err) {
			t.Errorf("Run error lost the fatal authentication failure: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Run did not finish cleanup")
	}
}

func TestAgentRunResumesPollingAfterTransientFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var polls atomic.Int32
	var failedAt atomic.Int64
	s := &agentServer{poll: func(context.Context) (*pb.Job, error) {
		if polls.Add(1) == 1 {
			failedAt.Store(time.Now().UnixNano())
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("temporary outage"))
		}
		if time.Since(time.Unix(0, failedAt.Load())) < 20*time.Millisecond {
			t.Error("poll bypassed next-cycle interval")
		}
		return agentTestJob(), nil
	}, completed: func(context.Context, *pb.JobCompletedRequest) (*pb.JobCompletedResponse, error) {
		cancel()
		return &pb.JobCompletedResponse{Success: true}, nil
	}}
	a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
		return emit.EmitServices(contract.ServiceResult{Target: targets[0], Items: []contract.Service{{Port: 443}}})
	}, func(cfg *Config) { cfg.PollInterval = 25 * time.Millisecond })
	if err := a.Run(ctx); err != nil {
		t.Errorf("Run stopped at transient poll failure: %v", err)
	}
	if polls.Load() != 2 || s.count("completed") != 1 {
		t.Errorf("polls/completed = %d/%d", polls.Load(), s.count("completed"))
	}
}

func TestAgentRunStopsAtInvalidClaimInsteadOfConsumingQueue(t *testing.T) {
	job := agentTestJob()
	job.Scanner = pb.Scanner(99)
	var polls atomic.Int32
	s := &agentServer{poll: func(context.Context) (*pb.Job, error) {
		if polls.Add(1) == 1 {
			return job, nil
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("unexpected extra claim"))
	}}
	a := newAgentTest(t, s, func(context.Context, []contract.Target, contract.Emitter) error {
		t.Error("invalid job reached scanner")
		return nil
	}, func(cfg *Config) { cfg.MaxConcurrency = 3 })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Run(ctx); !errors.Is(err, contract.ErrInvalidJob) {
		t.Errorf("invalid claim = %v", err)
	}
	if s.count("poll") != 1 || s.count("start") != 0 {
		t.Errorf("invalid claim consumed more queue: poll/start = %d/%d", s.count("poll"), s.count("start"))
	}
}

func TestAgentRunBoundsConcurrencyAndDrainsParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var claims atomic.Int32
	s := &agentServer{
		poll: func(ctx context.Context) (*pb.Job, error) {
			index := claims.Add(1)
			if index > 2 {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			job := agentTestJob()
			job.JobId = fmt.Sprintf("job-%d", index)
			job.RunId = fmt.Sprintf("run-%d", index)
			job.Targets[0].AssetScanId = ptr(fmt.Sprintf("asset-%d", index))
			return job, nil
		},
		validateID: func(jobID, runID string) {
			if (jobID != "job-1" || runID != "run-1") && (jobID != "job-2" || runID != "run-2") {
				t.Errorf("callback identity = %q/%q", jobID, runID)
			}
		},
		push: func(_ context.Context, req *pb.PushServicesRequest) (*pb.PushServicesResponse, error) {
			wantAsset := map[string]string{"job-1": "asset-1", "job-2": "asset-2"}[req.JobId]
			if len(req.Results) != 1 || req.Results[0].Target.GetAssetScanId() != wantAsset {
				t.Errorf("push target for %q = %v; want %q", req.JobId, req.Results, wantAsset)
			}
			return &pb.PushServicesResponse{Success: true}, nil
		},
	}
	var running, maximum atomic.Int32
	a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
		n := running.Add(1)
		defer running.Add(-1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		started <- struct{}{}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return emit.EmitServices(contract.ServiceResult{Target: targets[0], Items: []contract.Service{{Port: 443}}})
		}
	}, func(cfg *Config) { cfg.MaxConcurrency = 2 })
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitAgentSignal(t, started)
	waitAgentSignal(t, started)
	if s.count("poll") != 2 {
		t.Errorf("claimed beyond concurrency: %d", s.count("poll"))
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("Run did not drain active jobs: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := waitAgentError(t, done); err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 2 || s.count("completed") != 2 || s.count("failure") != 0 {
		t.Errorf("max/completed/failure = %d/%d/%d", maximum.Load(), s.count("completed"), s.count("failure"))
	}
}

func TestAgentRunForcedShutdownClosesEmitterAndReportsFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	late := make(chan error, 1)
	s := &agentServer{job: agentTestJob()}
	a := newAgentTest(t, s, func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		close(started)
		<-release // Deliberately ignore cancellation to exercise the SDK boundary.
		late <- emit.EmitServices(contract.ServiceResult{Target: targets[0], Items: []contract.Service{{Port: 443}}})
		return nil
	}, func(cfg *Config) { cfg.ShutdownTimeout = 30 * time.Millisecond })
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitAgentSignal(t, started)
	cancel()
	if err := waitAgentError(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("forced shutdown = %v", err)
	}
	close(release)
	if err := waitAgentError(t, late); err == nil {
		t.Error("late report accepted")
	}
	if s.count("failure") != 1 || s.count("push") != 0 {
		t.Errorf("failure/push = %d/%d", s.count("failure"), s.count("push"))
	}
}

func TestAgentRunContinuesAfterIndividualJobFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &agentServer{job: agentTestJob(), completed: func(context.Context, *pb.JobCompletedRequest) (*pb.JobCompletedResponse, error) {
		cancel()
		return &pb.JobCompletedResponse{Success: true}, nil
	}}
	var scans atomic.Int32
	a := newAgentTest(t, s, func(ctx context.Context, targets []contract.Target, emit contract.Emitter) error {
		if scans.Add(1) == 1 {
			return errors.New("scanner failed this job")
		}
		return emit.EmitServices(contract.ServiceResult{Target: targets[0], Items: []contract.Service{{Port: 443}}})
	})
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	if err := waitAgentError(t, done); err != nil {
		t.Fatalf("job error ended worker: %v", err)
	}
	if s.count("failure") != 1 || s.count("completed") != 1 {
		t.Errorf("failure/completed = %d/%d", s.count("failure"), s.count("completed"))
	}
}
