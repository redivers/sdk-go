package runtime

import (
	"buf.build/gen/go/rediver/api/connectrpc/go/networkscan/networkscanconnect"
	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
	"context"
	"errors"
	"fmt"
	"github.com/redivers/sdk-go/internal/client"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestResultEmitterEmptyCallsHonorLifecycle(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		for _, state := range []string{"canceled", "finished", "closed"} {
			t.Run(kind.String()+"/"+state, func(t *testing.T) {
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				emitter, _ := mustEmitter(t, ctx, emitterJob(kind), nil)
				cause := errors.New("scanner stopped")
				switch state {
				case "canceled":
					cancel(cause)
				case "finished":
					if err := emitter.finish(); err != nil {
						t.Fatal(err)
					}
				case "closed":
					emitter.close()
				}
				var err error
				switch kind {
				case pb.Scanner_SCANNER_SUBDOMAIN:
					err = emitter.EmitDomains()
				case pb.Scanner_SCANNER_SERVICE_DISCOVER:
					err = emitter.EmitServices()
				default:
					err = emitter.EmitFindings()
				}
				if err == nil || state == "canceled" && !errors.Is(err, cause) {
					t.Fatalf("empty call bypassed %s lifecycle: %v", state, err)
				}
				if state == "finished" && emitter.firstErr != nil {
					t.Fatal("late call changed a successfully finished scan")
				}
			})
		}
	}
}

func TestResultEmitterCloseInterruptsUploadWithoutDeadlock(t *testing.T) {
	var emitter *resultEmitter
	closed := make(chan struct{})
	backend := &emitterTestServer{findings: func(context.Context, *pb.PushFindingsRequest) (*pb.PushFindingsResponse, error) {
		// Closing while the caller waits for this very HTTP response must never
		// try to acquire the lock held around the upload.
		emitter.close()
		close(closed)
		return &pb.PushFindingsResponse{Success: true}, nil
	}}
	var targets []contract.Target
	emitter, targets = mustEmitter(t, context.Background(), emitterJob(pb.Scanner_SCANNER_VULNERABILITY), backend)
	done := make(chan error, 1)
	go func() {
		done <- emitter.EmitFindings(contract.FindingResult{Target: targets[0], Items: []contract.Finding{{Name: "record", Severity: contract.SeverityInfo}}})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("upload succeeded after emitter closed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close deadlocked with upload")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close did not release HTTP handler")
	}
	emitter.close()
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	if emitter.job != nil || emitter.client != nil {
		t.Fatal("closed emitter retains assignment references")
	}
}

func TestResultEmitterFinishDrainsActiveCall(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	backend := &emitterTestServer{findings: func(context.Context, *pb.PushFindingsRequest) (*pb.PushFindingsResponse, error) {
		close(entered)
		<-release
		return &pb.PushFindingsResponse{Success: true}, nil
	}}
	emitter, targets := mustEmitter(t, context.Background(), emitterJob(pb.Scanner_SCANNER_VULNERABILITY), backend)
	emitted := make(chan error, 1)
	go func() {
		emitted <- emitter.EmitFindings(contract.FindingResult{Target: targets[0], Items: []contract.Finding{{Name: "record", Severity: contract.SeverityInfo}}})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("upload did not start")
	}
	finished := make(chan error, 1)
	go func() { finished <- emitter.finish() }()
	select {
	case err := <-finished:
		t.Fatalf("finish preceded acknowledgement: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	for _, done := range []<-chan error{emitted, finished} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("acknowledged call did not drain")
		}
	}
	if err := emitter.EmitFindings(); err == nil {
		t.Fatal("finish left emission open")
	}
}

func TestResultEmitterRecoveredUploadPanicRemainsStickyAndReleasesLocks(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			backend := &emitterTestServer{transport: emitterPanicTransport{}}
			emitter, targets := mustEmitter(t, context.Background(), emitterJob(kind), backend)
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				switch kind {
				case pb.Scanner_SCANNER_SUBDOMAIN:
					_ = emitter.EmitDomains(contract.DNSResult{Target: targets[0], Items: []contract.DNSRecord{{Domain: "example.com"}}})
				case pb.Scanner_SCANNER_SERVICE_DISCOVER:
					_ = emitter.EmitServices(contract.ServiceResult{Target: targets[0], Items: []contract.Service{{Port: 443}}})
				default:
					_ = emitter.EmitFindings(contract.FindingResult{Target: targets[0], Items: []contract.Finding{{Name: "observed", Severity: contract.SeverityInfo}}})
				}
			}()
			if recovered != "transport failed" {
				t.Fatalf("upload panic = %v, want original transport panic", recovered)
			}
			finished := make(chan error, 1)
			go func() { finished <- emitter.finish() }()
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("recovered upload panic allowed successful completion")
				}
			case <-time.After(time.Second):
				t.Fatal("finish blocked after recovered upload panic")
			}
		})
	}
}

func TestScannerRejectsTargetFromAnotherExecution(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			var previous contract.Target
			first := &scannerAPIServer{job: scannerAPIJob(kind)}
			capture := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
				previous = targets[0]
				return scannerAPIEmitValid(kind, emit, targets[0])
			})
			if err := runScannerAPIOnce(t, newScannerAPIAgent(t, first, capture)); err != nil {
				t.Fatal(err)
			}
			// Identical IDs and fields cannot transfer a reference between invocations.
			second := &scannerAPIServer{job: scannerAPIJob(kind)}
			var emissionErr error
			reuse := contract.ScanFunc(func(_ context.Context, _ []contract.Target, emit contract.Emitter) error {
				emissionErr = scannerAPIEmitValid(kind, emit, previous)
				return nil
			})
			err := runScannerAPIOnce(t, newScannerAPIAgent(t, second, reuse))
			if emissionErr == nil || !errors.Is(err, emissionErr) || second.failed.Load() != 1 || second.completed.Load() != 0 {
				t.Fatalf("foreign target was accepted: emit=%v run=%v", emissionErr, err)
			}
			second.mu.Lock()
			defer second.mu.Unlock()
			if len(second.domains)+len(second.services)+len(second.findings) != 0 {
				t.Error("foreign reference caused a target upload")
			}
		})
	}
}

func TestScannerEmitWaitsForAcknowledgementAndSerializesConcurrentCalls(t *testing.T) {
	firstEntered, secondEntered := make(chan struct{}), make(chan struct{})
	secondIssued, release := make(chan struct{}), make(chan struct{})
	returned := make(chan struct{}, 2)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var attempts atomic.Int32
	job := scannerAPIJob(pb.Scanner_SCANNER_SERVICE_DISCOVER)
	secondTarget := proto.Clone(job.Targets[0]).(*pb.JobTarget)
	secondTarget.AssetScanId = ptr("second")
	job.Targets = append(job.Targets, secondTarget)
	server := &scannerAPIServer{job: job}
	server.serviceError = func(*pb.PushServicesRequest) error {
		if attempts.Add(1) == 1 {
			close(firstEntered)
			<-release
		} else {
			close(secondEntered)
		}
		return nil
	}
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		errs := make(chan error, 2)
		go func() {
			err := emit.EmitServices(contract.ServiceResult{Target: targets[0], Items: []contract.Service{{Port: 80}}})
			returned <- struct{}{}
			errs <- err
		}()
		<-firstEntered
		go func() {
			close(secondIssued)
			err := emit.EmitServices(contract.ServiceResult{Target: targets[1], Items: []contract.Service{{Port: 443}}})
			returned <- struct{}{}
			errs <- err
		}()
		return errors.Join(<-errs, <-errs)
	})
	agent := newScannerAPIAgent(t, server, scanner)
	// Unblock the handler before the HTTP fixture closes if an assertion fails.
	t.Cleanup(unblock)
	done := make(chan error, 1)
	go func() { done <- runScannerAPIOnce(t, agent) }()
	select {
	case <-secondIssued:
	case <-time.After(time.Second):
		t.Fatal("scanner did not start the concurrent emission")
	}
	select {
	case <-returned:
		t.Fatal("an Emit call returned before the first acknowledgement")
	case <-secondEntered:
		t.Fatal("concurrent Emit calls uploaded before the first acknowledgement")
	case <-time.After(50 * time.Millisecond):
	}
	if server.completed.Load() != 0 {
		t.Fatal("job completed with an unacknowledged Emit call")
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("emissions did not drain after acknowledgement")
	}
	if attempts.Load() != 2 || server.completed.Load() != 1 {
		t.Fatalf("pushes/completions = %d/%d; want 2/1", attempts.Load(), server.completed.Load())
	}
}

func TestScannerRejectsWrongEmitterMethodIncludingEmptyCalls(t *testing.T) {
	methods := []struct {
		kind pb.Scanner
		name string
		emit func(contract.Emitter, contract.Target, string) error
	}{
		{pb.Scanner_SCANNER_SUBDOMAIN, "EmitDomains", func(emit contract.Emitter, target contract.Target, form string) error {
			switch form {
			case "no arguments":
				return emit.EmitDomains()
			case "nil outer slice":
				return emit.EmitDomains([]contract.DNSResult(nil)...)
			case "empty inner slice":
				return emit.EmitDomains(contract.DNSResult{Target: target})
			default:
				return emit.EmitDomains(contract.DNSResult{Target: target, Items: []contract.DNSRecord{{Domain: "www.example.com"}}})
			}
		}},
		{pb.Scanner_SCANNER_SERVICE_DISCOVER, "EmitServices", func(emit contract.Emitter, target contract.Target, form string) error {
			switch form {
			case "no arguments":
				return emit.EmitServices()
			case "nil outer slice":
				return emit.EmitServices([]contract.ServiceResult(nil)...)
			case "empty inner slice":
				return emit.EmitServices(contract.ServiceResult{Target: target})
			default:
				return emit.EmitServices(contract.ServiceResult{Target: target, Items: []contract.Service{{Port: 443}}})
			}
		}},
		{pb.Scanner_SCANNER_VULNERABILITY, "EmitFindings", func(emit contract.Emitter, target contract.Target, form string) error {
			switch form {
			case "no arguments":
				return emit.EmitFindings()
			case "nil outer slice":
				return emit.EmitFindings([]contract.FindingResult(nil)...)
			case "empty inner slice":
				return emit.EmitFindings(contract.FindingResult{Target: target})
			default:
				return emit.EmitFindings(contract.FindingResult{Target: target, Items: []contract.Finding{{Name: "observed", Severity: contract.SeverityHigh}}})
			}
		}},
	}
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		for _, method := range methods {
			if method.kind == kind {
				continue
			}
			for _, form := range []string{"observations", "no arguments", "nil outer slice", "empty inner slice"} {
				t.Run(kind.String()+"/"+method.name+"/"+form, func(t *testing.T) {
					server := &scannerAPIServer{job: scannerAPIJob(kind)}
					var emissionErr, stickyErr error
					scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
						if err := scannerAPIEmitValid(kind, emit, targets[0]); err != nil {
							return err
						}
						emissionErr = method.emit(emit, targets[0], form)
						stickyErr = scannerAPIEmitValid(kind, emit, targets[0])
						return nil
					})
					err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner))
					if emissionErr == nil || !errors.Is(stickyErr, emissionErr) || !errors.Is(err, emissionErr) || server.completed.Load() != 0 || server.failed.Load() != 1 {
						t.Fatalf("wrong emitter method: emit=%v sticky=%v run=%v completed=%d failed=%d", emissionErr, stickyErr, err, server.completed.Load(), server.failed.Load())
					}
					server.mu.Lock()
					defer server.mu.Unlock()
					if len(server.domains)+len(server.services)+len(server.findings) != 1 {
						t.Error("incorrect emitter method must preserve only the previously acknowledged call")
					}
				})
			}
		}
	}
}

func TestScannerUploadsErrorOnlyResultsAndCompletes(t *testing.T) {
	const message = "target scan failed"
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			server := &scannerAPIServer{job: scannerAPIJob(kind)}
			scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
				switch kind {
				case pb.Scanner_SCANNER_SUBDOMAIN:
					return emit.EmitDomains(contract.DNSResult{Target: targets[0], ErrorMessage: ptr(message)})
				case pb.Scanner_SCANNER_SERVICE_DISCOVER:
					return emit.EmitServices(contract.ServiceResult{Target: targets[0], ErrorMessage: ptr(message)})
				default:
					return emit.EmitFindings(contract.FindingResult{Target: targets[0], ErrorMessage: ptr(message)})
				}
			})
			if err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner)); err != nil {
				t.Fatal(err)
			}
			if server.started.Load() != 1 || server.completed.Load() != 1 || server.failed.Load() != 0 {
				t.Fatalf("job lifecycle start/complete/fail = %d/%d/%d", server.started.Load(), server.completed.Load(), server.failed.Load())
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if len(server.domains)+len(server.services)+len(server.findings) != 1 {
				t.Fatalf("push calls = domains:%d services:%d findings:%d; want only the matching push", len(server.domains), len(server.services), len(server.findings))
			}
			switch kind {
			case pb.Scanner_SCANNER_SUBDOMAIN:
				req := server.domains[0]
				if len(req.GetResults()) != 1 {
					t.Fatalf("domain results = %v", req.GetResults())
				}
				result := req.GetResults()[0]
				assertScannerAPIIdentity(t, req.GetJobId(), req.GetRunId(), result.GetTarget(), server.job.GetTargets()[0])
				if !result.HasErrorMessage() || result.GetErrorMessage() != message || len(result.GetDomains()) != 0 {
					t.Errorf("domain error result = %v", result)
				}
			case pb.Scanner_SCANNER_SERVICE_DISCOVER:
				req := server.services[0]
				if len(req.GetResults()) != 1 {
					t.Fatalf("service results = %v", req.GetResults())
				}
				result := req.GetResults()[0]
				assertScannerAPIIdentity(t, req.GetJobId(), req.GetRunId(), result.GetTarget(), server.job.GetTargets()[0])
				if !result.HasErrorMessage() || result.GetErrorMessage() != message || len(result.GetServices()) != 0 {
					t.Errorf("service error result = %v", result)
				}
			default:
				req := server.findings[0]
				if len(req.GetResults()) != 1 {
					t.Fatalf("finding results = %v", req.GetResults())
				}
				result := req.GetResults()[0]
				assertScannerAPIIdentity(t, req.GetJobId(), req.GetRunId(), result.GetTarget(), server.job.GetTargets()[0])
				if !result.HasErrorMessage() || result.GetErrorMessage() != message || len(result.GetFindings()) != 0 {
					t.Errorf("finding error result = %v", result)
				}
			}
		})
	}
}

func TestScannerSnapshotsWrappersAndNestedPayloadsBeforeCallerReusesValues(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			job := scannerAPIJob(kind)
			second := proto.Clone(job.Targets[0]).(*pb.JobTarget)
			second.AssetScanId = ptr("second")
			job.Targets = append(job.Targets, second)
			server := &scannerAPIServer{job: job}
			assertPushCount := func(want int) error {
				server.mu.Lock()
				defer server.mu.Unlock()
				count := len(server.domains) + len(server.services) + len(server.findings)
				if count != want || server.completed.Load() != 0 {
					return fmt.Errorf("emission acknowledgement: pushes=%d want=%d complete=%d", count, want, server.completed.Load())
				}
				return nil
			}
			scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
				firstTarget, secondTarget := targets[0], targets[1]
				switch kind {
				case pb.Scanner_SCANNER_SUBDOMAIN:
					ttl := 60
					records := []contract.DNSRecord{
						{Domain: "first.example.com", A: []string{"192.0.2.3"}, AAAA: []string{"2001:db8::3"}, TXT: []string{"observed"}, TTL: &ttl},
						{Domain: firstTarget.Domain},
					}
					results := []contract.DNSResult{{Target: firstTarget, Items: records}, {Target: firstTarget, Items: []contract.DNSRecord{{Domain: "second.example.com"}}}}
					if err := emit.EmitDomains(results...); err != nil {
						return err
					}
					if err := assertPushCount(1); err != nil {
						return err
					}
					records[0].Domain, records[0].A[0], records[0].AAAA[0], records[0].TXT[0], ttl = "changed.invalid", "192.0.2.99", "2001:db8::99", "changed", 90
					results[1].Items[0].Domain = "changed.invalid"
					results[0] = contract.DNSResult{Target: contract.Target{Domain: "changed.invalid"}}
					if err := emit.EmitDomains(contract.DNSResult{Target: secondTarget, Items: []contract.DNSRecord{
						{Domain: secondTarget.Domain}, {Domain: "third.example.com"}, {Domain: "fourth.example.com"},
					}}); err != nil {
						return err
					}
				case pb.Scanner_SCANNER_SERVICE_DISCOVER:
					wildcard := false
					services := []contract.Service{{
						Port: 80, CPEs: []string{"cpe:/a:example:original"},
						HTTP:        &contract.HTTPData{Title: "observed", IPs: []string{"192.0.2.3"}, Technologies: []string{"original"}},
						Certificate: &contract.Certificate{SubjectAN: []string{"example.com"}, Wildcard: &wildcard},
					}}
					results := []contract.ServiceResult{{Target: firstTarget, Items: services}, {Target: firstTarget, Items: []contract.Service{{Port: 81}}}}
					if err := emit.EmitServices(results...); err != nil {
						return err
					}
					if err := assertPushCount(1); err != nil {
						return err
					}
					service := &services[0]
					service.Port, service.CPEs[0], service.HTTP.Title, service.HTTP.IPs[0] = 65536, "changed", "changed", "192.0.2.99"
					service.HTTP.Technologies[0], service.Certificate.SubjectAN[0], wildcard = "changed", "changed.invalid", true
					results[1].Items[0].Port = 65536
					results[0] = contract.ServiceResult{Target: contract.Target{Host: "changed.invalid"}}
					if err := emit.EmitServices(contract.ServiceResult{Target: secondTarget, Items: []contract.Service{{Port: 82}, {Port: 443}}}); err != nil {
						return err
					}
				case pb.Scanner_SCANNER_VULNERABILITY:
					score := 8.1
					findings := []contract.Finding{{
						Name: "observed", Severity: contract.SeverityHigh, CVSSScore: &score,
						CWEs: []string{"CWE-79"}, References: []string{"https://example.com/reference"},
						Requests: []contract.RawHTTPRequest{{Request: "GET / HTTP/1.1", Response: "HTTP/1.1 200 OK"}},
					}}
					results := []contract.FindingResult{{Target: firstTarget, Items: findings}, {Target: firstTarget, Items: []contract.Finding{{Name: "second", Severity: contract.SeverityInfo}}}}
					if err := emit.EmitFindings(results...); err != nil {
						return err
					}
					if err := assertPushCount(1); err != nil {
						return err
					}
					first := &findings[0]
					first.Name, first.CWEs[0], first.References[0], first.Requests[0].Request, score = "changed", "changed", "changed", "changed", 1
					results[1].Items[0].Name = "changed"
					results[0] = contract.FindingResult{Target: contract.Target{Host: "changed.invalid"}}
					if err := emit.EmitFindings(contract.FindingResult{Target: secondTarget, Items: []contract.Finding{
						{Name: "third", Severity: contract.SeverityLow}, {Name: "fourth", Severity: contract.SeverityMedium},
					}}); err != nil {
						return err
					}
				}
				return assertPushCount(2)
			})
			if err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner)); err != nil {
				t.Fatal(err)
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			switch kind {
			case pb.Scanner_SCANNER_SUBDOMAIN:
				if len(server.domains) != 2 {
					t.Fatalf("DNS pushes = %v", server.domains)
				}
				var domains []string
				for i, req := range server.domains {
					if len(req.Results) != 1 || len(req.Results[0].Domains) != 3 {
						t.Fatalf("DNS result = %v; want its assigned-domain record and two observations", req)
					}
					assertScannerAPIIdentity(t, req.JobId, req.RunId, req.Results[0].Target, server.job.Targets[i])
					for _, record := range req.Results[0].Domains {
						domains = append(domains, record.Domain)
					}
				}
				record := server.domains[0].Results[0].Domains[0]
				if len(record.A) != 1 || record.A[0] != "192.0.2.3" || len(record.Aaaa) != 1 || record.Aaaa[0] != "2001:db8::3" || len(record.Txt) != 1 || record.Txt[0] != "observed" || record.GetTtl() != 60 {
					t.Errorf("caller mutation leaked into DNS payload: %v", record)
				}
				wantDomains := []string{"first.example.com", "example.com", "second.example.com", "example.com", "third.example.com", "fourth.example.com"}
				if !reflect.DeepEqual(domains, wantDomains) {
					t.Errorf("caller mutation leaked into DNS result sets: %v", domains)
				}
			case pb.Scanner_SCANNER_SERVICE_DISCOVER:
				if len(server.services) != 2 {
					t.Fatalf("service pushes = %v", server.services)
				}
				for i, req := range server.services {
					if len(req.Results) != 1 || len(req.Results[0].Services) != 2 {
						t.Fatalf("service result = %v; want only its two observations", req)
					}
					assertScannerAPIIdentity(t, req.JobId, req.RunId, req.Results[0].Target, server.job.Targets[i])
					for j, service := range req.Results[0].Services {
						if want := []int32{80, 81, 82, 443}[i*2+j]; service.Port != want {
							t.Errorf("service push %d result %d port = %d; want %d", i, j, service.Port, want)
						}
					}
				}
				service := server.services[0].Results[0].Services[0]
				if service.Port != 80 || service.Host != "example.com" || len(service.Cpes) != 1 || service.Cpes[0] != "cpe:/a:example:original" {
					t.Errorf("caller mutation leaked into service payload: %v", service)
				}
				http, cert := service.Http, service.Certificate
				if http == nil || http.GetTitle() != "observed" || len(http.Ips) != 1 || http.Ips[0] != "192.0.2.3" || len(http.Technologies) != 1 || http.Technologies[0] != "original" {
					t.Errorf("caller mutation leaked into HTTP payload: %v", http)
				}
				if cert == nil || cert.Wildcard == nil || cert.GetWildcard() || len(cert.SubjectAn) != 1 || cert.SubjectAn[0] != "example.com" {
					t.Errorf("caller mutation leaked into certificate payload: %v", cert)
				}
			case pb.Scanner_SCANNER_VULNERABILITY:
				if len(server.findings) != 2 {
					t.Fatalf("finding pushes = %v", server.findings)
				}
				for i, req := range server.findings {
					if len(req.Results) != 1 || len(req.Results[0].Findings) != 2 {
						t.Fatalf("finding result = %v; want only its two observations", req)
					}
					assertScannerAPIIdentity(t, req.JobId, req.RunId, req.Results[0].Target, server.job.Targets[i])
					for j, finding := range req.Results[0].Findings {
						if want := []string{"observed", "second", "third", "fourth"}[i*2+j]; finding.Name != want {
							t.Errorf("finding push %d result %d name = %q; want %q", i, j, finding.Name, want)
						}
					}
				}
				finding := server.findings[0].Results[0].Findings[0]
				if finding.Name != "observed" || finding.Severity != pb.FindingSeverity_FINDING_SEVERITY_HIGH || finding.GetCvssScore() != float32(8.1) ||
					len(finding.Cwes) != 1 || finding.Cwes[0] != "CWE-79" || len(finding.References) != 1 || finding.References[0] != "https://example.com/reference" ||
					len(finding.Requests) != 1 || finding.Requests[0].Request != "GET / HTTP/1.1" || finding.Requests[0].Response != "HTTP/1.1 200 OK" {
					t.Errorf("caller mutation leaked into finding payload: %v", finding)
				}
			}
		})
	}
}

func TestScannerValidatesWholeEmitCallAndPreservesEarlierAcknowledgements(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		for _, invalid := range []string{"later observation", "later wrapper", "reconstructed target", "empty reconstructed target"} {
			for _, prior := range []string{"no prior emission", "acknowledged emission"} {
				t.Run(kind.String()+"/"+invalid+"/"+prior, func(t *testing.T) {
					job := scannerAPIJob(kind)
					second := scannerAPIJob(kind).Targets[0]
					second.AssetScanId = ptr("second")
					job.Targets = append(job.Targets, second)
					server := &scannerAPIServer{job: job}
					var emissionErr, stickyErr error
					scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
						if prior == "acknowledged emission" {
							if err := scannerAPIEmitValid(kind, emit, targets[0]); err != nil {
								return err
							}
						}
						first, last := targets[0], targets[1]
						if invalid == "reconstructed target" || invalid == "empty reconstructed target" {
							last = contract.Target{Domain: last.Domain, Host: last.Host, Port: last.Port, URL: last.URL, Ports: last.Ports, Rate: last.Rate}
						}
						switch kind {
						case pb.Scanner_SCANNER_SUBDOMAIN:
							valid := contract.DNSRecord{Domain: "www.example.com"}
							results := []contract.DNSResult{{Target: first, Items: []contract.DNSRecord{valid}}, {Target: last, Items: []contract.DNSRecord{valid}}}
							switch invalid {
							case "later observation":
								results[0].Items = append(results[0].Items, contract.DNSRecord{Domain: "unrelated.invalid"})
							case "later wrapper":
								results[1].Items[0].Domain = "unrelated.invalid"
							case "empty reconstructed target":
								results[1].Items = nil
							}
							emissionErr = emit.EmitDomains(results...)
						case pb.Scanner_SCANNER_SERVICE_DISCOVER:
							results := []contract.ServiceResult{{Target: first, Items: []contract.Service{{Port: 80}}}, {Target: last, Items: []contract.Service{{Port: 443}}}}
							switch invalid {
							case "later observation":
								results[0].Items = append(results[0].Items, contract.Service{Port: 65536})
							case "later wrapper":
								results[1].Items[0].Port = 65536
							case "empty reconstructed target":
								results[1].Items = nil
							}
							emissionErr = emit.EmitServices(results...)
						default:
							valid := contract.Finding{Name: "observed", Severity: contract.SeverityHigh}
							results := []contract.FindingResult{{Target: first, Items: []contract.Finding{valid}}, {Target: last, Items: []contract.Finding{valid}}}
							switch invalid {
							case "later observation":
								results[0].Items = append(results[0].Items, contract.Finding{})
							case "later wrapper":
								results[1].Items[0].Severity = contract.SeverityUnspecified
							case "empty reconstructed target":
								results[1].Items = nil
							}
							emissionErr = emit.EmitFindings(results...)
						}
						stickyErr = scannerAPIEmitValid(kind, emit, targets[0])
						// Ignoring an emission error must never finalize a partial batch.
						return nil
					})
					err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner))
					if emissionErr == nil || !errors.Is(stickyErr, emissionErr) || !errors.Is(err, emissionErr) || server.failed.Load() != 1 || server.completed.Load() != 0 {
						t.Fatalf("ignored emission error: emit=%v sticky=%v run=%v failed=%d completed=%d", emissionErr, stickyErr, err, server.failed.Load(), server.completed.Load())
					}
					server.mu.Lock()
					defer server.mu.Unlock()
					want := 0
					if prior == "acknowledged emission" {
						want = 1
					}
					if len(server.services)+len(server.domains)+len(server.findings) != want {
						t.Errorf("invalid call changed uploads: got %d; want %d earlier acknowledgements", len(server.services)+len(server.domains)+len(server.findings), want)
					}
				})
			}
		}
	}
}

func scannerAPIEmitValid(kind pb.Scanner, emit contract.Emitter, target contract.Target) error {
	switch kind {
	case pb.Scanner_SCANNER_SUBDOMAIN:
		return emit.EmitDomains(contract.DNSResult{Target: target, Items: []contract.DNSRecord{{Domain: target.Domain}}})
	case pb.Scanner_SCANNER_SERVICE_DISCOVER:
		return emit.EmitServices(contract.ServiceResult{Target: target, Items: []contract.Service{{Port: 443}}})
	default:
		return emit.EmitFindings(contract.FindingResult{Target: target, Items: []contract.Finding{{Name: "observed", Severity: contract.SeverityHigh}}})
	}
}

func TestScannerPreservesDNSResultMetadata(t *testing.T) {
	job := scannerAPIJob(pb.Scanner_SCANNER_SUBDOMAIN)
	for i := 1; i < 4; i++ {
		target := proto.Clone(job.Targets[0]).(*pb.JobTarget)
		target.AssetScanId = ptr(fmt.Sprintf("asset-%d", i))
		job.Targets = append(job.Targets, target)
	}
	server := &scannerAPIServer{job: job}
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		for i, records := range [][]contract.DNSRecord{
			{{Domain: "example.com"}, {Domain: "www.example.com"}},
			{{Domain: "example.com", TTL: ptr(300)}},
			{{Domain: "EXAMPLE.COM.", TTL: ptr(600)}},
			{{Domain: "example.com"}, {Domain: "www.example.com", TTL: ptr(60)}},
		} {
			if err := emit.EmitDomains(contract.DNSResult{Target: targets[i], Items: records}); err != nil {
				return err
			}
		}
		return nil
	})
	if err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner)); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.domains) != 4 || server.completed.Load() != 1 {
		t.Fatalf("Push calls/completions = %d/%d; want 4/1", len(server.domains), server.completed.Load())
	}
	for i, req := range server.domains {
		wantRecords := []int{2, 1, 1, 2}[i]
		if len(req.Results) != 1 || len(req.Results[0].Domains) != wantRecords {
			t.Fatalf("call %d DNS records = %v; want %d", i, req.Results, wantRecords)
		}
		assertScannerAPIIdentity(t, req.JobId, req.RunId, req.Results[0].Target, server.job.Targets[i])
	}
	if server.domains[1].Results[0].Domains[0].GetTtl() != 300 || server.domains[2].Results[0].Domains[0].GetTtl() != 600 {
		t.Fatal("assigned-domain records lost their metadata")
	}
	if server.domains[3].Results[0].Domains[1].GetTtl() != 60 {
		t.Fatal("descendant record lost its metadata")
	}
}

func TestScannerRejectsDuplicateDNSOwnDomainAcrossMergedWrappers(t *testing.T) {
	for _, domain := range []string{"example.com", "EXAMPLE.COM"} {
		t.Run(domain, func(t *testing.T) {
			server := &scannerAPIServer{job: scannerAPIJob(pb.Scanner_SCANNER_SUBDOMAIN)}
			var emissionErr error
			scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
				emissionErr = emit.EmitDomains(
					contract.DNSResult{Target: targets[0], Items: []contract.DNSRecord{{Domain: domain}}},
					contract.DNSResult{Target: targets[0], Items: []contract.DNSRecord{{Domain: domain + "."}}},
				)
				return nil
			})
			err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner))
			if emissionErr == nil || !errors.Is(err, emissionErr) || server.completed.Load() != 0 || server.failed.Load() != 1 {
				t.Fatalf("duplicate DNS lifecycle: emit=%v run=%v complete=%d failed=%d", emissionErr, err, server.completed.Load(), server.failed.Load())
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if len(server.domains) != 0 {
				t.Fatal("part of an invalid merged DNS call reached HTTP")
			}
		})
	}
}

func TestScannerPreservesRepeatedDNSDescendantsAcrossMergedWrappers(t *testing.T) {
	server := &scannerAPIServer{job: scannerAPIJob(pb.Scanner_SCANNER_SUBDOMAIN)}
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		return emit.EmitDomains(
			contract.DNSResult{Target: targets[0], Items: []contract.DNSRecord{
				{Domain: targets[0].Domain},
				{Domain: "www.example.com", TXT: []string{"first"}, TTL: ptr(300)},
				{Domain: "api.example.com", TXT: []string{"distinct"}},
			}},
			contract.DNSResult{Target: targets[0], Items: []contract.DNSRecord{
				{Domain: "WWW.EXAMPLE.COM.", TXT: []string{"second"}},
			}},
		)
	})
	if err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner)); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.domains) != 1 || len(server.domains[0].Results) != 1 || server.completed.Load() != 1 {
		t.Fatalf("repeated descendant request did not upload once and complete: %v", server.domains)
	}
	records := server.domains[0].Results[0].Domains
	if len(records) != 4 || records[0].Domain != "example.com" || records[1].Domain != "www.example.com" || records[1].GetTtl() != 300 || records[1].GetTxt()[0] != "first" || records[2].Domain != "api.example.com" || records[2].GetTxt()[0] != "distinct" || records[3].Domain != "WWW.EXAMPLE.COM." || records[3].Ttl != nil || records[3].GetTxt()[0] != "second" {
		t.Fatalf("merged wrappers lost or combined complete DNS observations: %v", records)
	}
}

func TestScannerEmitsMultipleTargetsAndMergesRepeatedResultSets(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		for _, form := range []string{"variadic", "expanded slice"} {
			t.Run(kind.String()+"/"+form, func(t *testing.T) {
				job := scannerAPIJob(kind)
				for i := 1; i < 3; i++ {
					target := scannerAPIJob(kind).Targets[0]
					target.AssetScanId = ptr(fmt.Sprintf("asset-%d", i))
					job.Targets = append(job.Targets, target)
				}
				server := &scannerAPIServer{job: job}
				scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
					if len(targets) != 3 {
						return fmt.Errorf("input batch has %d targets; want 3", len(targets))
					}
					// Interleave identical visible targets and repeat one target inside
					// a single final request. Emit the remaining target separately.
					switch kind {
					case pb.Scanner_SCANNER_SUBDOMAIN:
						results := []contract.DNSResult{
							{Target: targets[1], Items: []contract.DNSRecord{{Domain: targets[1].Domain}, {Domain: "one.example.com"}}},
							{Target: targets[0], Items: []contract.DNSRecord{{Domain: targets[0].Domain}, {Domain: "two.example.com"}, {Domain: "three.example.com"}}},
							{Target: targets[1], Items: []contract.DNSRecord{{Domain: "four.example.com"}}},
						}
						var err error
						if form == "variadic" {
							err = emit.EmitDomains(results[0], results[1], results[2])
						} else {
							err = emit.EmitDomains(results...)
						}
						if err != nil {
							return err
						}
						return emit.EmitDomains(contract.DNSResult{Target: targets[2], Items: []contract.DNSRecord{{Domain: targets[2].Domain}, {Domain: "five.example.com"}}})
					case pb.Scanner_SCANNER_SERVICE_DISCOVER:
						results := []contract.ServiceResult{
							{Target: targets[1], Items: []contract.Service{{Port: 80}}},
							{Target: targets[0], Items: []contract.Service{{Port: 81}, {Port: 82}}},
							{Target: targets[1], Items: []contract.Service{{Port: 443}}},
						}
						var err error
						if form == "variadic" {
							err = emit.EmitServices(results[0], results[1], results[2])
						} else {
							err = emit.EmitServices(results...)
						}
						if err != nil {
							return err
						}
						return emit.EmitServices(contract.ServiceResult{Target: targets[2], Items: []contract.Service{{Port: 443}}})
					default:
						finding := func(name string) contract.Finding {
							return contract.Finding{Name: name, Severity: contract.SeverityHigh}
						}
						results := []contract.FindingResult{
							{Target: targets[1], Items: []contract.Finding{finding("one")}},
							{Target: targets[0], Items: []contract.Finding{finding("two"), finding("three")}},
							{Target: targets[1], Items: []contract.Finding{finding("four")}},
						}
						var err error
						if form == "variadic" {
							err = emit.EmitFindings(results[0], results[1], results[2])
						} else {
							err = emit.EmitFindings(results...)
						}
						if err != nil {
							return err
						}
						return emit.EmitFindings(contract.FindingResult{Target: targets[2], Items: []contract.Finding{finding("five")}})
					}
				})
				if err := runScannerAPIOnce(t, newScannerAPIAgent(t, server, scanner)); err != nil {
					t.Fatal(err)
				}
				server.mu.Lock()
				defer server.mu.Unlock()
				if len(server.domains)+len(server.services)+len(server.findings) != 2 || server.completed.Load() != 1 || server.failed.Load() != 0 {
					t.Fatal("expected exactly one upload per Emit call and one completed job")
				}
				got := make([][]string, 3)
				targetIndex := func(jobID, runID string, target *pb.JobTarget) int {
					for i, original := range job.Targets {
						if target.GetAssetScanId() == original.GetAssetScanId() {
							assertScannerAPIIdentity(t, jobID, runID, target, original)
							return i
						}
					}
					t.Fatalf("unknown target in upload: %v", target)
					return -1
				}
				assertResultCount := func(call, count int) {
					want := 2
					if call == 1 {
						want = 1
					}
					if count != want {
						t.Fatalf("Push call %d contains %d target results; want %d", call, count, want)
					}
				}
				for i, req := range server.domains {
					assertResultCount(i, len(req.Results))
					for _, result := range req.Results {
						index := targetIndex(req.JobId, req.RunId, result.Target)
						for _, record := range result.Domains {
							got[index] = append(got[index], record.Domain)
						}
					}
				}
				for i, req := range server.services {
					assertResultCount(i, len(req.Results))
					for _, result := range req.Results {
						index := targetIndex(req.JobId, req.RunId, result.Target)
						for _, service := range result.Services {
							got[index] = append(got[index], fmt.Sprint(service.Port))
						}
					}
				}
				for i, req := range server.findings {
					assertResultCount(i, len(req.Results))
					for _, result := range req.Results {
						index := targetIndex(req.JobId, req.RunId, result.Target)
						for _, finding := range result.Findings {
							got[index] = append(got[index], finding.Name)
						}
					}
				}
				var want [][]string
				switch kind {
				case pb.Scanner_SCANNER_SUBDOMAIN:
					want = [][]string{{"example.com", "two.example.com", "three.example.com"}, {"example.com", "one.example.com", "four.example.com"}, {"example.com", "five.example.com"}}
				case pb.Scanner_SCANNER_SERVICE_DISCOVER:
					want = [][]string{{"81", "82"}, {"80", "443"}, {"443"}}
				default:
					want = [][]string{{"two", "three"}, {"one", "four"}, {"five"}}
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("merged target results = %v; want %v", got, want)
				}
			})
		}
	}
}

func TestScannerUploadRetryDoesNotRescanBatch(t *testing.T) {
	var attempts, calls atomic.Int32
	server := &scannerAPIServer{
		job: scannerAPIJob(pb.Scanner_SCANNER_SERVICE_DISCOVER),
		serviceError: func(*pb.PushServicesRequest) error {
			if attempts.Add(1) == 1 {
				return connect.NewError(connect.CodeUnavailable, errors.New("temporary upload failure"))
			}
			return nil
		},
	}
	scanner := contract.ScanFunc(func(_ context.Context, targets []contract.Target, emit contract.Emitter) error {
		calls.Add(1)
		return emit.EmitServices(contract.ServiceResult{Target: targets[0], Items: []contract.Service{{Port: 443}}})
	})
	policy := contract.DefaultRetryPolicy()
	policy.MaxAttempts, policy.InitialBackoff, policy.MaxBackoff, policy.Jitter = 2, time.Millisecond, time.Millisecond, false
	agent := newScannerAPIAgent(t, server, scanner, func(cfg *Config) { cfg.RetryPolicy = policy })
	if err := runScannerAPIOnce(t, agent); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || attempts.Load() != 2 || server.completed.Load() != 1 {
		t.Fatalf("scan/upload/complete = %d/%d/%d", calls.Load(), attempts.Load(), server.completed.Load())
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.services) != 2 || !proto.Equal(server.services[0], server.services[1]) {
		t.Errorf("retry changed target identity or scan results: %v", server.services)
	}
}

func TestResultEmitterRetainsUploadErrorsAndRejectedAcknowledgements(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(map[bool]string{false: "connect error", true: "success false"}[rejected], func(t *testing.T) {
			backend := &emitterTestServer{services: func(context.Context, *pb.PushServicesRequest) (*pb.PushServicesResponse, error) {
				if rejected {
					return &pb.PushServicesResponse{Success: false}, nil
				}
				return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("stale run"))
			}}
			emitter, targets := mustEmitter(t, context.Background(), emitterJob(pb.Scanner_SCANNER_SERVICE_DISCOVER), backend)
			emitErr := emitter.EmitServices(contract.ServiceResult{Target: targets[0], Items: []contract.Service{{Port: 443}}})
			finishErr := emitter.finish()
			if emitErr == nil || !errors.Is(finishErr, emitErr) {
				t.Fatalf("emit = %v, finish = %v", emitErr, finishErr)
			}
			if !rejected && connect.CodeOf(finishErr) != connect.CodeFailedPrecondition {
				t.Fatalf("Connect code lost: %v", finishErr)
			}
		})
	}
}

// The emitter receives an opaque assignment prepared by the actual backend client.
// Generated fixtures remain in tests; production lifetime code sees native values.
type emitterTestServer struct {
	networkscanconnect.UnimplementedScannerServiceHandler
	job       *pb.Job
	transport http.RoundTripper
	domains   func(context.Context, *pb.PushDomainsRequest) (*pb.PushDomainsResponse, error)
	services  func(context.Context, *pb.PushServicesRequest) (*pb.PushServicesResponse, error)
	findings  func(context.Context, *pb.PushFindingsRequest) (*pb.PushFindingsResponse, error)
}

func (s *emitterTestServer) JobPoll(context.Context, *connect.Request[pb.JobPollRequest]) (*connect.Response[pb.JobPollResponse], error) {
	return connect.NewResponse(&pb.JobPollResponse{Job: proto.Clone(s.job).(*pb.Job)}), nil
}

func (s *emitterTestServer) PushDomains(ctx context.Context, req *connect.Request[pb.PushDomainsRequest]) (*connect.Response[pb.PushDomainsResponse], error) {
	if s.domains != nil {
		msg, err := s.domains(ctx, req.Msg)
		return connect.NewResponse(msg), err
	}
	return connect.NewResponse(&pb.PushDomainsResponse{Success: true}), nil
}

func (s *emitterTestServer) PushServices(ctx context.Context, req *connect.Request[pb.PushServicesRequest]) (*connect.Response[pb.PushServicesResponse], error) {
	if s.services != nil {
		msg, err := s.services(ctx, req.Msg)
		return connect.NewResponse(msg), err
	}
	return connect.NewResponse(&pb.PushServicesResponse{Success: true}), nil
}

func (s *emitterTestServer) PushFindings(ctx context.Context, req *connect.Request[pb.PushFindingsRequest]) (*connect.Response[pb.PushFindingsResponse], error) {
	if s.findings != nil {
		msg, err := s.findings(ctx, req.Msg)
		return connect.NewResponse(msg), err
	}
	return connect.NewResponse(&pb.PushFindingsResponse{Success: true}), nil
}

type emitterPanicTransport struct{}

func (emitterPanicTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("transport failed")
}

func emitterJob(kind pb.Scanner) *pb.Job {
	job := &pb.Job{JobId: "emitter-job", RunId: "emitter-run", Scanner: kind,
		Targets: []*pb.JobTarget{{AssetScanId: ptr("first"), Domain: ptr("example.com"), Host: ptr("example.com"), Url: ptr("")}}}
	if kind == pb.Scanner_SCANNER_SERVICE_DISCOVER {
		job.Options = &pb.JobOptions{Value: &pb.JobOptions_ServiceDiscover{ServiceDiscover: &pb.ServiceDiscoverOption{Ports: "443,80-81,80", Rate: 20}}}
	}
	if kind == pb.Scanner_SCANNER_VULNERABILITY {
		job.Targets[0].Port = ptr(int32(443))
	}
	return job
}

func mustEmitter(t *testing.T, ctx context.Context, job *pb.Job, fixture *emitterTestServer) (*resultEmitter, []contract.Target) {
	t.Helper()
	if fixture == nil {
		fixture = &emitterTestServer{}
	}
	fixture.job = job
	_, handler := networkscanconnect.NewScannerServiceHandler(fixture)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	backend := client.New("token", server.URL, server.Client(), time.Second, contract.RetryPolicy{MaxAttempts: 1})
	assignment, err := backend.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := assignment.PrepareTargets(); err != nil {
		t.Fatal(err)
	}
	if fixture.transport != nil {
		backend = client.New("token", server.URL, &http.Client{Transport: fixture.transport}, time.Second, contract.RetryPolicy{MaxAttempts: 1})
	}
	scanCtx, cancelScan := context.WithCancelCause(ctx)
	emitter := newResultEmitter(scanCtx, assignment, backend, cancelScan)
	t.Cleanup(func() { emitter.close(); cancelScan(nil) })
	return emitter, assignment.Targets()
}
