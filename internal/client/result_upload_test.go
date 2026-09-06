package client

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
)

func TestPushEmptyCallsCheckKindAndPreparation(t *testing.T) {
	s := &clientTestServer{}
	c := newTestClient(t, s)
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		a := &Assignment{job: assignmentJob(kind)}
		for _, push := range []func(context.Context, *Assignment) error{
			func(ctx context.Context, a *Assignment) error { return c.PushDomains(ctx, a) },
			func(ctx context.Context, a *Assignment) error { return c.PushServices(ctx, a) },
			func(ctx context.Context, a *Assignment) error { return c.PushFindings(ctx, a) },
		} {
			if err := push(context.Background(), a); err == nil {
				t.Fatal("unprepared assignment accepted an empty push")
			}
		}
		if err := a.PrepareTargets(); err != nil {
			t.Fatal(err)
		}
		errorsByKind := map[pb.Scanner]error{
			pb.Scanner_SCANNER_SUBDOMAIN:        c.PushDomains(context.Background(), a, ([]contract.DNSResult)(nil)...),
			pb.Scanner_SCANNER_SERVICE_DISCOVER: c.PushServices(context.Background(), a, ([]contract.ServiceResult)(nil)...),
			pb.Scanner_SCANNER_VULNERABILITY:    c.PushFindings(context.Background(), a, ([]contract.FindingResult)(nil)...),
		}
		for expected, err := range errorsByKind {
			if (expected == kind) != (err == nil) {
				t.Fatalf("kind=%v method=%v error=%v", kind, expected, err)
			}
		}
		var err error
		switch kind {
		case pb.Scanner_SCANNER_SUBDOMAIN:
			err = c.PushDomains(context.Background(), a)
		case pb.Scanner_SCANNER_SERVICE_DISCOVER:
			err = c.PushServices(context.Background(), a)
		default:
			err = c.PushFindings(context.Background(), a)
		}
		if err != nil {
			t.Fatalf("kind=%v zero-argument push: %v", kind, err)
		}
	}
	if s.count("push") != 0 {
		t.Fatalf("empty outer calls uploaded %d requests", s.count("push"))
	}
}

func TestPushMapsTargetOnlyResultForEveryResultType(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		for _, shape := range []string{"target only", "explicit empty items", "repeated empty wrappers"} {
			t.Run(kind.String()+"/"+shape, func(t *testing.T) {
				requests := make(chan proto.Message, 1)
				s := &clientTestServer{onPush: func(_ http.Header, msg proto.Message) { requests <- msg }}
				c := newTestClient(t, s)
				job := assignmentJob(kind)
				a := preparedAssignment(t, job)
				target := a.Targets()[0]

				var err error
				switch kind {
				case pb.Scanner_SCANNER_SUBDOMAIN:
					results := []contract.DNSResult{{Target: target}}
					if shape != "target only" {
						results[0].Items = []contract.DNSRecord{}
					}
					if shape == "repeated empty wrappers" {
						results = append(results, contract.DNSResult{Target: target})
					}
					err = c.PushDomains(context.Background(), a, results...)
				case pb.Scanner_SCANNER_SERVICE_DISCOVER:
					results := []contract.ServiceResult{{Target: target}}
					if shape != "target only" {
						results[0].Items = []contract.Service{}
					}
					if shape == "repeated empty wrappers" {
						results = append(results, contract.ServiceResult{Target: target})
					}
					err = c.PushServices(context.Background(), a, results...)
				default:
					results := []contract.FindingResult{{Target: target}}
					if shape != "target only" {
						results[0].Items = []contract.Finding{}
					}
					if shape == "repeated empty wrappers" {
						results = append(results, contract.FindingResult{Target: target})
					}
					err = c.PushFindings(context.Background(), a, results...)
				}
				if err != nil {
					t.Fatal(err)
				}
				if s.count("push") != 1 {
					t.Fatalf("target-only result uploaded %d requests", s.count("push"))
				}

				request := <-requests
				switch request := request.(type) {
				case *pb.PushDomainsRequest:
					if len(request.Results) != 1 || !proto.Equal(request.Results[0].Target, job.Targets[0]) || len(request.Results[0].Domains) != 0 || request.Results[0].ErrorMessage != nil {
						t.Fatalf("target-only DNS result = %v", request.Results)
					}
				case *pb.PushServicesRequest:
					if len(request.Results) != 1 || !proto.Equal(request.Results[0].Target, job.Targets[0]) || len(request.Results[0].Services) != 0 || request.Results[0].ErrorMessage != nil {
						t.Fatalf("target-only service result = %v", request.Results)
					}
				case *pb.PushFindingsRequest:
					if len(request.Results) != 1 || !proto.Equal(request.Results[0].Target, job.Targets[0]) || len(request.Results[0].Findings) != 0 || request.Results[0].ErrorMessage != nil {
						t.Fatalf("target-only finding result = %v", request.Results)
					}
				default:
					t.Fatalf("unexpected request type %T", request)
				}
			})
		}
	}
}

func TestPushMapsErrorMessagePresenceForEveryResultType(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			requests := make(chan proto.Message, 2)
			s := &clientTestServer{onPush: func(_ http.Header, msg proto.Message) { requests <- msg }}
			c := newTestClient(t, s)
			job := assignmentJob(kind)
			emptyTarget := proto.Clone(job.Targets[0]).(*pb.JobTarget)
			emptyTarget.AssetScanId = ptr("error-empty")
			failedTarget := proto.Clone(job.Targets[0]).(*pb.JobTarget)
			failedTarget.AssetScanId = ptr("error-message")
			job.Targets = append(job.Targets, emptyTarget, failedTarget)
			a := preparedAssignment(t, job)
			targets := a.Targets()
			empty, message := "", "target failed"

			var err error
			switch kind {
			case pb.Scanner_SCANNER_SUBDOMAIN:
				err = c.PushDomains(context.Background(), a, contract.DNSResult{Target: targets[0], Items: []contract.DNSRecord{{Domain: "www.example.com"}}})
				if err == nil {
					err = c.PushDomains(context.Background(), a,
						contract.DNSResult{Target: targets[1], ErrorMessage: &empty},
						contract.DNSResult{Target: targets[2], ErrorMessage: &message},
					)
				}
			case pb.Scanner_SCANNER_SERVICE_DISCOVER:
				err = c.PushServices(context.Background(), a, contract.ServiceResult{Target: targets[0], Items: []contract.Service{{Port: 443}}})
				if err == nil {
					err = c.PushServices(context.Background(), a,
						contract.ServiceResult{Target: targets[1], ErrorMessage: &empty},
						contract.ServiceResult{Target: targets[2], ErrorMessage: &message},
					)
				}
			default:
				err = c.PushFindings(context.Background(), a, contract.FindingResult{Target: targets[0], Items: []contract.Finding{{Name: "finding", Severity: contract.SeverityInfo}}})
				if err == nil {
					err = c.PushFindings(context.Background(), a,
						contract.FindingResult{Target: targets[1], ErrorMessage: &empty},
						contract.FindingResult{Target: targets[2], ErrorMessage: &message},
					)
				}
			}
			if err != nil {
				t.Fatal(err)
			}

			extract := func(msg proto.Message) ([]*pb.JobTarget, []*string, []int) {
				var gotTargets []*pb.JobTarget
				var gotErrors []*string
				var itemCounts []int
				switch req := msg.(type) {
				case *pb.PushDomainsRequest:
					for _, result := range req.Results {
						gotTargets = append(gotTargets, result.Target)
						gotErrors = append(gotErrors, result.ErrorMessage)
						itemCounts = append(itemCounts, len(result.Domains))
					}
				case *pb.PushServicesRequest:
					for _, result := range req.Results {
						gotTargets = append(gotTargets, result.Target)
						gotErrors = append(gotErrors, result.ErrorMessage)
						itemCounts = append(itemCounts, len(result.Services))
					}
				case *pb.PushFindingsRequest:
					for _, result := range req.Results {
						gotTargets = append(gotTargets, result.Target)
						gotErrors = append(gotErrors, result.ErrorMessage)
						itemCounts = append(itemCounts, len(result.Findings))
					}
				default:
					t.Fatalf("unexpected request type %T", msg)
				}
				return gotTargets, gotErrors, itemCounts
			}

			itemTargets, itemErrors, itemCounts := extract(<-requests)
			if len(itemTargets) != 1 || !proto.Equal(itemTargets[0], job.Targets[0]) || itemErrors[0] != nil || itemCounts[0] != 1 {
				t.Fatalf("item result target=%v error=%v count=%v", itemTargets, itemErrors, itemCounts)
			}
			errorTargets, errorMessages, errorItemCounts := extract(<-requests)
			if len(errorTargets) != 2 || !proto.Equal(errorTargets[0], emptyTarget) || !proto.Equal(errorTargets[1], failedTarget) ||
				errorMessages[0] == nil || *errorMessages[0] != "" || errorMessages[1] == nil || *errorMessages[1] != "target failed" ||
				errorItemCounts[0] != 0 || errorItemCounts[1] != 0 || s.count("push") != 2 {
				t.Fatalf("error results targets=%v errors=%v counts=%v uploads=%d", errorTargets, errorMessages, errorItemCounts, s.count("push"))
			}
		})
	}
}

func TestPushRejectsItemsWithErrorBeforeUpload(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			s := &clientTestServer{}
			c := newTestClient(t, s)
			a := preparedAssignment(t, assignmentJob(kind))
			target := a.Targets()[0]
			message := "target failed"
			var err error
			switch kind {
			case pb.Scanner_SCANNER_SUBDOMAIN:
				err = c.PushDomains(context.Background(), a, contract.DNSResult{Target: target, Items: []contract.DNSRecord{{Domain: "www.example.com"}}, ErrorMessage: &message})
			case pb.Scanner_SCANNER_SERVICE_DISCOVER:
				err = c.PushServices(context.Background(), a, contract.ServiceResult{Target: target, Items: []contract.Service{{Port: 443}}, ErrorMessage: &message})
			default:
				err = c.PushFindings(context.Background(), a, contract.FindingResult{Target: target, Items: []contract.Finding{{Name: "finding", Severity: contract.SeverityInfo}}, ErrorMessage: &message})
			}
			if err == nil || s.count("push") != 0 {
				t.Fatalf("items with error accepted: %v uploads=%d", err, s.count("push"))
			}
		})
	}
}

func TestPushDNSWithoutObservationsSkipsConversion(t *testing.T) {
	message := "domain scan failed"
	for _, tc := range []struct {
		name         string
		errorMessage *string
	}{
		{name: "target-only payload"},
		{name: "target error", errorMessage: &message},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan *pb.PushDomainsRequest, 1)
			s := &clientTestServer{domains: func(_ context.Context, req *pb.PushDomainsRequest) (*pb.PushDomainsResponse, error) {
				requests <- req
				return &pb.PushDomainsResponse{Success: true}, nil
			}}
			c := newTestClient(t, s)
			job := assignmentJob(pb.Scanner_SCANNER_SUBDOMAIN)
			job.Targets[0].Domain = ptr("invalid..assigned.domain")
			a := preparedAssignment(t, job)

			if err := c.PushDomains(context.Background(), a, contract.DNSResult{Target: a.Targets()[0], ErrorMessage: tc.errorMessage}); err != nil {
				t.Fatal(err)
			}
			req := <-requests
			if len(req.Results) != 1 || len(req.Results[0].Domains) != 0 ||
				(req.Results[0].ErrorMessage == nil) != (tc.errorMessage == nil) ||
				req.Results[0].ErrorMessage != nil && *req.Results[0].ErrorMessage != *tc.errorMessage {
				t.Fatalf("DNS result = %v", req.Results)
			}
		})
	}
}

func TestPushDNSDoesNotSynthesizeAssignedRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record contract.DNSRecord
		want   *pb.DnsRecord
	}{
		{
			name:   "descendant without own record",
			record: contract.DNSRecord{Domain: "a.example.com", IPs: []string{"192.0.2.1"}},
			want:   &pb.DnsRecord{Domain: "a.example.com", Ips: []string{"192.0.2.1"}},
		},
		{
			name:   "own record with metadata",
			record: contract.DNSRecord{Domain: "example.com", TXT: []string{"first"}, TTL: ptr(300)},
			want:   &pb.DnsRecord{Domain: "example.com", Txt: []string{"first"}, Ttl: ptr(int32(300))},
		},
		{
			name:   "canonical own record without TTL",
			record: contract.DNSRecord{Domain: "EXAMPLE.COM.", TXT: []string{"second"}},
			want:   &pb.DnsRecord{Domain: "EXAMPLE.COM.", Txt: []string{"second"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan *pb.PushDomainsRequest, 1)
			s := &clientTestServer{domains: func(_ context.Context, req *pb.PushDomainsRequest) (*pb.PushDomainsResponse, error) {
				requests <- req
				return &pb.PushDomainsResponse{Success: true}, nil
			}}
			c := newTestClient(t, s)
			a := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_SUBDOMAIN))
			if err := c.PushDomains(context.Background(), a, contract.DNSResult{Target: a.Targets()[0], Items: []contract.DNSRecord{tc.record}}); err != nil {
				t.Fatal(err)
			}
			req := <-requests
			if len(req.Results) != 1 || len(req.Results[0].Domains) != 1 || !proto.Equal(req.Results[0].Domains[0], tc.want) {
				t.Fatalf("uploaded DNS results = %v; want %v", req.Results, tc.want)
			}
		})
	}
}

func TestPushDNSRejectsDuplicateOwnDomainAcrossMergedWrappers(t *testing.T) {
	s := &clientTestServer{}
	c := newTestClient(t, s)
	a := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_SUBDOMAIN))
	for _, domain := range []string{"example.com", "EXAMPLE.COM"} {
		target := a.Targets()[0]
		err := c.PushDomains(context.Background(), a,
			contract.DNSResult{Target: target, Items: []contract.DNSRecord{{Domain: domain}}},
			contract.DNSResult{Target: target},
			contract.DNSResult{Target: target, Items: []contract.DNSRecord{{Domain: strings.ToUpper(domain) + "."}}},
		)
		if err == nil || !strings.Contains(err.Error(), "duplicate own-domain") || s.count("push") != 0 {
			t.Fatalf("duplicate own domain: %v uploads=%d", err, s.count("push"))
		}
	}
}

func TestPushRetryUsesBoundedAttemptContext(t *testing.T) {
	s := &clientTestServer{}
	c := newTestClient(t, s)
	a := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_SERVICE_DISCOVER))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.PushServices(ctx, a, contract.ServiceResult{Target: a.Targets()[0], Items: []contract.Service{{Port: 443}}})
	if !errors.Is(err, context.Canceled) || s.count("push") != 0 {
		t.Fatalf("canceled attempt: %v uploads=%d", err, s.count("push"))
	}
}

func TestPushConvertedRequestSnapshotsSurviveRetries(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			requests := make(chan proto.Message, 3)
			var attempts atomic.Int32
			responseError := func() error {
				if attempts.Add(1) == 1 {
					return connect.NewError(connect.CodeUnavailable, errors.New("acknowledgement lost"))
				}
				return nil
			}
			s := &clientTestServer{
				onPush: func(_ http.Header, msg proto.Message) { requests <- msg },
				domains: func(context.Context, *pb.PushDomainsRequest) (*pb.PushDomainsResponse, error) {
					return &pb.PushDomainsResponse{Success: true}, responseError()
				},
				push: func(context.Context, *pb.PushServicesRequest) (*pb.PushServicesResponse, error) {
					return &pb.PushServicesResponse{Success: true}, responseError()
				},
				findings: func(context.Context, *pb.PushFindingsRequest) (*pb.PushFindingsResponse, error) {
					return &pb.PushFindingsResponse{Success: true}, responseError()
				},
			}
			job := assignmentJob(kind)
			other := proto.Clone(job.Targets[0]).(*pb.JobTarget)
			other.AssetScanId = ptr("second")
			failed := proto.Clone(job.Targets[0]).(*pb.JobTarget)
			failed.AssetScanId = ptr("failed")
			fresh := proto.Clone(job.Targets[0]).(*pb.JobTarget)
			fresh.AssetScanId = ptr("fresh")
			job.Targets = append(job.Targets, other, failed, fresh)
			original := proto.Clone(job).(*pb.Job)
			a := preparedAssignment(t, job)
			targets := a.Targets()
			targets[0].Host, targets[0].Domain, targets[0].Port, targets[0].URL = "changed", "changed", 80, "changed"
			score := 8.1
			errorMessage := "original failure"
			domains := []contract.DNSResult{
				{Target: targets[0], Items: []contract.DNSRecord{{Domain: "www.example.com", IPs: []string{"192.0.2.1"}, TTL: ptr(60)}}},
				{Target: targets[1], Items: []contract.DNSRecord{{Domain: "other.example.com"}}},
				{Target: targets[2], ErrorMessage: &errorMessage},
			}
			services := []contract.ServiceResult{
				{Target: targets[0], Items: []contract.Service{{Port: 443, CPEs: []string{"original"}, HTTP: &contract.HTTPData{IPs: []string{"192.0.2.1"}, Technologies: []string{"tech"}}, Certificate: &contract.Certificate{SubjectAN: []string{"example.com"}, Wildcard: ptr(false)}}}},
				{Target: targets[1], Items: []contract.Service{{Port: 80}}},
				{Target: targets[2], ErrorMessage: &errorMessage},
			}
			findings := []contract.FindingResult{
				{Target: targets[0], Items: []contract.Finding{{Name: "first", Severity: contract.SeverityHigh, CVSSScore: &score, CWEs: []string{"CWE-79"}, References: []string{"https://example.com/ref"}, Requests: []contract.RawHTTPRequest{{Request: "GET / HTTP/1.1", Response: "HTTP/1.1 200 OK"}}}}},
				{Target: targets[1], Items: []contract.Finding{{Name: "second", Severity: contract.SeverityLow}}},
				{Target: targets[2], ErrorMessage: &errorMessage},
			}
			mutate := func() {
				domains[0].Items[0].IPs[0] = "changed"
				*domains[0].Items[0].TTL = 90
				domains[1].Items[0].Domain = "changed.example.com"
				services[0].Items[0].Port = 8080
				services[0].Items[0].CPEs[0] = "changed"
				services[0].Items[0].HTTP.IPs[0] = "changed"
				services[0].Items[0].HTTP.Technologies[0] = "changed"
				services[0].Items[0].Certificate.SubjectAN[0] = "changed"
				*services[0].Items[0].Certificate.Wildcard = true
				services[1].Items[0].Port = 81
				score = 1
				findings[0].Items[0].CWEs[0] = "changed"
				findings[0].Items[0].References[0] = "changed"
				findings[0].Items[0].Requests[0].Request = "changed"
				findings[1].Items[0].Name = "changed"
				errorMessage = "changed"
			}
			server := startClientServer(t, s)
			transport := http.DefaultTransport.(*http.Transport).Clone()
			t.Cleanup(transport.CloseIdleConnections)
			calls := 0
			httpClient := &http.Client{Transport: transportRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				response, err := transport.RoundTrip(req)
				calls++
				if calls == 1 {
					mutate()
				}
				return response, err
			})}
			c := New("network-token", server.URL, httpClient, time.Second, contract.RetryPolicy{MaxAttempts: 2})
			push := func() error {
				switch kind {
				case pb.Scanner_SCANNER_SUBDOMAIN:
					return c.PushDomains(context.Background(), a, domains...)
				case pb.Scanner_SCANNER_SERVICE_DISCOVER:
					return c.PushServices(context.Background(), a, services...)
				default:
					return c.PushFindings(context.Background(), a, findings...)
				}
			}
			if err := push(); err != nil {
				t.Fatal(err)
			}
			first, second := <-requests, <-requests
			if !proto.Equal(first, second) {
				t.Fatalf("retry changed snapshot: first=%v second=%v", first, second)
			}
			switch req := first.(type) {
			case *pb.PushDomainsRequest:
				if len(req.Results) != len(original.Targets)-1 || req.Results[2].ErrorMessage == nil || *req.Results[2].ErrorMessage != "original failure" {
					t.Fatalf("DNS error snapshot = %v", req.Results)
				}
				for i, r := range req.Results {
					if !proto.Equal(r.Target, original.Targets[i]) {
						t.Fatal("DNS assignment changed")
					}
				}
			case *pb.PushServicesRequest:
				if len(req.Results) != len(original.Targets)-1 || req.Results[2].ErrorMessage == nil || *req.Results[2].ErrorMessage != "original failure" {
					t.Fatalf("service error snapshot = %v", req.Results)
				}
				for i, r := range req.Results {
					if !proto.Equal(r.Target, original.Targets[i]) {
						t.Fatal("service assignment changed")
					}
				}
			case *pb.PushFindingsRequest:
				if len(req.Results) != len(original.Targets)-1 || req.Results[2].ErrorMessage == nil || *req.Results[2].ErrorMessage != "original failure" {
					t.Fatalf("finding error snapshot = %v", req.Results)
				}
				for i, r := range req.Results {
					if !proto.Equal(r.Target, original.Targets[i]) {
						t.Fatal("finding assignment changed")
					}
				}
			}
			var pushErr error
			switch kind {
			case pb.Scanner_SCANNER_SUBDOMAIN:
				pushErr = c.PushDomains(context.Background(), a, contract.DNSResult{Target: targets[3], Items: []contract.DNSRecord{{Domain: "fresh.example.com"}}})
			case pb.Scanner_SCANNER_SERVICE_DISCOVER:
				pushErr = c.PushServices(context.Background(), a, contract.ServiceResult{Target: targets[3], Items: []contract.Service{{Port: 443}}})
			default:
				pushErr = c.PushFindings(context.Background(), a, contract.FindingResult{Target: targets[3], Items: []contract.Finding{{Name: "fresh", Severity: contract.SeverityInfo}}})
			}
			if pushErr != nil {
				t.Fatal(pushErr)
			}
			third := <-requests
			switch req := third.(type) {
			case *pb.PushDomainsRequest:
				if len(req.Results) != 1 || !proto.Equal(req.Results[0].Target, original.Targets[3]) {
					t.Fatalf("fresh DNS push = %v", req.Results)
				}
			case *pb.PushServicesRequest:
				if len(req.Results) != 1 || !proto.Equal(req.Results[0].Target, original.Targets[3]) {
					t.Fatalf("fresh service push = %v", req.Results)
				}
			case *pb.PushFindingsRequest:
				if len(req.Results) != 1 || !proto.Equal(req.Results[0].Target, original.Targets[3]) {
					t.Fatalf("fresh finding push = %v", req.Results)
				}
			}
		})
	}
}
