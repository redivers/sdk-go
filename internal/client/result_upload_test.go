package client

import (
	"context"
	"encoding/hex"
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
	c := newTestClient(t, &clientTestServer{})
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
	}
}

func TestPushPayloadLimitResetsForEachCall(t *testing.T) {
	s := &clientTestServer{}
	c := newTestClient(t, s)
	c.requestTimeout = 5 * time.Second
	a := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_VULNERABILITY))
	result := contract.FindingResult{Target: a.Targets()[0], Items: []contract.Finding{{Name: "large evidence", Severity: contract.SeverityInfo, Description: strings.Repeat("a", 33<<20)}}}
	for i := 0; i < 2; i++ {
		if err := c.PushFindings(context.Background(), a, result); err != nil {
			t.Fatalf("valid payload %d: %v", i, err)
		}
	}
	err := c.PushFindings(context.Background(), a, result, result)
	if err == nil || !strings.Contains(err.Error(), "64 MiB") || s.count("push") != 2 {
		t.Fatalf("per-call payload error=%v uploads=%d", err, s.count("push"))
	}
}

func TestPushPayloadLimitIncludesRequestEnvelope(t *testing.T) {
	s := &clientTestServer{}
	c := newTestClient(t, s)
	a := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_VULNERABILITY))
	finding := contract.Finding{Name: "record", Severity: contract.SeverityInfo, Description: strings.Repeat("a", maxEmissionBytes-32)}
	err := c.PushFindings(context.Background(), a, contract.FindingResult{Target: a.Targets()[0], Items: []contract.Finding{finding}})
	if err == nil || !strings.Contains(err.Error(), "64 MiB") || s.count("push") != 0 {
		t.Fatalf("envelope escaped accounting: %v uploads=%d", err, s.count("push"))
	}
}

func TestPushDNSOwnRecordIsOptionalAndMayRepeatAcrossCalls(t *testing.T) {
	requests := make(chan *pb.PushDomainsRequest, 3)
	s := &clientTestServer{domains: func(_ context.Context, req *pb.PushDomainsRequest) (*pb.PushDomainsResponse, error) {
		requests <- req
		return &pb.PushDomainsResponse{Success: true}, nil
	}}
	c := newTestClient(t, s)
	a := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_SUBDOMAIN))
	for _, records := range [][]contract.DNSRecord{
		{{Domain: "a.example.com", IPs: []string{"192.0.2.1"}}},
		{{Domain: "example.com", TXT: []string{"first"}, TTL: ptr(300)}},
		{{Domain: "EXAMPLE.COM.", TXT: []string{"second"}}},
	} {
		if err := c.PushDomains(context.Background(), a, contract.DNSResult{Target: a.Targets()[0], Items: records}); err != nil {
			t.Fatal(err)
		}
	}
	var last *pb.DnsRecord
	for i := 0; i < 3; i++ {
		req := <-requests
		if len(req.Results) != 1 || len(req.Results[0].Domains) != 1 {
			t.Fatalf("synthetic records uploaded: %v", req)
		}
		last = req.Results[0].Domains[0]
	}
	if last.Ttl != nil || len(last.Txt) != 1 || last.Txt[0] != "second" {
		t.Fatalf("prior record metadata leaked: %v", last)
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

func TestPushIdempotencyKeysAndAllWrapperSnapshotsSurviveRetries(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			type received struct {
				key string
				msg proto.Message
			}
			requests := make(chan received, 3)
			var attempts atomic.Int32
			responseError := func() error {
				if attempts.Add(1) == 1 {
					return connect.NewError(connect.CodeUnavailable, errors.New("acknowledgement lost"))
				}
				return nil
			}
			s := &clientTestServer{
				onPush: func(header http.Header, msg proto.Message) { requests <- received{header.Get("Idempotency-Key"), msg} },
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
			job.Targets = append(job.Targets, other)
			original := proto.Clone(job).(*pb.Job)
			a := preparedAssignment(t, job)
			targets := a.Targets()
			targets[0].Host, targets[0].Domain, targets[0].Port, targets[0].URL = "changed", "changed", 80, "changed"
			score := 8.1
			domains := []contract.DNSResult{
				{Target: targets[0], Items: []contract.DNSRecord{{Domain: "www.example.com", IPs: []string{"192.0.2.1"}, TTL: ptr(60)}}},
				{Target: targets[1], Items: []contract.DNSRecord{{Domain: "other.example.com"}}},
			}
			services := []contract.ServiceResult{
				{Target: targets[0], Items: []contract.Service{{Port: 443, CPEs: []string{"original"}, HTTP: &contract.HTTPData{IPs: []string{"192.0.2.1"}, Technologies: []string{"tech"}}, Certificate: &contract.Certificate{SubjectAN: []string{"example.com"}, Wildcard: ptr(false)}}}},
				{Target: targets[1], Items: []contract.Service{{Port: 80}}},
			}
			findings := []contract.FindingResult{
				{Target: targets[0], Items: []contract.Finding{{Name: "first", Severity: contract.SeverityHigh, CVSSScore: &score, CWEs: []string{"CWE-79"}, References: []string{"https://example.com/ref"}, Requests: []contract.RawHTTPRequest{{Request: "GET / HTTP/1.1", Response: "HTTP/1.1 200 OK"}}}}},
				{Target: targets[1], Items: []contract.Finding{{Name: "second", Severity: contract.SeverityLow}}},
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
			c := New("network-token", server.URL, httpClient, time.Second, contract.RetryPolicy{MaxAttempts: 2, RetryableStatusCodes: []int{503}})
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
			decoded, err := hex.DecodeString(first.key)
			if err != nil || len(decoded) != 16 || first.key != second.key || !proto.Equal(first.msg, second.msg) {
				t.Fatalf("retry changed snapshot or key: first=%v second=%v", first, second)
			}
			switch req := first.msg.(type) {
			case *pb.PushDomainsRequest:
				for i, r := range req.Results {
					if !proto.Equal(r.Target, original.Targets[i]) {
						t.Fatal("DNS assignment changed")
					}
				}
			case *pb.PushServicesRequest:
				for i, r := range req.Results {
					if !proto.Equal(r.Target, original.Targets[i]) {
						t.Fatal("service assignment changed")
					}
				}
			case *pb.PushFindingsRequest:
				for i, r := range req.Results {
					if !proto.Equal(r.Target, original.Targets[i]) {
						t.Fatal("finding assignment changed")
					}
				}
			}
			if err := push(); err != nil {
				t.Fatal(err)
			}
			third := <-requests
			if third.key == first.key || third.key == "" {
				t.Fatal("new push reused previous key")
			}
		})
	}
}
