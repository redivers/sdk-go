package client

import (
	"context"
	"strings"
	"testing"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
)

func TestPushRecordLimitResetsForEachCall(t *testing.T) {
	s := &clientTestServer{}
	c := newTestClient(t, s)
	a := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_VULNERABILITY))
	findings := make([]contract.Finding, maxEmissionRecords/2+1)
	for i := range findings {
		findings[i] = contract.Finding{Name: "record", Severity: contract.SeverityInfo}
	}
	result := contract.FindingResult{Target: a.Targets()[0], Items: findings}
	for i := 0; i < 2; i++ {
		if err := c.PushFindings(context.Background(), a, result); err != nil {
			t.Fatalf("individually valid chunk: %v", err)
		}
	}
	if err := c.PushFindings(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	findings[0] = contract.Finding{}
	err := c.PushFindings(context.Background(), a, result, result)
	if err == nil || !strings.Contains(err.Error(), "100000") || s.count("push") != 2 {
		t.Fatalf("record limit error=%v uploads=%d", err, s.count("push"))
	}
}

func TestGroupEmissionResultsMergesRepeatedTargetsInFirstAppearanceOrder(t *testing.T) {
	job := assignmentJob(pb.Scanner_SCANNER_SERVICE_DISCOVER)
	other := proto.Clone(job.Targets[0]).(*pb.JobTarget)
	other.AssetScanId = ptr("other")
	job.Targets = append(job.Targets, other)
	a := preparedAssignment(t, job)
	targets := a.Targets()
	groups, err := groupEmissionResults(a, []contract.ServiceResult{
		{Target: targets[1], Items: []contract.Service{{Port: 80}}},
		{Target: targets[0], Items: []contract.Service{{Port: 81}}},
		{Target: targets[1], Items: []contract.Service{{Port: 443}}},
	})
	if err != nil || len(groups) != 2 || groups[0].target != other || groups[1].target != job.Targets[0] || len(groups[0].observations) != 2 || groups[0].observations[1].Port != 443 {
		t.Fatalf("groups=%v error=%v", groups, err)
	}
}

func TestPushValidatesEveryTargetBeforeAnyUpload(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			s := &clientTestServer{}
			c := newTestClient(t, s)
			a := preparedAssignment(t, assignmentJob(kind))
			original := a.Targets()[0]
			emit := func(target contract.Target, empty bool) error {
				switch kind {
				case pb.Scanner_SCANNER_SUBDOMAIN:
					record := []contract.DNSRecord{{Domain: "www.example.com"}}
					if empty {
						record = nil
					}
					return c.PushDomains(context.Background(), a, contract.DNSResult{Target: original, Items: record}, contract.DNSResult{Target: target})
				case pb.Scanner_SCANNER_SERVICE_DISCOVER:
					records := []contract.Service{{Port: 443}}
					if empty {
						records = nil
					}
					return c.PushServices(context.Background(), a, contract.ServiceResult{Target: original, Items: records}, contract.ServiceResult{Target: target})
				default:
					records := []contract.Finding{{Name: "finding", Severity: contract.SeverityInfo}}
					if empty {
						records = nil
					}
					return c.PushFindings(context.Background(), a, contract.FindingResult{Target: original, Items: records}, contract.FindingResult{Target: target})
				}
			}
			if err := emit(original, true); err != nil {
				t.Fatalf("valid empty results rejected: %v", err)
			}
			other := preparedAssignment(t, assignmentJob(kind)).Targets()[0]
			for _, target := range []contract.Target{{Domain: original.Domain, Host: original.Host}, other} {
				for _, empty := range []bool{false, true} {
					if err := emit(target, empty); err == nil {
						t.Fatal("invalid target accepted, including empty inner results")
					}
				}
			}
			if s.count("push") != 0 {
				t.Fatal("whole-call validation uploaded a partial request")
			}
		})
	}
}
