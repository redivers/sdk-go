package client

import (
	"context"
	"testing"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
)

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

func TestGroupEmissionResultsKeepsEmptyWrappersInFirstAppearanceOrder(t *testing.T) {
	job := assignmentJob(pb.Scanner_SCANNER_SERVICE_DISCOVER)
	other := proto.Clone(job.Targets[0]).(*pb.JobTarget)
	other.AssetScanId = ptr("other")
	job.Targets = append(job.Targets, other)
	a := preparedAssignment(t, job)
	targets := a.Targets()

	groups, err := groupEmissionResults(a, []contract.ServiceResult{
		{Target: targets[1], Items: []contract.Service{}},
		{Target: targets[0]},
		{Target: targets[1]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].target != other || groups[1].target != job.Targets[0] {
		t.Fatalf("empty groups = %v", groups)
	}
	for _, group := range groups {
		if len(group.observations) != 0 || group.errorMessage != nil {
			t.Fatalf("empty group contains an outcome: %v", group)
		}
	}
}

func TestGroupEmissionResultsRejectsObservationErrorConflicts(t *testing.T) {
	a := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_SERVICE_DISCOVER))
	target := a.Targets()[0]
	message := "probe failed"
	for _, tc := range []struct {
		name    string
		results []contract.ServiceResult
	}{
		{
			name: "same wrapper",
			results: []contract.ServiceResult{{
				Target: target, Items: []contract.Service{{Port: 443}}, ErrorMessage: &message,
			}},
		},
		{
			name: "split wrappers",
			results: []contract.ServiceResult{
				{Target: target, Items: []contract.Service{{Port: 443}}},
				{Target: target, ErrorMessage: &message},
			},
		},
		{
			name: "split wrappers error first",
			results: []contract.ServiceResult{
				{Target: target, ErrorMessage: &message},
				{Target: target, Items: []contract.Service{{Port: 443}}},
			},
		},
		{
			name: "multiple error wrappers",
			results: []contract.ServiceResult{
				{Target: target, ErrorMessage: &message},
				{Target: target, ErrorMessage: ptr("")},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groups, err := groupEmissionResults(a, tc.results)
			if err == nil {
				t.Fatalf("conflicting results accepted: %v", groups)
			}
		})
	}
}

func TestGroupEmissionResultsAllowsEmptyWrappersWithErrorMessage(t *testing.T) {
	a := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_SERVICE_DISCOVER))
	target := a.Targets()[0]
	message := "probe failed"

	groups, err := groupEmissionResults(a, []contract.ServiceResult{
		{Target: target},
		{Target: target, ErrorMessage: &message},
		{Target: target, Items: []contract.Service{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].errorMessage == nil || *groups[0].errorMessage != message || len(groups[0].observations) != 0 {
		t.Fatalf("group = %v", groups)
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
