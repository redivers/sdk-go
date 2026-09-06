package client

import (
	"errors"
	"reflect"
	"testing"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
)

func assignmentJob(kind pb.Scanner) *pb.Job {
	job := clientTestJob()
	job.Scanner = kind
	job.Options = nil
	job.Targets[0].Domain = ptr("example.com")
	job.Targets[0].Url = ptr("")
	if kind == pb.Scanner_SCANNER_SERVICE_DISCOVER {
		job.Options = &pb.JobOptions{Value: &pb.JobOptions_ServiceDiscover{ServiceDiscover: &pb.ServiceDiscoverOption{Ports: "443,80-81,80", Rate: 20}}}
	}
	if kind == pb.Scanner_SCANNER_VULNERABILITY {
		job.Targets[0].Port = ptr(int32(443))
	}
	return job
}

func preparedAssignment(t *testing.T, job *pb.Job) *Assignment {
	t.Helper()
	if err := validateJob(job); err != nil {
		t.Fatal(err)
	}
	assignment := &Assignment{job: job}
	if err := assignment.PrepareTargets(); err != nil {
		t.Fatal(err)
	}
	return assignment
}

func TestAssignmentPreparesTargetsOnceAndReturnsIndependentCopies(t *testing.T) {
	job := assignmentJob(pb.Scanner_SCANNER_SERVICE_DISCOVER)
	job.Targets = append(job.Targets, &pb.JobTarget{AssetScanId: ptr("second"), Host: ptr("second.example.com")})
	original := proto.Clone(job)
	a := preparedAssignment(t, job)
	first := a.Targets()
	if len(first) != 2 || first[0].Rate != 20 || first[1].Rate != 20 || !reflect.DeepEqual(first[0].Ports, []int{80, 81, 443}) {
		t.Fatalf("inputs = %+v", first)
	}
	copyTarget := first[0]
	first[0].Ports[0] = 9999
	first[0].Domain, first[0].Host, first[0].Port, first[0].URL = "changed", "changed", 7, "changed"
	first[1] = contract.Target{}
	if err := a.PrepareTargets(); err != nil {
		t.Fatal(err)
	}
	second := a.Targets()
	if second[0].Ports[0] != 80 || second[1].Ports[0] != 80 || second[0].Host != "example.com" || second[1].Host != "second.example.com" {
		t.Fatalf("registry mutated through accessor: %+v", second)
	}
	if _, err := a.resolveTarget(copyTarget); err != nil {
		t.Fatalf("original reference changed during repeated preparation: %v", err)
	}
	if _, err := a.resolveTarget(second[0]); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(job, original) {
		t.Fatal("scanner values mutated original wire target/options")
	}
}

func TestAssignmentRejectsFabricatedAndForeignReferences(t *testing.T) {
	first := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_SUBDOMAIN))
	second := preparedAssignment(t, assignmentJob(pb.Scanner_SCANNER_SUBDOMAIN))
	for _, target := range []contract.Target{{Domain: "example.com"}, second.Targets()[0], contract.BindTarget(contract.Target{}, -1), contract.BindTarget(contract.Target{}, 100)} {
		if _, err := first.resolveTarget(target); err == nil {
			t.Fatalf("foreign reference accepted: %+v", target)
		}
	}
}

func TestAssignmentRejectsInvalidServiceOptionsAtPreparation(t *testing.T) {
	for _, variant := range []string{"missing", "ports", "rate"} {
		t.Run(variant, func(t *testing.T) {
			job := assignmentJob(pb.Scanner_SCANNER_SERVICE_DISCOVER)
			switch variant {
			case "missing":
				job.Options = nil
			case "ports":
				job.Options.GetServiceDiscover().Ports = "80-"
			case "rate":
				job.Options.GetServiceDiscover().Rate = 0
			}
			if err := validateJob(job); err != nil {
				t.Fatalf("option decoding moved before Start: %v", err)
			}
			a := &Assignment{job: job}
			err := a.PrepareTargets()
			if !errors.Is(err, contract.ErrInvalidJob) || len(a.Targets()) != 0 {
				t.Fatalf("invalid options prepared: %v", err)
			}
			if again := a.PrepareTargets(); again != err {
				t.Fatalf("preparation result was regenerated: %v", again)
			}
		})
	}
}
