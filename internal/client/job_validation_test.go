package client

import (
	"errors"
	"testing"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
)

func validationJob(kind pb.Scanner) *pb.Job {
	target := &pb.JobTarget{AssetScanId: ptr("asset-1")}
	switch kind {
	case pb.Scanner_SCANNER_SUBDOMAIN:
		target.Domain = ptr("example.com")
	case pb.Scanner_SCANNER_SERVICE_DISCOVER:
		target.Host = ptr("192.0.2.1")
	case pb.Scanner_SCANNER_VULNERABILITY:
		target.Host, target.Port = ptr("example.com"), ptr(int32(443))
	}
	return &pb.Job{JobId: "job-1", RunId: "run-1", Scanner: kind, Targets: []*pb.JobTarget{target}}
}

func TestValidateJobRejectsMalformedJobs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*pb.Job)
	}{
		{"missing job ID", func(j *pb.Job) { j.JobId = "" }},
		{"blank job ID", func(j *pb.Job) { j.JobId = " \t" }},
		{"missing run ID", func(j *pb.Job) { j.RunId = "" }},
		{"blank run ID", func(j *pb.Job) { j.RunId = "\n" }},
		{"unspecified scanner", func(j *pb.Job) { j.Scanner = 0 }},
		{"unknown scanner", func(j *pb.Job) { j.Scanner = 99 }},
		{"scanner target fields mismatch", func(j *pb.Job) { j.Scanner = pb.Scanner_SCANNER_SERVICE_DISCOVER }},
		{"missing targets", func(j *pb.Job) { j.Targets = nil }},
		{"empty targets", func(j *pb.Job) { j.Targets = []*pb.JobTarget{} }},
		{"nil target", func(j *pb.Job) { j.Targets = append(j.Targets, nil) }},
		{"missing asset scan ID", func(j *pb.Job) { j.Targets[0].AssetScanId = nil }},
		{"empty asset scan ID", func(j *pb.Job) { j.Targets[0].AssetScanId = ptr("") }},
		{"blank asset scan ID", func(j *pb.Job) { j.Targets[0].AssetScanId = ptr(" ") }},
		{"duplicate full target", func(j *pb.Job) { j.Targets = append(j.Targets, proto.Clone(j.Targets[0]).(*pb.JobTarget)) }},
		{"duplicate asset scan ID", func(j *pb.Job) {
			j.Targets = append(j.Targets, &pb.JobTarget{AssetScanId: ptr("asset-1"), Domain: ptr("other.example.com")})
		}},
		{"missing domain", func(j *pb.Job) { j.Targets[0].Domain = nil }},
		{"empty domain", func(j *pb.Job) { j.Targets[0].Domain = ptr("") }},
		{"blank domain", func(j *pb.Job) { j.Targets[0].Domain = ptr(" \t") }},
		{"zero optional port", func(j *pb.Job) { j.Targets[0].Port = ptr(int32(0)) }},
		{"negative optional port", func(j *pb.Job) { j.Targets[0].Port = ptr(int32(-1)) }},
		{"high optional port", func(j *pb.Job) { j.Targets[0].Port = ptr(int32(65536)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := validationJob(pb.Scanner_SCANNER_SUBDOMAIN)
			tt.mutate(job)
			if err := validateJob(job); !errors.Is(err, contract.ErrInvalidJob) {
				t.Fatalf("error = %v, want contract.ErrInvalidJob", err)
			}
		})
	}
	if err := validateJob(nil); !errors.Is(err, contract.ErrInvalidJob) {
		t.Fatalf("nil job error = %v, want contract.ErrInvalidJob", err)
	}
}

func TestValidateJobScannerTargetRequirements(t *testing.T) {
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		t.Run(kind.String(), func(t *testing.T) {
			job := validationJob(kind)
			if err := validateJob(job); err != nil {
				t.Fatalf("valid job rejected: %v", err)
			}
			if kind == pb.Scanner_SCANNER_SUBDOMAIN {
				return
			}
			for _, host := range []*string{nil, ptr(""), ptr("\t")} {
				invalid := proto.Clone(job).(*pb.Job)
				invalid.Targets[0].Host = host
				if err := validateJob(invalid); !errors.Is(err, contract.ErrInvalidJob) {
					t.Fatalf("host %v error = %v, want contract.ErrInvalidJob", host, err)
				}
			}
			if kind == pb.Scanner_SCANNER_VULNERABILITY {
				for _, port := range []*int32{nil, ptr(int32(0)), ptr(int32(-1)), ptr(int32(65536))} {
					invalid := proto.Clone(job).(*pb.Job)
					invalid.Targets[0].Port = port
					if err := validateJob(invalid); !errors.Is(err, contract.ErrInvalidJob) {
						t.Fatalf("port %v error = %v, want contract.ErrInvalidJob", port, err)
					}
				}
			}
		})
	}
}

func TestValidateJobOptionsMatchScanner(t *testing.T) {
	options := []struct {
		kind    pb.Scanner
		options *pb.JobOptions
	}{
		{pb.Scanner_SCANNER_SUBDOMAIN, &pb.JobOptions{Value: &pb.JobOptions_Subdomain{Subdomain: &pb.SubdomainOption{}}}},
		{pb.Scanner_SCANNER_SERVICE_DISCOVER, &pb.JobOptions{Value: &pb.JobOptions_ServiceDiscover{ServiceDiscover: &pb.ServiceDiscoverOption{Ports: "80,443", Rate: 20}}}},
		{pb.Scanner_SCANNER_VULNERABILITY, &pb.JobOptions{Value: &pb.JobOptions_Vulnerability{Vulnerability: &pb.VulnerabilityOption{}}}},
	}
	for _, kind := range []pb.Scanner{pb.Scanner_SCANNER_SUBDOMAIN, pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY} {
		for _, option := range options {
			job := validationJob(kind)
			job.Options = option.options
			err := validateJob(job)
			if option.kind == kind && err != nil {
				t.Errorf("matching %v options rejected: %v", kind, err)
			}
			if option.kind != kind && !errors.Is(err, contract.ErrInvalidJob) {
				t.Errorf("%v job with %v options error = %v, want contract.ErrInvalidJob", kind, option.kind, err)
			}
		}
	}
}

func TestValidateJobOptionsPresence(t *testing.T) {
	for _, options := range []*pb.JobOptions{nil, {}} {
		job := validationJob(pb.Scanner_SCANNER_SUBDOMAIN)
		job.Options = options
		if err := validateJob(job); err != nil {
			t.Fatalf("absent options rejected: %v", err)
		}
	}
	for _, options := range []*pb.JobOptions{
		{Value: (*pb.JobOptions_Subdomain)(nil)},
		{Value: (*pb.JobOptions_ServiceDiscover)(nil)},
		{Value: (*pb.JobOptions_Vulnerability)(nil)},
	} {
		job := validationJob(pb.Scanner_SCANNER_SUBDOMAIN)
		job.Options = options
		if err := validateJob(job); !errors.Is(err, contract.ErrInvalidJob) {
			t.Fatalf("typed nil oneof error = %v, want contract.ErrInvalidJob", err)
		}
	}
}

func TestValidateJobPreservesOptionalPresence(t *testing.T) {
	job := validationJob(pb.Scanner_SCANNER_VULNERABILITY)
	job.JobId, job.RunId = " job-1 ", " run-1 "
	job.Targets[0].Url = ptr("")
	job.Targets[0].Domain = ptr("")
	job.Targets = append(job.Targets, &pb.JobTarget{AssetScanId: ptr("asset-2"), Host: ptr("example.com"), Port: ptr(int32(65535))})
	before := proto.Clone(job)
	if err := validateJob(job); err != nil {
		t.Fatalf("valid optional fields rejected: %v", err)
	}
	if !proto.Equal(job, before) {
		t.Fatal("validation mutated the original job")
	}
	job.Targets[0].Port = ptr(int32(1))
	if err := validateJob(job); err != nil {
		t.Fatalf("minimum valid port rejected: %v", err)
	}
}
