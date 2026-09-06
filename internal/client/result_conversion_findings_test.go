package client

import (
	"math"
	"testing"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
)

func TestToProtoFindingsPreservesAllFieldsAndCopiesResults(t *testing.T) {
	score := 0.0
	findings := []contract.Finding{{
		Name: "finding", Description: "description", Category: "category", Remediation: "fix", Severity: contract.SeverityHigh,
		CVE: "CVE-2026-12345", CWEs: []string{"CWE-79"}, References: []string{"https://example.com/ref"},
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", CVSSScore: &score,
		RuleID: "rule", Endpoint: "https://example.com/path", CurlCommand: "curl https://example.com/path",
		Requests: []contract.RawHTTPRequest{{Request: "GET /path HTTP/1.1", Response: "HTTP/1.1 200 OK", Param: "param", Payload: "payload"}},
	}}
	want := &pb.Finding{
		Name: "finding", Description: ptr("description"), Category: ptr("category"), Remediation: ptr("fix"),
		Severity: pb.FindingSeverity_FINDING_SEVERITY_HIGH, Cve: ptr("CVE-2026-12345"), Cwes: []string{"CWE-79"},
		References: []string{"https://example.com/ref"}, CvssVector: ptr("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
		CvssScore: ptr(float32(0)), RuleId: ptr("rule"), Endpoint: ptr("https://example.com/path"), CurlCommand: ptr("curl https://example.com/path"),
		Requests: []*pb.RawHttpRequest{{Request: "GET /path HTTP/1.1", Response: "HTTP/1.1 200 OK", Param: ptr("param"), Payload: ptr("payload")}},
	}
	got, err := toProtoFindings(findings)
	if err != nil || len(got) != 1 || !proto.Equal(got[0], want) {
		t.Fatalf("converted = %v, error = %v; want %v", got, err, want)
	}
	if findings[0].CVSSScore != &score || findings[0].Name != "finding" {
		t.Fatal("conversion mutated handler result")
	}
	findings[0].CWEs[0], findings[0].References[0], findings[0].Requests[0].Request = "changed", "changed", "changed"
	score = 10
	if !proto.Equal(got[0], want) {
		t.Fatalf("converted finding retained mutable handler data: %v", got[0])
	}
}

func TestToProtoFindingsMapsSeverityAndOmitsUnknownFields(t *testing.T) {
	for severity, wire := range map[contract.FindingSeverity]pb.FindingSeverity{
		contract.SeverityInfo: pb.FindingSeverity_FINDING_SEVERITY_INFO, contract.SeverityLow: pb.FindingSeverity_FINDING_SEVERITY_LOW,
		contract.SeverityMedium: pb.FindingSeverity_FINDING_SEVERITY_MEDIUM, contract.SeverityHigh: pb.FindingSeverity_FINDING_SEVERITY_HIGH,
		contract.SeverityCritical: pb.FindingSeverity_FINDING_SEVERITY_CRITICAL,
	} {
		t.Run(string(severity), func(t *testing.T) {
			got, err := toProtoFindings([]contract.Finding{{Severity: severity}})
			if err != nil || len(got) != 1 || !proto.Equal(got[0], &pb.Finding{Severity: wire}) {
				t.Fatalf("severity/presence changed: %v, %v", got, err)
			}
		})
	}
	if got, err := toProtoFindings(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty successful results rejected: %v, %v", got, err)
	}
	for _, score := range []float64{0, 4.7, 10} {
		got, err := toProtoFindings([]contract.Finding{{Severity: contract.SeverityInfo, CVSSScore: &score}})
		if err != nil || got[0].CvssScore == nil || *got[0].CvssScore != float32(score) {
			t.Fatalf("valid score %v was not preserved: %v, %v", score, got, err)
		}
	}
}

func TestToProtoFindingsRejectsUnknownSeverityAndInvalidScores(t *testing.T) {
	for _, severity := range []contract.FindingSeverity{contract.SeverityUnspecified, "none", "HIGH", "future"} {
		if got, err := toProtoFindings([]contract.Finding{{Severity: severity}}); err == nil || got != nil {
			t.Fatalf("unsupported severity %q accepted: %v, %v", severity, got, err)
		}
	}
	for _, score := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.1, 10.1, math.MaxFloat64} {
		if got, err := toProtoFindings([]contract.Finding{{Severity: contract.SeverityInfo, CVSSScore: &score}}); err == nil || got != nil {
			t.Fatalf("invalid score %v accepted: %v, %v", score, got, err)
		}
	}
}
