package client

import (
	"fmt"
	"math"
	"slices"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
)

func toProtoFindings(findings []contract.Finding) ([]*pb.Finding, error) {
	converted := make([]*pb.Finding, 0, len(findings))
	for index, finding := range findings {
		severity, err := toProtoSeverity(finding.Severity)
		if err != nil {
			return nil, fmt.Errorf("rediver: finding %d: %w", index, err)
		}
		out := &pb.Finding{
			Name: finding.Name, Severity: severity,
			Description: optionalResultString(finding.Description), Category: optionalResultString(finding.Category),
			Remediation: optionalResultString(finding.Remediation), Cve: optionalResultString(finding.CVE),
			Cwes: slices.Clone(finding.CWEs), References: slices.Clone(finding.References),
			CvssVector: optionalResultString(finding.CVSSVector), RuleId: optionalResultString(finding.RuleID),
			Endpoint: optionalResultString(finding.Endpoint), CurlCommand: optionalResultString(finding.CurlCommand),
			Requests: make([]*pb.RawHttpRequest, 0, len(finding.Requests)),
		}
		if finding.CVSSScore != nil {
			score := *finding.CVSSScore
			if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 10 {
				return nil, fmt.Errorf("rediver: finding %d: CVSS score must be finite and between 0 and 10", index)
			}
			wireScore := float32(score)
			out.CvssScore = &wireScore
		}
		for _, request := range finding.Requests {
			out.Requests = append(out.Requests, &pb.RawHttpRequest{
				Request: request.Request, Response: request.Response,
				Param: optionalResultString(request.Param), Payload: optionalResultString(request.Payload),
			})
		}
		converted = append(converted, out)
	}
	return converted, nil
}

func toProtoSeverity(severity contract.FindingSeverity) (pb.FindingSeverity, error) {
	switch severity {
	case contract.SeverityInfo:
		return pb.FindingSeverity_FINDING_SEVERITY_INFO, nil
	case contract.SeverityLow:
		return pb.FindingSeverity_FINDING_SEVERITY_LOW, nil
	case contract.SeverityMedium:
		return pb.FindingSeverity_FINDING_SEVERITY_MEDIUM, nil
	case contract.SeverityHigh:
		return pb.FindingSeverity_FINDING_SEVERITY_HIGH, nil
	case contract.SeverityCritical:
		return pb.FindingSeverity_FINDING_SEVERITY_CRITICAL, nil
	default:
		return pb.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED, fmt.Errorf("rediver: unsupported finding severity %q", severity)
	}
}
