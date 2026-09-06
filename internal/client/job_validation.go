package client

import (
	"fmt"
	"strings"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
)

func validScannerKind(kind pb.Scanner) bool {
	return kind == pb.Scanner_SCANNER_SUBDOMAIN || kind == pb.Scanner_SCANNER_SERVICE_DISCOVER || kind == pb.Scanner_SCANNER_VULNERABILITY
}

func validateJob(job *pb.Job) error {
	if job == nil || strings.TrimSpace(job.GetJobId()) == "" || strings.TrimSpace(job.GetRunId()) == "" {
		return fmt.Errorf("%w: job ID and run ID are required", contract.ErrInvalidJob)
	}
	if !validScannerKind(job.Scanner) {
		return fmt.Errorf("%w: unsupported job scanner %v", contract.ErrInvalidJob, job.Scanner)
	}
	if len(job.Targets) == 0 {
		return fmt.Errorf("%w: at least one target is required", contract.ErrInvalidJob)
	}
	seen := make(map[string]struct{}, len(job.Targets))
	for i, target := range job.Targets {
		if target == nil {
			return fmt.Errorf("%w: target %d is nil", contract.ErrInvalidJob, i)
		}
		assetScanID := target.GetAssetScanId()
		if strings.TrimSpace(assetScanID) == "" {
			return fmt.Errorf("%w: target %d requires an asset scan ID", contract.ErrInvalidJob, i)
		}
		// The required asset scan ID is part of the full target, so unique IDs
		// also ensure no full target can appear twice.
		if _, duplicate := seen[assetScanID]; duplicate {
			return fmt.Errorf("%w: target %d repeats asset scan ID %q", contract.ErrInvalidJob, i, assetScanID)
		}
		seen[assetScanID] = struct{}{}
		if target.Port != nil && (*target.Port < 1 || *target.Port > 65535) {
			return fmt.Errorf("%w: target %d port must be between 1 and 65535", contract.ErrInvalidJob, i)
		}
		switch job.Scanner {
		case pb.Scanner_SCANNER_SUBDOMAIN:
			if strings.TrimSpace(target.GetDomain()) == "" {
				return fmt.Errorf("%w: target %d requires a domain", contract.ErrInvalidJob, i)
			}
		case pb.Scanner_SCANNER_SERVICE_DISCOVER, pb.Scanner_SCANNER_VULNERABILITY:
			if strings.TrimSpace(target.GetHost()) == "" {
				return fmt.Errorf("%w: target %d requires a host", contract.ErrInvalidJob, i)
			}
			if job.Scanner == pb.Scanner_SCANNER_VULNERABILITY && target.Port == nil {
				return fmt.Errorf("%w: target %d requires a port", contract.ErrInvalidJob, i)
			}
		}
	}
	return validateJobOptions(job)
}

func validateJobOptions(job *pb.Job) error {
	var kind pb.Scanner
	switch value := job.Options.GetValue().(type) {
	case nil:
		return nil
	case *pb.JobOptions_Subdomain:
		if value != nil {
			kind = pb.Scanner_SCANNER_SUBDOMAIN
		}
	case *pb.JobOptions_ServiceDiscover:
		if value != nil {
			kind = pb.Scanner_SCANNER_SERVICE_DISCOVER
		}
	case *pb.JobOptions_Vulnerability:
		if value != nil {
			kind = pb.Scanner_SCANNER_VULNERABILITY
		}
	}
	if kind != job.Scanner {
		return fmt.Errorf("%w: options must match job scanner %v", contract.ErrInvalidJob, job.Scanner)
	}
	return nil
}
