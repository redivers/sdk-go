package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
)

func (c *Client) PushDomains(ctx context.Context, a *Assignment, results ...contract.DNSResult) error {
	if err := a.validatePush(pb.Scanner_SCANNER_SUBDOMAIN); err != nil {
		return err
	}
	groups, err := groupEmissionResults(a, results, func(result contract.DNSResult) (contract.Target, []contract.DNSRecord) {
		return result.Target, result.Records
	})
	if err != nil || len(groups) == 0 {
		return err
	}
	wire := make([]*pb.DomainResult, 0, len(groups))
	for index, group := range groups {
		records, err := toProtoDNSRecords(group.target.GetDomain(), group.observations)
		if err != nil {
			return fmt.Errorf("target %d: %w", index, err)
		}
		wire = append(wire, &pb.DomainResult{Target: group.target, Domains: records})
	}
	request := &pb.PushDomainsRequest{JobId: a.job.JobId, RunId: a.job.RunId, Results: wire}
	if err := checkEmissionSize(request); err != nil {
		return err
	}
	client := c.rpc
	return c.upload(ctx, func(ctx context.Context, key string) (bool, error) {
		response, err := client.PushDomains(ctx, pushRequest(request, key))
		return response != nil && response.Msg.GetSuccess(), err
	})
}

func (c *Client) PushServices(ctx context.Context, a *Assignment, results ...contract.ServiceResult) error {
	if err := a.validatePush(pb.Scanner_SCANNER_SERVICE_DISCOVER); err != nil {
		return err
	}
	groups, err := groupEmissionResults(a, results, func(result contract.ServiceResult) (contract.Target, []contract.Service) {
		return result.Target, result.Services
	})
	if err != nil || len(groups) == 0 {
		return err
	}
	wire := make([]*pb.ServiceResult, 0, len(groups))
	for index, group := range groups {
		services, err := toProtoServices(group.target.GetHost(), group.observations)
		if err != nil {
			return fmt.Errorf("target %d: %w", index, err)
		}
		wire = append(wire, &pb.ServiceResult{Target: group.target, Services: services})
	}
	request := &pb.PushServicesRequest{JobId: a.job.JobId, RunId: a.job.RunId, Results: wire}
	if err := checkEmissionSize(request); err != nil {
		return err
	}
	client := c.rpc
	return c.upload(ctx, func(ctx context.Context, key string) (bool, error) {
		response, err := client.PushServices(ctx, pushRequest(request, key))
		return response != nil && response.Msg.GetSuccess(), err
	})
}

func (c *Client) PushFindings(ctx context.Context, a *Assignment, results ...contract.FindingResult) error {
	if err := a.validatePush(pb.Scanner_SCANNER_VULNERABILITY); err != nil {
		return err
	}
	groups, err := groupEmissionResults(a, results, func(result contract.FindingResult) (contract.Target, []contract.Finding) {
		return result.Target, result.Findings
	})
	if err != nil || len(groups) == 0 {
		return err
	}
	wire := make([]*pb.FindingResult, 0, len(groups))
	for index, group := range groups {
		findings, err := toProtoFindings(group.observations)
		if err != nil {
			return fmt.Errorf("target %d: %w", index, err)
		}
		wire = append(wire, &pb.FindingResult{Target: group.target, Findings: findings})
	}
	request := &pb.PushFindingsRequest{JobId: a.job.JobId, RunId: a.job.RunId, Results: wire}
	if err := checkEmissionSize(request); err != nil {
		return err
	}
	client := c.rpc
	return c.upload(ctx, func(ctx context.Context, key string) (bool, error) {
		response, err := client.PushFindings(ctx, pushRequest(request, key))
		return response != nil && response.Msg.GetSuccess(), err
	})
}

func checkEmissionSize(request proto.Message) error {
	if proto.Size(request) > maxEmissionBytes {
		return fmt.Errorf("rediver: results exceed the per-call limit (64 MiB encoded request)")
	}
	return nil
}

// A converted request and its fresh key remain fixed across transport retries.
func (c *Client) upload(ctx context.Context, push func(context.Context, string) (bool, error)) error {
	key := newPushIdempotencyKey()
	return c.retry(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		success, err := push(ctx, key)
		if err != nil {
			return err
		}
		if !success {
			return fmt.Errorf("server rejected result acknowledgement")
		}
		return nil
	})
}
func newPushIdempotencyKey() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(fmt.Sprintf("generate result request ID: %v", err))
	}
	return hex.EncodeToString(value[:])
}

func pushRequest[T any](message *T, key string) *connect.Request[T] {
	request := connect.NewRequest(message)
	request.Header().Set("Idempotency-Key", key)
	return request
}
