package client

import (
	"context"
	"fmt"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"connectrpc.com/connect"
	"github.com/redivers/sdk-go/internal/contract"
)

func (c *Client) PushDomains(ctx context.Context, a *Assignment, results ...contract.DNSResult) error {
	if err := a.validatePush(pb.Scanner_SCANNER_SUBDOMAIN); err != nil {
		return err
	}
	groups, err := groupEmissionResults(a, results)
	if err != nil || len(groups) == 0 {
		return err
	}
	wire := make([]*pb.DomainResult, 0, len(groups))
	for index, group := range groups {
		var records []*pb.DnsRecord
		if len(group.observations) > 0 {
			records, err = toProtoDNSRecords(group.target.GetDomain(), group.observations)
			if err != nil {
				return fmt.Errorf("target %d: %w", index, err)
			}
		}
		wire = append(wire, &pb.DomainResult{Target: group.target, Domains: records, ErrorMessage: group.errorMessage})
	}
	request := &pb.PushDomainsRequest{JobId: a.job.JobId, RunId: a.job.RunId, Results: wire}
	client := c.rpc
	return c.upload(ctx, func(ctx context.Context) (bool, error) {
		response, err := client.PushDomains(ctx, connect.NewRequest(request))
		return response != nil && response.Msg.GetSuccess(), err
	})
}

func (c *Client) PushServices(ctx context.Context, a *Assignment, results ...contract.ServiceResult) error {
	if err := a.validatePush(pb.Scanner_SCANNER_SERVICE_DISCOVER); err != nil {
		return err
	}
	groups, err := groupEmissionResults(a, results)
	if err != nil || len(groups) == 0 {
		return err
	}
	wire := make([]*pb.ServiceResult, 0, len(groups))
	for index, group := range groups {
		services, err := toProtoServices(group.target.GetHost(), group.observations)
		if err != nil {
			return fmt.Errorf("target %d: %w", index, err)
		}
		wire = append(wire, &pb.ServiceResult{Target: group.target, Services: services, ErrorMessage: group.errorMessage})
	}
	request := &pb.PushServicesRequest{JobId: a.job.JobId, RunId: a.job.RunId, Results: wire}
	client := c.rpc
	return c.upload(ctx, func(ctx context.Context) (bool, error) {
		response, err := client.PushServices(ctx, connect.NewRequest(request))
		return response != nil && response.Msg.GetSuccess(), err
	})
}

func (c *Client) PushFindings(ctx context.Context, a *Assignment, results ...contract.FindingResult) error {
	if err := a.validatePush(pb.Scanner_SCANNER_VULNERABILITY); err != nil {
		return err
	}
	groups, err := groupEmissionResults(a, results)
	if err != nil || len(groups) == 0 {
		return err
	}
	wire := make([]*pb.FindingResult, 0, len(groups))
	for index, group := range groups {
		findings, err := toProtoFindings(group.observations)
		if err != nil {
			return fmt.Errorf("target %d: %w", index, err)
		}
		wire = append(wire, &pb.FindingResult{Target: group.target, Findings: findings, ErrorMessage: group.errorMessage})
	}
	request := &pb.PushFindingsRequest{JobId: a.job.JobId, RunId: a.job.RunId, Results: wire}
	client := c.rpc
	return c.upload(ctx, func(ctx context.Context) (bool, error) {
		response, err := client.PushFindings(ctx, connect.NewRequest(request))
		return response != nil && response.Msg.GetSuccess(), err
	})
}

func (c *Client) upload(ctx context.Context, push func(context.Context) (bool, error)) error {
	return c.retry(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		success, err := push(ctx)
		if err != nil {
			return err
		}
		if !success {
			return fmt.Errorf("server rejected result acknowledgement")
		}
		return nil
	})
}
