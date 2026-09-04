package main

import (
	"context"
	"errors"
	"fmt"
	"net"

	rediver "github.com/redivers/sdk-go"
)

// scan resolves every assigned domain. NXDOMAIN completes the target without
// observations because there is no DNS result to report.
func scan(ctx context.Context, targets []rediver.Target, emitter rediver.Emitter) error {
	for _, target := range targets {
		ips, err := net.DefaultResolver.LookupHost(ctx, target.Domain)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue
			}
			return fmt.Errorf("resolve %s: %w", target.Domain, err)
		}
		if err := emitter.EmitDomains(rediver.DNSResult{
			Target: target,
			Items:  []rediver.DNSRecord{{Domain: target.Domain, IPs: ips}},
		}); err != nil {
			return err
		}
	}
	return nil
}
