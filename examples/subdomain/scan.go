package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	rediver "github.com/redivers/sdk-go"
)

// scan resolves every assigned domain and reports NXDOMAIN as a final target
// error.
func scan(ctx context.Context, targets []rediver.Target, emitter rediver.Emitter) error {
	for _, target := range targets {
		ips, err := net.DefaultResolver.LookupHost(ctx, target.Domain)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				if emitErr := emitter.EmitDomains(rediver.DNSResult{
					Target:       target,
					ErrorMessage: rediver.Ptr(dnsErr.Error()),
				}); emitErr != nil {
					return emitErr
				}
				continue
			}
			return fmt.Errorf("resolve %s: %w", target.Domain, err)
		}
		record := rediver.DNSRecord{Domain: target.Domain}
		for _, address := range ips {
			ip, err := netip.ParseAddr(address)
			if err != nil {
				return fmt.Errorf("parse address for %s: %w", target.Domain, err)
			}
			if ip.Is4() {
				record.A = append(record.A, address)
			} else {
				record.AAAA = append(record.AAAA, address)
			}
		}
		if err := emitter.EmitDomains(rediver.DNSResult{
			Target: target,
			Items:  []rediver.DNSRecord{record},
		}); err != nil {
			return err
		}
	}
	return nil
}
