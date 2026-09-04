package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	rediver "github.com/redivers/sdk-go"
)

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
			Target:  target,
			Records: []rediver.DNSRecord{{Domain: target.Domain, IPs: ips}},
		}); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	scanner := rediver.ScanFunc(scan)
	agent, err := rediver.NewAgent(os.Getenv("REDIVER_TOKEN"), scanner)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := agent.RunOnce(ctx); err != nil && !errors.Is(err, rediver.ErrNoJobAvailable) {
		log.Fatal(err)
	}
}
