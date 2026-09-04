package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	rediver "github.com/redivers/sdk-go"
)

// DNSScanner implements the subdomain example's DNS lookup logic.
type DNSScanner struct{}

var _ rediver.Scanner = (*DNSScanner)(nil)

func (*DNSScanner) Scan(ctx context.Context, targets []rediver.Target, emitter rediver.Emitter) error {
	return scan(ctx, targets, emitter)
}

func main() {
	agent, err := rediver.NewAgent(os.Getenv("REDIVER_TOKEN"), &DNSScanner{})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := agent.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
