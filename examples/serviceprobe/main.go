package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	rediver "github.com/redivers/sdk-go"
)

func main() {
	agent, err := rediver.NewAgent(os.Getenv("REDIVER_TOKEN"),
		rediver.ScanFunc(scan))
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := agent.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func scan(ctx context.Context, targets []rediver.Target, emitter rediver.Emitter) error {
	if len(targets) == 0 {
		return nil
	}
	// The SDK validates and expands the assigned ports. Rate is the budget for
	// the whole batch, so every target shares this limiter. A bulk engine can
	// instead receive all targets and the batch rate in one invocation.
	interval := max(time.Nanosecond, time.Second/time.Duration(targets[0].Rate))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	dialer := net.Dialer{Timeout: 2 * time.Second}
	for _, target := range targets {
		for _, port := range target.Ports {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(port)))
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			conn.Close()
			// Host defaults to the assigned target's host when omitted.
			if err := emitter.EmitServices(rediver.ServiceResult{
				Target: target,
				Items:  []rediver.Service{{Port: port, Transport: "tcp"}},
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
