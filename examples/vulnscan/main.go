package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
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

// Scan receives the entire assigned batch. This small example checks targets in
// sequence; a bulk scanning engine can process the whole list in one call.
func scan(ctx context.Context, targets []rediver.Target, emitter rediver.Emitter) error {
	results := make([]rediver.FindingResult, 0, len(targets))
	for _, target := range targets {
		finding, err := scanCertificate(ctx, target)
		if err != nil {
			return err
		}
		result := rediver.FindingResult{Target: target}
		if finding != nil {
			result.Items = []rediver.Finding{*finding}
		}
		results = append(results, result)
	}
	// Include every target. An empty Items slice is a successful scan with no
	// findings. A bulk engine can supply several findings in each inner slice.
	return emitter.EmitFindings(results...)
}

// This check inspects certificate expiry on HTTPS targets only.
func scanCertificate(ctx context.Context, target rediver.Target) (*rediver.Finding, error) {
	endpoint := target.URL
	if endpoint == "" && target.Port == 443 {
		endpoint = "https://" + net.JoinHostPort(target.Host, "443")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, nil
	}
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		// Inspect the presented certificate even when it is expired.
		// This scanner sends no credentials or application data.
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: target.Host},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	if err != nil {
		return nil, err
	}
	state := conn.(*tls.Conn).ConnectionState()
	_ = conn.Close()
	if len(state.PeerCertificates) == 0 || !time.Now().After(state.PeerCertificates[0].NotAfter) {
		return nil, nil
	}
	cert := state.PeerCertificates[0]
	return &rediver.Finding{
		Name: "Expired TLS certificate", Severity: rediver.SeverityMedium,
		RuleID: "tls-certificate-expired", Endpoint: endpoint,
		Description: fmt.Sprintf("Certificate expired at %s.", cert.NotAfter.UTC().Format(time.RFC3339)),
		Remediation: "Renew and deploy a valid TLS certificate.",
	}, nil
}
