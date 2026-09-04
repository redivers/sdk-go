package rediver_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	rediver "github.com/redivers/sdk-go"
)

// Consumers can test scanners by supplying an emitter without a backend agent.
type recordingEmitter struct {
	domains  []rediver.DNSResult
	services []rediver.ServiceResult
	findings []rediver.FindingResult
	err      error
}

var _ rediver.Emitter = (*recordingEmitter)(nil)

func (e *recordingEmitter) EmitDomains(results ...rediver.DNSResult) error {
	e.domains = append(e.domains, results...)
	return e.err
}

func (e *recordingEmitter) EmitServices(results ...rediver.ServiceResult) error {
	e.services = append(e.services, results...)
	return e.err
}

func (e *recordingEmitter) EmitFindings(results ...rediver.FindingResult) error {
	e.findings = append(e.findings, results...)
	return e.err
}

func TestScannerWithConsumerEmitter(t *testing.T) {
	targets := []rediver.Target{
		{Domain: "one.example", Host: "192.0.2.1", Ports: []int{443}},
		{Domain: "two.example", Host: "192.0.2.2", Port: 8443},
	}
	for _, tc := range []struct {
		name string
		scan rediver.ScanFunc
		want recordingEmitter
	}{
		{
			name: "domain",
			scan: func(_ context.Context, targets []rediver.Target, emit rediver.Emitter) error {
				return emit.EmitDomains(
					rediver.DNSResult{Target: targets[0], Records: []rediver.DNSRecord{{Domain: targets[0].Domain}}},
					rediver.DNSResult{Target: targets[1], Records: []rediver.DNSRecord{{Domain: targets[1].Domain}}},
				)
			},
			want: recordingEmitter{domains: []rediver.DNSResult{
				{Target: targets[0], Records: []rediver.DNSRecord{{Domain: "one.example"}}},
				{Target: targets[1], Records: []rediver.DNSRecord{{Domain: "two.example"}}},
			}},
		},
		{
			name: "service",
			scan: func(_ context.Context, targets []rediver.Target, emit rediver.Emitter) error {
				results := []rediver.ServiceResult{
					{Target: targets[0], Services: []rediver.Service{{Host: targets[0].Host, Port: targets[0].Ports[0]}}},
					{Target: targets[1], Services: []rediver.Service{{Host: targets[1].Host, Port: targets[1].Port}}},
				}
				return emit.EmitServices(results...)
			},
			want: recordingEmitter{services: []rediver.ServiceResult{
				{Target: targets[0], Services: []rediver.Service{{Host: "192.0.2.1", Port: 443}}},
				{Target: targets[1], Services: []rediver.Service{{Host: "192.0.2.2", Port: 8443}}},
			}},
		},
		{
			name: "finding",
			scan: func(_ context.Context, targets []rediver.Target, emit rediver.Emitter) error {
				return emit.EmitFindings(rediver.FindingResult{Target: targets[1], Findings: []rediver.Finding{
					{Name: "Expired certificate", Severity: rediver.SeverityMedium},
					{Name: "Weak cipher", Severity: rediver.SeverityLow},
				}})
			},
			want: recordingEmitter{findings: []rediver.FindingResult{
				{Target: targets[1], Findings: []rediver.Finding{
					{Name: "Expired certificate", Severity: rediver.SeverityMedium},
					{Name: "Weak cipher", Severity: rediver.SeverityLow},
				}},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, impl := range []struct {
				name    string
				scanner rediver.Scanner
			}{
				{"function", tc.scan},
				{"custom", &customScanner{scan: tc.scan}},
			} {
				t.Run(impl.name, func(t *testing.T) {
					var emit recordingEmitter
					if err := impl.scanner.Scan(context.Background(), targets, &emit); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(emit, tc.want) {
						t.Fatalf("recorded payloads = %#v, want %#v", emit, tc.want)
					}

					emitErr := errors.New("consumer emitter failed")
					failing := &recordingEmitter{err: emitErr}
					if err := impl.scanner.Scan(context.Background(), targets, failing); !errors.Is(err, emitErr) {
						t.Fatalf("emitter error = %v, want %v", err, emitErr)
					}
				})
			}
		})
	}
}
