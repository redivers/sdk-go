package rediver_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	rediver "github.com/redivers/sdk-go"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func consumerScanner() rediver.Scanner {
	return rediver.ScanFunc(func(context.Context, []rediver.Target, rediver.Emitter) error { return nil })
}

func TestAgentConstructorValidatesWithoutNetwork(t *testing.T) {
	t.Setenv("REDIVER_TOKEN", "")
	var requests atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("constructor contacted the server")
	})}
	var typedNil *customScanner
	for _, tc := range []struct {
		name    string
		token   string
		scanner rediver.Scanner
		options []rediver.Option
		invalid bool
	}{
		{"valid", "token", consumerScanner(), nil, false},
		{"missing token", "", consumerScanner(), nil, true},
		{"blank token", " \t ", consumerScanner(), nil, true},
		{"newline token", "token\nvalue", consumerScanner(), nil, true},
		{"carriage return token", "token\rvalue", consumerScanner(), nil, true},
		{"NUL token", "token\x00value", consumerScanner(), nil, true},
		{"control token", "token\x01value", consumerScanner(), nil, true},
		{"DEL token", "token\x7fvalue", consumerScanner(), nil, true},
		{"nil scanner", "token", nil, nil, true},
		{"typed nil scanner", "token", typedNil, nil, true},
		{"nil function", "token", rediver.ScanFunc(nil), nil, true},
		{"nil option", "token", consumerScanner(), []rediver.Option{nil}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := []rediver.Option{rediver.WithServerURL("https://sdk.example"), rediver.WithHTTPClient(client)}
			agent, err := rediver.NewAgent(tc.token, tc.scanner, append(options, tc.options...)...)
			if tc.invalid {
				if agent != nil || !errors.Is(err, rediver.ErrInvalidConfig) {
					t.Fatalf("invalid constructor input: agent=%v, error=%v", agent != nil, err)
				}
			} else if agent == nil || err != nil {
				t.Fatalf("valid constructor input: agent=%v, error=%v", agent != nil, err)
			}
		})
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("constructor made %d network requests", got)
	}
}

func TestAgentTokenEnvironmentAndExplicitPrecedence(t *testing.T) {
	t.Setenv("REDIVER_TOKEN", "environment-token")
	for _, tc := range []struct{ name, token, want string }{
		{"environment fallback", "", "environment-token"},
		{"explicit override", "explicit-token", "explicit-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transportErr := errors.New("transport stopped")
			var requests atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests.Add(1)
				if got := r.Header.Values("X-Token"); !slices.Equal(got, []string{tc.want}) {
					t.Errorf("X-Token values = %q, want %q", got, tc.want)
				}
				if got := r.Header.Values("Authorization"); len(got) != 0 {
					t.Errorf("unexpected Authorization values: %q", got)
				}
				return nil, transportErr
			})}
			agent, err := rediver.NewAgent(tc.token, consumerScanner(), rediver.WithServerURL("https://sdk.example"), rediver.WithHTTPClient(client), rediver.WithNoRetry())
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.RunOnce(context.Background()); !errors.Is(err, transportErr) {
				t.Fatalf("RunOnce lost transport cause: %v", err)
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("request count = %d, want 1", got)
			}
		})
	}
}

func TestAgentLifecycleMethodsForwardErrorsAndRemainOneShot(t *testing.T) {
	for _, method := range []string{"Run", "RunOnce"} {
		t.Run(method, func(t *testing.T) {
			transportErr := errors.New("transport failed")
			var requests atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, transportErr
			})}
			agent, err := rediver.NewAgent("token", consumerScanner(), rediver.WithServerURL("https://sdk.example"), rediver.WithHTTPClient(client), rediver.WithRunnerID("candidate-runner"), rediver.WithNoRetry())
			if err != nil {
				t.Fatal(err)
			}
			if got := agent.RunnerID(); got != "candidate-runner" {
				t.Fatalf("RunnerID = %q, want candidate-runner", got)
			}
			methods := map[string]func(context.Context) error{"Run": agent.Run, "RunOnce": agent.RunOnce}
			if err := methods[method](context.Background()); !errors.Is(err, transportErr) {
				t.Fatalf("%s lost transport cause: %v", method, err)
			}
			for name, run := range methods {
				if err := run(context.Background()); !errors.Is(err, rediver.ErrAlreadyRunning) {
					t.Errorf("%s after first lifecycle = %v, want ErrAlreadyRunning", name, err)
				}
			}
			agent.Stop()
			agent.Stop()
			if got := requests.Load(); got != 1 {
				t.Fatalf("request count = %d, want 1", got)
			}
		})
	}
}

func TestAgentStopAndCancellationReachActiveLifecycle(t *testing.T) {
	for _, method := range []string{"Run", "RunOnce"} {
		for _, stop := range []bool{false, true} {
			name := method + "/cancel"
			if stop {
				name = method + "/Stop"
			}
			t.Run(name, func(t *testing.T) {
				started := make(chan struct{})
				client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					close(started)
					<-r.Context().Done()
					return nil, r.Context().Err()
				})}
				agent, err := rediver.NewAgent("token", consumerScanner(), rediver.WithServerURL("https://sdk.example"), rediver.WithHTTPClient(client), rediver.WithNoRetry())
				if err != nil {
					t.Fatal(err)
				}
				defer agent.Stop()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				run := agent.Run
				if method == "RunOnce" {
					run = agent.RunOnce
				}
				done := make(chan error, 1)
				go func() { done <- run(ctx) }()
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("lifecycle did not reach the HTTP client")
				}
				if err := agent.RunOnce(context.Background()); !errors.Is(err, rediver.ErrAlreadyRunning) {
					t.Errorf("concurrent lifecycle = %v, want ErrAlreadyRunning", err)
				}
				if stop {
					agent.Stop()
				} else {
					cancel()
				}
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("canceled lifecycle = %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("lifecycle did not terminate after cancellation")
				}
			})
		}
	}
}

func TestAgentStopBeforeRunMakesNoRequests(t *testing.T) {
	for _, method := range []string{"Run", "RunOnce"} {
		t.Run(method, func(t *testing.T) {
			var requests atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, errors.New("stopped agent contacted the server")
			})}
			agent, err := rediver.NewAgent("token", consumerScanner(), rediver.WithServerURL("https://sdk.example"), rediver.WithHTTPClient(client))
			if err != nil {
				t.Fatal(err)
			}
			agent.Stop()
			agent.Stop()
			run := agent.Run
			if method == "RunOnce" {
				run = agent.RunOnce
			}
			if err := run(context.Background()); !errors.Is(err, context.Canceled) {
				t.Fatalf("stopped lifecycle = %v, want context.Canceled", err)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("stopped agent made %d requests", got)
			}
		})
	}
}

func TestPublicAgentAndContractMethodSets(t *testing.T) {
	for name, tc := range map[string]struct {
		typ  reflect.Type
		want []string
	}{
		"Agent":    {reflect.TypeFor[*rediver.Agent](), []string{"Run", "RunOnce", "RunnerID", "Stop"}},
		"Scanner":  {reflect.TypeFor[rediver.Scanner](), []string{"Scan"}},
		"ScanFunc": {reflect.TypeFor[rediver.ScanFunc](), []string{"Scan"}},
		"Emitter":  {reflect.TypeFor[rediver.Emitter](), []string{"EmitDomains", "EmitFindings", "EmitServices"}},
	} {
		var got []string
		for index := range tc.typ.NumMethod() {
			got = append(got, tc.typ.Method(index).Name)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s methods = %v, want %v", name, got, tc.want)
		}
	}
	for _, typ := range []reflect.Type{
		reflect.TypeFor[rediver.Target](), reflect.TypeFor[rediver.RetryPolicy](),
		reflect.TypeFor[rediver.DNSResult](), reflect.TypeFor[rediver.ServiceResult](), reflect.TypeFor[rediver.FindingResult](),
		reflect.TypeFor[rediver.DNSRecord](), reflect.TypeFor[rediver.Service](), reflect.TypeFor[rediver.HTTPData](),
		reflect.TypeFor[rediver.Certificate](), reflect.TypeFor[rediver.Finding](), reflect.TypeFor[rediver.RawHTTPRequest](),
		reflect.TypeFor[rediver.FindingSeverity](),
	} {
		if typ.NumMethod() != 0 || reflect.PointerTo(typ).NumMethod() != 0 {
			t.Errorf("native %s exposes implementation methods", typ.Name())
		}
	}
}
