package rediver_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	rediver "github.com/redivers/sdk-go"
)

func TestAgentOptionsValidateThroughConstructor(t *testing.T) {
	t.Setenv("REDIVER_URL", "")
	for name, option := range map[string]rediver.Option{
		"zero concurrency": rediver.WithMaxConcurrency(0), "negative concurrency": rediver.WithMaxConcurrency(-1),
		"zero poll": rediver.WithPollInterval(0), "negative heartbeat": rediver.WithHeartbeatInterval(-time.Second),
		"zero job heartbeat": rediver.WithJobHeartbeatInterval(0), "zero shutdown": rediver.WithShutdownTimeout(0),
		"zero request": rediver.WithRequestTimeout(0), "nil client": rediver.WithHTTPClient(nil), "nil logger": rediver.WithLogger(nil),
	} {
		t.Run(name, func(t *testing.T) {
			if agent, err := rediver.NewAgent("token", consumerScanner(), option); agent != nil || !errors.Is(err, rediver.ErrInvalidConfig) {
				t.Fatalf("invalid option: agent=%v, error=%v", agent != nil, err)
			}
		})
	}
	options := []rediver.Option{
		rediver.WithServerURL("https://sdk.example/api"), rediver.WithHTTPClient(&http.Client{}),
		rediver.WithMaxConcurrency(2), rediver.WithPollInterval(time.Second), rediver.WithHeartbeatInterval(time.Second),
		rediver.WithJobHeartbeatInterval(time.Second), rediver.WithShutdownTimeout(time.Second), rediver.WithRequestTimeout(time.Second),
		rediver.WithHostname("scanner-host"), rediver.WithVersion("consumer-version"),
		rediver.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	if agent, err := rediver.NewAgent("token", consumerScanner(), options...); agent == nil || err != nil {
		t.Fatalf("valid options: agent=%v, error=%v", agent != nil, err)
	}
}

func TestAgentIPAddressOptions(t *testing.T) {
	t.Setenv("REDIVER_URL", "")
	for _, address := range []string{"", "192.0.2.42", "2001:db8::42"} {
		if _, err := rediver.NewAgent("token", consumerScanner(), rediver.WithIPAddress(address)); err != nil {
			t.Errorf("valid address %q: %v", address, err)
		}
	}
	for _, address := range []string{"example.com", "192.0.2.42:443", "999.0.0.1", " 192.0.2.42 ", "192.0.2.0/24"} {
		if _, err := rediver.NewAgent("token", consumerScanner(), rediver.WithIPAddress(address)); !errors.Is(err, rediver.ErrInvalidConfig) {
			t.Errorf("invalid address %q: %v", address, err)
		}
	}
}

func TestAgentServerURLRejectsInvalidValues(t *testing.T) {
	for _, serverURL := range []string{
		"", "localhost:8080", "ftp://example.com", "https:///path", "https://:443",
		"https://user:secret@example.com", "https://example.com?key=value", "https://example.com?",
		"https://example.com#fragment", "https://example.com#", "https://example.com:invalid",
	} {
		t.Run(serverURL, func(t *testing.T) {
			if _, err := rediver.NewAgent("token", consumerScanner(), rediver.WithServerURL(serverURL)); !errors.Is(err, rediver.ErrInvalidConfig) {
				t.Fatalf("invalid URL accepted: %v", err)
			}
		})
	}
}

func TestAgentServerURLPrecedenceReachesHTTPClient(t *testing.T) {
	for _, tc := range []struct{ name, environment, explicit, want string }{
		{"default", "", "", "https://api.rediver.ai/"},
		{"environment", "https://environment.example/api", "", "https://environment.example/api/"},
		{"explicit", "https://environment.example/api", "http://localhost:8080/scanner", "http://localhost:8080/scanner/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REDIVER_URL", tc.environment)
			transportErr := errors.New("transport stopped")
			var requests atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests.Add(1)
				if !strings.HasPrefix(r.URL.String(), tc.want) {
					t.Errorf("request URL = %q, want prefix %q", r.URL, tc.want)
				}
				return nil, transportErr
			})}
			options := []rediver.Option{rediver.WithHTTPClient(client), rediver.WithNoRetry()}
			if tc.explicit != "" {
				options = append(options, rediver.WithServerURL(tc.explicit))
			}
			agent, err := rediver.NewAgent("token", consumerScanner(), options...)
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.RunOnce(context.Background()); !errors.Is(err, transportErr) {
				t.Fatalf("RunOnce lost transport error: %v", err)
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("request count = %d, want 1", got)
			}
		})
	}
}

func TestAgentRejectsInvalidRetryOptions(t *testing.T) {
	t.Setenv("REDIVER_URL", "")
	for name, mutate := range map[string]func(*rediver.RetryPolicy){
		"no attempts":         func(p *rediver.RetryPolicy) { p.MaxAttempts = 0 },
		"negative attempts":   func(p *rediver.RetryPolicy) { p.MaxAttempts = -1 },
		"zero backoff":        func(p *rediver.RetryPolicy) { p.InitialBackoff = 0 },
		"negative backoff":    func(p *rediver.RetryPolicy) { p.InitialBackoff = -time.Second },
		"zero maximum":        func(p *rediver.RetryPolicy) { p.MaxBackoff = 0 },
		"inverted bounds":     func(p *rediver.RetryPolicy) { p.MaxBackoff = p.InitialBackoff / 2 },
		"shrinking backoff":   func(p *rediver.RetryPolicy) { p.BackoffMultiplier = 0.5 },
		"NaN multiplier":      func(p *rediver.RetryPolicy) { p.BackoffMultiplier = math.NaN() },
		"infinite multiplier": func(p *rediver.RetryPolicy) { p.BackoffMultiplier = math.Inf(1) },
		"invalid status":      func(p *rediver.RetryPolicy) { p.RetryableStatusCodes = []int{600} },
	} {
		t.Run(name, func(t *testing.T) {
			policy := rediver.DefaultRetryPolicy()
			mutate(&policy)
			if _, err := rediver.NewAgent("token", consumerScanner(), rediver.WithRetryPolicy(policy)); !errors.Is(err, rediver.ErrInvalidConfig) {
				t.Fatalf("invalid retry policy accepted: %v", err)
			}
		})
	}
	for name, preset := range map[string]rediver.Option{
		"default": rediver.WithRetryDefault(), "aggressive": rediver.WithRetryAggressive(), "disabled": rediver.WithNoRetry(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := rediver.NewAgent("token", consumerScanner(), preset); err != nil {
				t.Fatalf("retry preset rejected: %v", err)
			}
		})
	}
}

func TestWithRetryPolicyCapturesStatusCodesBeforeCallerMutation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	policy := rediver.RetryPolicy{
		MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
		BackoffMultiplier: 1, RetryableStatusCodes: []int{http.StatusServiceUnavailable},
	}
	option := rediver.WithRetryPolicy(policy)
	policy.RetryableStatusCodes[0] = http.StatusBadRequest
	// Reusing the option must preserve its captured policy for each agent.
	for index := range 2 {
		agent, err := rediver.NewAgent("token", consumerScanner(), rediver.WithServerURL(server.URL), rediver.WithHTTPClient(server.Client()), rediver.WithRequestTimeout(time.Second), option)
		if err != nil {
			t.Fatal(err)
		}
		if err := agent.RunOnce(context.Background()); err == nil {
			t.Fatal("unavailable server unexpectedly succeeded")
		}
		if got, want := requests.Load(), int32((index+1)*3); got != want {
			t.Fatalf("request count = %d, want %d from captured retry policy", got, want)
		}
	}
}
