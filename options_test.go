package rediver_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
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
		"zero shutdown": rediver.WithShutdownTimeout(0),
		"zero request":  rediver.WithRequestTimeout(0), "nil client": rediver.WithHTTPClient(nil), "nil logger": rediver.WithLogger(nil),
	} {
		t.Run(name, func(t *testing.T) {
			if agent, err := rediver.NewAgent("token", consumerScanner(), option); agent != nil || !errors.Is(err, rediver.ErrInvalidConfig) {
				t.Fatalf("invalid option: agent=%v, error=%v", agent != nil, err)
			}
		})
	}
	options := []rediver.Option{
		rediver.WithServerURL("https://sdk.example/api"), rediver.WithHTTPClient(&http.Client{}),
		rediver.WithMaxConcurrency(2), rediver.WithShutdownTimeout(time.Second), rediver.WithRequestTimeout(time.Second),
		rediver.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	if agent, err := rediver.NewAgent("token", consumerScanner(), options...); agent == nil || err != nil {
		t.Fatalf("valid options: agent=%v, error=%v", agent != nil, err)
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
				return nil, nonRetryableTransportError(transportErr)
			})}
			options := []rediver.Option{rediver.WithHTTPClient(client)}
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
