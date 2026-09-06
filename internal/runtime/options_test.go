package runtime

import (
	"errors"
	"github.com/redivers/sdk-go/internal/contract"
	"math"
	"os"
	"testing"
	"time"
)

func TestAgentConfigDefaults(t *testing.T) {
	t.Setenv("REDIVER_URL", "")
	config := DefaultConfig("test-version")
	if err := config.validate(); err != nil {
		t.Fatalf("default configuration is invalid: %v", err)
	}
	if config.ServerURL != "https://api.rediver.ai" || config.MaxConcurrency != 1 {
		t.Errorf("unexpected server or concurrency default: %q, %d", config.ServerURL, config.MaxConcurrency)
	}
	if config.HTTPClient == nil || config.Logger == nil {
		t.Fatal("default client and logger must be usable")
	}
	if config.HTTPClient.Timeout != 0 {
		t.Errorf("request deadlines must be managed per request, got client timeout %v", config.HTTPClient.Timeout)
	}
	for name, values := range map[string][2]time.Duration{
		"poll":          {config.PollInterval, 5 * time.Second},
		"heartbeat":     {config.HeartbeatInterval, 30 * time.Second},
		"job heartbeat": {config.JobHeartbeatInterval, 15 * time.Second},
		"shutdown":      {config.ShutdownTimeout, 30 * time.Second},
		"request":       {config.RequestTimeout, 60 * time.Second},
	} {
		if values[0] != values[1] {
			t.Errorf("%s default: got %v, want %v", name, values[0], values[1])
		}
	}
	hostname, _ := os.Hostname()
	if config.Hostname != hostname || config.Version != "test-version" {
		t.Errorf("default registration metadata: hostname=%q, version=%q", config.Hostname, config.Version)
	}
}

func TestAgentConfigServerURLPrecedence(t *testing.T) {
	t.Setenv("REDIVER_URL", "https://environment.example/api")
	config := DefaultConfig("test-version")
	if config.ServerURL != "https://environment.example/api" {
		t.Fatalf("environment URL was not selected: %q", config.ServerURL)
	}
	config.ServerURL = "http://localhost:8080/scanner"
	if err := config.validate(); err != nil {
		t.Fatalf("explicit local server URL is invalid: %v", err)
	}
	if config.ServerURL != "http://localhost:8080/scanner" {
		t.Errorf("explicit server URL did not override environment: %q", config.ServerURL)
	}
}

func TestAgentConfigRejectsInvalidOptions(t *testing.T) {
	t.Setenv("REDIVER_URL", "")
	tests := map[string]func(*Config){
		"zero concurrency":     func(cfg *Config) { cfg.MaxConcurrency = 0 },
		"negative concurrency": func(cfg *Config) { cfg.MaxConcurrency = -1 },
		"zero poll":            func(cfg *Config) { cfg.PollInterval = 0 },
		"negative heartbeat":   func(cfg *Config) { cfg.HeartbeatInterval = -time.Second },
		"zero job heartbeat":   func(cfg *Config) { cfg.JobHeartbeatInterval = 0 },
		"zero shutdown":        func(cfg *Config) { cfg.ShutdownTimeout = 0 },
		"zero request":         func(cfg *Config) { cfg.RequestTimeout = 0 },
		"nil client":           func(cfg *Config) { cfg.HTTPClient = nil },
		"nil logger":           func(cfg *Config) { cfg.Logger = nil },
	}
	for name, option := range tests {
		t.Run(name, func(t *testing.T) {
			config := DefaultConfig("test-version")
			option(&config)
			if err := config.validate(); !errors.Is(err, contract.ErrInvalidConfig) {
				t.Errorf("invalid option: got %v, want contract.ErrInvalidConfig", err)
			}
		})
	}
}

func TestAgentConfigRejectsInvalidServerURLs(t *testing.T) {
	for _, serverURL := range []string{
		"", "localhost:8080", "ftp://example.com", "https:///path", "https://:443",
		"https://user:secret@example.com", "https://example.com?key=value", "https://example.com?",
		"https://example.com#fragment", "https://example.com#", "https://example.com:invalid",
	} {
		t.Run(serverURL, func(t *testing.T) {
			config := DefaultConfig("test-version")
			config.ServerURL = serverURL
			if err := config.validate(); !errors.Is(err, contract.ErrInvalidConfig) {
				t.Errorf("URL %q: got %v, want contract.ErrInvalidConfig", serverURL, err)
			}
		})
	}
}

func TestAgentConfigRejectsInvalidRetryPolicies(t *testing.T) {
	t.Setenv("REDIVER_URL", "")
	policies := map[string]func(*contract.RetryPolicy){
		"no attempts":         func(p *contract.RetryPolicy) { p.MaxAttempts = 0 },
		"negative attempts":   func(p *contract.RetryPolicy) { p.MaxAttempts = -1 },
		"zero backoff":        func(p *contract.RetryPolicy) { p.InitialBackoff = 0 },
		"negative backoff":    func(p *contract.RetryPolicy) { p.InitialBackoff = -time.Second },
		"zero maximum":        func(p *contract.RetryPolicy) { p.MaxBackoff = 0 },
		"inverted bounds":     func(p *contract.RetryPolicy) { p.MaxBackoff = p.InitialBackoff / 2 },
		"shrinking backoff":   func(p *contract.RetryPolicy) { p.BackoffMultiplier = 0.5 },
		"NaN multiplier":      func(p *contract.RetryPolicy) { p.BackoffMultiplier = math.NaN() },
		"infinite multiplier": func(p *contract.RetryPolicy) { p.BackoffMultiplier = math.Inf(1) },
	}
	for name, mutate := range policies {
		t.Run(name, func(t *testing.T) {
			config := DefaultConfig("test-version")
			policy := contract.DefaultRetryPolicy()
			mutate(&policy)
			config.RetryPolicy = policy
			if err := config.validate(); !errors.Is(err, contract.ErrInvalidConfig) {
				t.Errorf("invalid retry policy: got %v, want contract.ErrInvalidConfig", err)
			}
		})
	}
}

func TestAgentConfigDefaultRetryPolicy(t *testing.T) {
	t.Setenv("REDIVER_URL", "")
	config := DefaultConfig("test-version")
	if err := config.validate(); err != nil {
		t.Fatalf("default retry policy is invalid: %v", err)
	}
	if config.RetryPolicy.MaxAttempts != 5 {
		t.Errorf("got %d attempts, want 5", config.RetryPolicy.MaxAttempts)
	}
}
