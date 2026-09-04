package runtime

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/redivers/sdk-go/internal/contract"
)

// Config holds the settings used by the SDK runtime.
type Config struct {
	ServerURL            string
	HTTPClient           *http.Client
	MaxConcurrency       int
	PollInterval         time.Duration
	HeartbeatInterval    time.Duration
	JobHeartbeatInterval time.Duration
	ShutdownTimeout      time.Duration
	RequestTimeout       time.Duration
	RunnerID             string
	Hostname             string
	IPAddress            string
	Version              string
	Logger               *slog.Logger
	RetryPolicy          contract.RetryPolicy
}

// DefaultConfig supplies native runtime defaults without making network calls.
func DefaultConfig(sdkVersion string) Config {
	serverURL := os.Getenv("REDIVER_URL")
	if serverURL == "" {
		serverURL = "https://api.rediver.ai"
	}
	hostname, _ := os.Hostname()
	return Config{
		ServerURL:            serverURL,
		HTTPClient:           &http.Client{},
		MaxConcurrency:       1,
		PollInterval:         5 * time.Second,
		HeartbeatInterval:    30 * time.Second,
		JobHeartbeatInterval: 15 * time.Second,
		ShutdownTimeout:      30 * time.Second,
		RequestTimeout:       60 * time.Second,
		Hostname:             hostname,
		Version:              sdkVersion,
		Logger:               slog.Default(),
		RetryPolicy:          contract.DefaultRetryPolicy(),
	}
}

func (c Config) validate() error {
	serverURL, err := url.Parse(c.ServerURL)
	if err != nil || serverURL.Hostname() == "" ||
		(serverURL.Scheme != "http" && serverURL.Scheme != "https") ||
		serverURL.User != nil || serverURL.RawQuery != "" || serverURL.ForceQuery ||
		strings.Contains(c.ServerURL, "#") {
		return fmt.Errorf("%w: server URL must use HTTP(S), include a host, and omit credentials, query, and fragment", contract.ErrInvalidConfig)
	}
	if c.HTTPClient == nil {
		return fmt.Errorf("%w: HTTP client must not be nil", contract.ErrInvalidConfig)
	}
	if c.Logger == nil {
		return fmt.Errorf("%w: logger must not be nil", contract.ErrInvalidConfig)
	}
	if c.MaxConcurrency <= 0 {
		return fmt.Errorf("%w: max concurrency must be positive", contract.ErrInvalidConfig)
	}
	if c.IPAddress != "" && net.ParseIP(c.IPAddress) == nil {
		return fmt.Errorf("%w: IP address must be a valid IPv4 or IPv6 address", contract.ErrInvalidConfig)
	}
	for _, setting := range []struct {
		name     string
		duration time.Duration
	}{
		{"poll interval", c.PollInterval},
		{"heartbeat interval", c.HeartbeatInterval},
		{"job heartbeat interval", c.JobHeartbeatInterval},
		{"shutdown timeout", c.ShutdownTimeout},
		{"request timeout", c.RequestTimeout},
	} {
		if setting.duration <= 0 {
			return fmt.Errorf("%w: %s must be positive", contract.ErrInvalidConfig, setting.name)
		}
	}
	p := c.RetryPolicy
	if p.MaxAttempts <= 0 || p.InitialBackoff < 0 || p.MaxBackoff < p.InitialBackoff ||
		math.IsNaN(p.BackoffMultiplier) || math.IsInf(p.BackoffMultiplier, 0) || p.BackoffMultiplier < 0 {
		return fmt.Errorf("%w: retry policy has invalid attempts or backoff settings", contract.ErrInvalidConfig)
	}
	// A disabled policy needs no backoff; policies that retry must remain bounded.
	if p.MaxAttempts > 1 && (p.InitialBackoff == 0 || p.MaxBackoff == 0 || p.BackoffMultiplier < 1) {
		return fmt.Errorf("%w: retries require positive backoffs and a multiplier of at least one", contract.ErrInvalidConfig)
	}
	for _, status := range p.RetryableStatusCodes {
		if status < 100 || status > 599 {
			return fmt.Errorf("%w: retry HTTP status must be between 100 and 599", contract.ErrInvalidConfig)
		}
	}
	return nil
}
