package contract

import "time"

// DNSRecord is a domain observation. A contains IPv4 addresses; AAAA contains
// IPv6 addresses. TTL is measured in seconds; nil means unknown, while a pointer
// to zero records an explicit zero TTL.
type DNSRecord struct {
	Domain string
	A      []string
	AAAA   []string
	TXT    []string
	MX     []string
	SOA    []string
	NS     []string
	CNAME  string
	TTL    *int
}

// Service is a discovered network service. An empty Host uses the assigned
// target's host. Optional text fields are omitted when empty.
type Service struct {
	Host        string
	Port        int
	Name        string
	Transport   string
	Banner      string
	CPEs        []string
	HTTP        *HTTPData
	Certificate *Certificate
}

// HTTPData contains HTTP observations for a service. Zero StatusCode and Port
// mean unknown and are omitted from the result.
type HTTPData struct {
	URL           string
	IPs           []string
	Title         string
	StatusCode    int
	RedirectTo    string
	ContentType   string
	Webserver     string
	FaviconMMH3   string
	ScreenshotURL string
	Technologies  []string
	Scheme        string
	Host          string
	Port          int
	Path          string
}

// Certificate contains TLS certificate observations. Zero dates are omitted.
// Wildcard distinguishes an unknown value from an observed false value.
type Certificate struct {
	Fingerprint string
	Serial      string
	SubjectCN   string
	SubjectAN   []string
	SubjectOrg  string
	IssuerCN    string
	IssuerOrg   string
	NotBefore   time.Time
	NotAfter    time.Time
	Wildcard    *bool
}

// Finding is a vulnerability observation. CVSSScore is optional and must be
// finite and between 0 and 10 when present. Optional text is omitted when empty.
type Finding struct {
	Name        string
	Description string
	Category    string
	Remediation string
	Severity    FindingSeverity
	CVE         string
	CWEs        []string
	References  []string
	CVSSVector  string
	CVSSScore   *float64
	RuleID      string
	Endpoint    string
	Requests    []RawHTTPRequest
	CurlCommand string
}

// RawHTTPRequest contains the HTTP request and response evidence for a finding.
type RawHTTPRequest struct {
	Request  string
	Response string
	Param    string
	Payload  string
}

// FindingSeverity is the severity of a vulnerability observation.
type FindingSeverity string

const (
	SeverityUnspecified FindingSeverity = ""
	SeverityInfo        FindingSeverity = "info"
	SeverityLow         FindingSeverity = "low"
	SeverityMedium      FindingSeverity = "medium"
	SeverityHigh        FindingSeverity = "high"
	SeverityCritical    FindingSeverity = "critical"
)
