package rediver

import "github.com/redivers/sdk-go/internal/contract"

// DNSRecord is a domain observation. TTL is measured in seconds; nil means
// unknown, while a pointer to zero records an explicit zero TTL.
type DNSRecord = contract.DNSRecord

// Service is a discovered network service. An empty Host uses the assigned
// target's host. Optional text fields are omitted when empty.
type Service = contract.Service

// HTTPData contains HTTP observations for a service. Zero StatusCode and Port
// mean unknown and are omitted from the result.
type HTTPData = contract.HTTPData

// Certificate contains TLS certificate observations. Zero dates are omitted.
// Wildcard distinguishes an unknown value from an observed false value.
type Certificate = contract.Certificate

// Finding is a vulnerability observation. CVSSScore is optional and must be
// finite and between 0 and 10 when present. Optional text is omitted when empty.
type Finding = contract.Finding

// RawHTTPRequest contains the HTTP request and response evidence for a finding.
type RawHTTPRequest = contract.RawHTTPRequest

// FindingSeverity is the severity of a vulnerability observation.
type FindingSeverity = contract.FindingSeverity

const (
	SeverityInfo     = contract.SeverityInfo
	SeverityLow      = contract.SeverityLow
	SeverityMedium   = contract.SeverityMedium
	SeverityHigh     = contract.SeverityHigh
	SeverityCritical = contract.SeverityCritical
)
