package client

import (
	"fmt"
	"slices"
	"strings"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
	"golang.org/x/net/idna"
)

// Each chunk contains only observed records. The target's own-domain record is
// optional; completing an empty DNS scan must not replace observed metadata.
func toProtoDNSRecords(domain string, records []contract.DNSRecord) ([]*pb.DnsRecord, error) {
	assigned, err := normalizedDomain(domain)
	if err != nil {
		return nil, err
	}
	converted := make([]*pb.DnsRecord, 0, len(records))
	ownFound := false
	for index, record := range records {
		name, err := normalizedDomain(record.Domain)
		if err != nil {
			return nil, fmt.Errorf("rediver: DNS record %d: %w", index, err)
		}
		if name == assigned {
			if ownFound {
				return nil, fmt.Errorf("rediver: DNS results contain duplicate own-domain records")
			}
			ownFound = true
		} else if !strings.HasSuffix(name, "."+assigned) {
			return nil, fmt.Errorf("rediver: DNS record %d is not a strict descendant of its target", index)
		}
		// Preserve repeated descendants for the backend to select a complete
		// observation; dropping or merging them here would discard metadata.
		out := &pb.DnsRecord{
			Domain: record.Domain,
			Ips:    slices.Clone(record.IPs),
			Txt:    slices.Clone(record.TXT),
			Mx:     slices.Clone(record.MX),
			Soa:    slices.Clone(record.SOA),
			Ns:     slices.Clone(record.NS),
			Cname:  optionalResultString(record.CNAME),
		}
		if record.TTL != nil {
			ttl, err := resultInt32(*record.TTL, "DNS TTL")
			if err != nil {
				return nil, err
			}
			if ttl < 0 {
				return nil, fmt.Errorf("rediver: DNS TTL must not be negative")
			}
			out.Ttl = &ttl
		}
		converted = append(converted, out)
	}
	return converted, nil
}

// Normalize only for comparison; preserve the scanner's observations on the wire.
func normalizedDomain(value string) (string, error) {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || ascii == "" {
		return "", fmt.Errorf("rediver: DNS record domain is invalid")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" {
			return "", fmt.Errorf("rediver: DNS record domain contains an empty label")
		}
	}
	return strings.ToLower(ascii), nil
}
