package client

import (
	"encoding/json"
	"math"
	"slices"
	"testing"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestToProtoDNSRecordsUsesAddressFamilyJSON(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record contract.DNSRecord
		want   map[string][]string
	}{
		{
			name:   "IPv4 only",
			record: contract.DNSRecord{Domain: "example.com", A: []string{"192.0.2.1"}},
			want:   map[string][]string{"a": {"192.0.2.1"}},
		},
		{
			name:   "IPv6 only",
			record: contract.DNSRecord{Domain: "example.com", AAAA: []string{"2001:db8::1"}},
			want:   map[string][]string{"aaaa": {"2001:db8::1"}},
		},
		{
			name:   "both address families",
			record: contract.DNSRecord{Domain: "example.com", A: []string{"192.0.2.1"}, AAAA: []string{"2001:db8::1"}},
			want:   map[string][]string{"a": {"192.0.2.1"}, "aaaa": {"2001:db8::1"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			converted, err := toProtoDNSRecords("example.com", []contract.DNSRecord{tc.record})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := protojson.Marshal(converted[0])
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(payload, &fields); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"a", "aaaa"} {
				if want, present := tc.want[key]; present {
					var addresses []string
					if err := json.Unmarshal(fields[key], &addresses); err != nil || !slices.Equal(addresses, want) {
						t.Errorf("%s JSON addresses = %v, error = %v; want %v; payload = %s", key, addresses, err, want, payload)
					}
				} else if _, present := fields[key]; present {
					t.Errorf("absent address family %s was serialized: %s", key, payload)
				}
			}
			if _, present := fields["ips"]; present {
				t.Errorf("DNS JSON included the removed ips field: %s", payload)
			}
		})
	}
}

func TestToProtoDNSRecordsPreservesObservationsAndPresence(t *testing.T) {
	ttl := 0
	records := []contract.DNSRecord{{
		Domain: "Example.COM.", A: []string{"192.0.2.1"}, AAAA: []string{"2001:db8::1"}, TXT: []string{"txt"},
		MX: []string{"mail.example.com"}, SOA: []string{"soa"}, NS: []string{"ns.example.com"},
		CNAME: "alias.example.com", TTL: &ttl,
	}}
	want := &pb.DnsRecord{
		Domain: "Example.COM.", A: []string{"192.0.2.1"}, Aaaa: []string{"2001:db8::1"}, Txt: []string{"txt"},
		Mx: []string{"mail.example.com"}, Soa: []string{"soa"}, Ns: []string{"ns.example.com"},
		Cname: ptr("alias.example.com"), Ttl: ptr(int32(0)),
	}
	got, err := toProtoDNSRecords("example.com", records)
	if err != nil || len(got) != 1 || !proto.Equal(got[0], want) {
		t.Fatalf("converted = %v, error = %v; want %v", got, err, want)
	}
	if records[0].Domain != "Example.COM." || records[0].TTL != &ttl {
		t.Fatal("conversion mutated the handler's record")
	}
	records[0].A[0], records[0].AAAA[0] = "changed IPv4", "changed IPv6"
	records[0].TXT[0], records[0].MX[0] = "changed", "changed"
	records[0].SOA[0], records[0].NS[0], ttl = "changed", "changed", 10
	if !proto.Equal(got[0], want) {
		t.Fatalf("converted record retained mutable handler data: %v", got[0])
	}
}

func TestToProtoDNSRecordsNeverSynthesizesMissingOwnDomain(t *testing.T) {
	for _, records := range [][]contract.DNSRecord{nil, {{Domain: "api.example.com"}}} {
		got, err := toProtoDNSRecords("Example.com.", records)
		if err != nil || len(got) != len(records) {
			t.Fatalf("converted = %v, error = %v", got, err)
		}
		if len(records) != 0 && got[0].Domain != records[0].Domain {
			t.Fatalf("conversion replaced an observed domain: %v", got)
		}
	}
	got, err := toProtoDNSRecords("bücher.example", []contract.DNSRecord{{Domain: "xn--bcher-kva.example"}})
	if err != nil || len(got) != 1 {
		t.Fatalf("IDNA equivalent own record must not be duplicated: %v, %v", got, err)
	}
}

func TestToProtoDNSRecordsRejectsInvalidAttributionAndTTL(t *testing.T) {
	for name, records := range map[string][]contract.DNSRecord{
		"duplicate own": {{Domain: "example.com"}, {Domain: "EXAMPLE.COM."}},
		"unrelated":     {{Domain: "other.example"}},
		"suffix only":   {{Domain: "notexample.com"}},
		"empty label":   {{Domain: "api..example.com"}},
		"missing name":  {{}},
		"negative TTL":  {{Domain: "example.com", TTL: ptr(-1)}},
		"TTL overflow":  {{Domain: "example.com", TTL: ptr(int(int64(math.MaxInt32) + 1))}},
	} {
		t.Run(name, func(t *testing.T) {
			if records, err := toProtoDNSRecords("example.com", records); err == nil || records != nil {
				t.Fatalf("invalid result accepted: %v, %v", records, err)
			}
		})
	}
	if _, err := toProtoDNSRecords("", nil); err == nil {
		t.Fatal("missing target domain accepted")
	}
	got, err := toProtoDNSRecords("example.com", []contract.DNSRecord{{Domain: "example.com", TTL: ptr(int(math.MaxInt32))}})
	if err != nil || got[0].GetTtl() != math.MaxInt32 {
		t.Fatalf("maximum TTL was not preserved: %v, %v", got, err)
	}
}

func TestToProtoDNSRecordsPreservesRepeatedDescendantObservations(t *testing.T) {
	for _, names := range [][2]string{{"api.example.com", "API.EXAMPLE.COM."}, {"bücher.example.com", "xn--bcher-kva.example.com"}} {
		t.Run(names[0], func(t *testing.T) {
			records := []contract.DNSRecord{
				{Domain: names[0], TXT: []string{"first"}, TTL: ptr(300)},
				{Domain: names[1], TXT: []string{"second"}},
			}
			got, err := toProtoDNSRecords("example.com", records)
			if err != nil || len(got) != 2 {
				t.Fatalf("repeated descendant observations = %v, %v", got, err)
			}
			if got[0].Domain != names[0] || got[0].GetTtl() != 300 || got[0].Txt[0] != "first" || got[1].Domain != names[1] || got[1].Ttl != nil || got[1].Txt[0] != "second" {
				t.Fatalf("descendant observations were merged or replaced: %v", got)
			}
		})
	}
	if got, err := toProtoDNSRecords("bücher.example", []contract.DNSRecord{{Domain: "bücher.example"}, {Domain: "xn--bcher-kva.example"}}); err == nil || got != nil {
		t.Fatalf("IDNA-equivalent duplicate own records accepted: %v, %v", got, err)
	}
}
