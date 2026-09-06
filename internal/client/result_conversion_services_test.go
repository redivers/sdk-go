package client

import (
	"math"
	"testing"
	"time"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestToProtoServicesPreservesAllFieldsAndCopiesResults(t *testing.T) {
	notBefore := time.Date(2026, 1, 2, 3, 4, 5, 123, time.FixedZone("scan", 7*60*60))
	notAfter := notBefore.Add(24 * time.Hour)
	wildcard := false
	services := []contract.Service{{
		Port: 443, Name: "https", Transport: "tcp", Banner: "banner", CPEs: []string{"cpe"},
		HTTP: &contract.HTTPData{
			URL: "https://example.com/path", IPs: []string{"192.0.2.1"}, Title: "title", StatusCode: 200,
			RedirectTo: "/next", ContentType: "text/html", Webserver: "nginx", FaviconMMH3: "123",
			ScreenshotURL: "https://images.example/screen", Technologies: []string{"tech"},
			Scheme: "https", Host: "example.com", Port: 443, Path: "/path",
		},
		Certificate: &contract.Certificate{
			Fingerprint: "fingerprint", Serial: "serial", SubjectCN: "example.com", SubjectAN: []string{"example.com"},
			SubjectOrg: "owner", IssuerCN: "issuer", IssuerOrg: "CA", NotBefore: notBefore, NotAfter: notAfter, Wildcard: &wildcard,
		},
	}}
	want := &pb.Service{
		Host: "example.com", Port: 443, Name: ptr("https"), Transport: ptr("tcp"), Banner: ptr("banner"), Cpes: []string{"cpe"},
		Http: &pb.HttpData{
			Url: ptr("https://example.com/path"), Ips: []string{"192.0.2.1"}, Title: ptr("title"), StatusCode: ptr(int32(200)),
			RedirectTo: ptr("/next"), ContentType: ptr("text/html"), Webserver: ptr("nginx"), FaviconMmh3: ptr("123"),
			ScreenshotUrl: ptr("https://images.example/screen"), Technologies: []string{"tech"},
			Scheme: ptr("https"), Host: ptr("example.com"), Port: ptr(int32(443)), Path: ptr("/path"),
		},
		Certificate: &pb.Certificate{
			Fingerprint: ptr("fingerprint"), Serial: ptr("serial"), SubjectCn: ptr("example.com"), SubjectAn: []string{"example.com"},
			SubjectOrg: ptr("owner"), IssuerCn: ptr("issuer"), IssuerOrg: ptr("CA"),
			NotBefore: timestamppb.New(notBefore), NotAfter: timestamppb.New(notAfter), Wildcard: ptr(false),
		},
	}
	got, err := toProtoServices("example.com", services)
	if err != nil || len(got) != 1 || !proto.Equal(got[0], want) {
		t.Fatalf("converted = %v, error = %v; want %v", got, err, want)
	}
	if services[0].Host != "" {
		t.Fatal("default host mutated handler result")
	}
	services[0].CPEs[0], services[0].HTTP.IPs[0], services[0].HTTP.Technologies[0] = "changed", "changed", "changed"
	services[0].Certificate.SubjectAN[0], wildcard = "changed", true
	services[0].HTTP.Title = "changed"
	if !proto.Equal(got[0], want) {
		t.Fatalf("wire result retained mutable handler data: %v", got[0])
	}
}

func TestToProtoServicesOmitsUnknownFieldsAndKeepsExplicitHost(t *testing.T) {
	got, err := toProtoServices("assigned.example", []contract.Service{{Host: "observed.example", Port: 1, HTTP: &contract.HTTPData{}, Certificate: &contract.Certificate{}}})
	want := &pb.Service{Host: "observed.example", Port: 1, Http: &pb.HttpData{}, Certificate: &pb.Certificate{}}
	if err != nil || len(got) != 1 || !proto.Equal(got[0], want) {
		t.Fatalf("empty optional fields not omitted or host replaced: %v, %v", got, err)
	}
	got, err = toProtoServices("assigned.example", nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty successful results rejected: %v, %v", got, err)
	}
	got, err = toProtoServices("assigned.example", []contract.Service{{Port: 65535}})
	if err != nil || got[0].Http != nil || got[0].Certificate != nil || got[0].Port != 65535 {
		t.Fatalf("missing nested observations or maximum port changed: %v, %v", got, err)
	}
}

func TestToProtoServicesRejectsUnrepresentableNumbersAndDates(t *testing.T) {
	for name, service := range map[string]contract.Service{
		"missing port":    {},
		"negative port":   {Port: -1},
		"oversize port":   {Port: 65536},
		"int32 overflow":  {Port: int(int64(math.MaxInt32) + 1)},
		"HTTP port":       {Port: 443, HTTP: &contract.HTTPData{Port: -1}},
		"HTTP oversize":   {Port: 443, HTTP: &contract.HTTPData{Port: 65536}},
		"HTTP overflow":   {Port: 443, HTTP: &contract.HTTPData{StatusCode: int(int64(math.MaxInt32) + 1)}},
		"HTTP underflow":  {Port: 443, HTTP: &contract.HTTPData{StatusCode: int(int64(math.MinInt32) - 1)}},
		"early NotBefore": {Port: 443, Certificate: &contract.Certificate{NotBefore: time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)}},
		"late NotAfter":   {Port: 443, Certificate: &contract.Certificate{NotAfter: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := toProtoServices("example.com", []contract.Service{service}); err == nil || got != nil {
				t.Fatalf("invalid value accepted: %v, %v", got, err)
			}
		})
	}
}
