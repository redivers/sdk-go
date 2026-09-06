package client

import (
	"fmt"
	"slices"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
)

func toProtoServices(host string, services []contract.Service) ([]*pb.Service, error) {
	converted := make([]*pb.Service, 0, len(services))
	for index, service := range services {
		port, err := resultPort(service.Port, "service port")
		if err != nil {
			return nil, fmt.Errorf("rediver: service %d: %w", index, err)
		}
		assignedHost := service.Host
		if assignedHost == "" {
			assignedHost = host
		}
		http, err := toProtoHTTPData(service.HTTP)
		if err != nil {
			return nil, fmt.Errorf("rediver: service %d: %w", index, err)
		}
		certificate, err := toProtoCertificate(service.Certificate)
		if err != nil {
			return nil, fmt.Errorf("rediver: service %d: %w", index, err)
		}
		converted = append(converted, &pb.Service{
			Host: assignedHost, Port: port,
			Name: optionalResultString(service.Name), Transport: optionalResultString(service.Transport),
			Banner: optionalResultString(service.Banner), Cpes: slices.Clone(service.CPEs),
			Http: http, Certificate: certificate,
		})
	}
	return converted, nil
}

func toProtoHTTPData(http *contract.HTTPData) (*pb.HttpData, error) {
	if http == nil {
		return nil, nil
	}
	converted := &pb.HttpData{
		Url: optionalResultString(http.URL), Ips: slices.Clone(http.IPs),
		Title: optionalResultString(http.Title), RedirectTo: optionalResultString(http.RedirectTo),
		ContentType: optionalResultString(http.ContentType), Webserver: optionalResultString(http.Webserver),
		FaviconMmh3: optionalResultString(http.FaviconMMH3), ScreenshotUrl: optionalResultString(http.ScreenshotURL),
		Technologies: slices.Clone(http.Technologies), Scheme: optionalResultString(http.Scheme),
		Host: optionalResultString(http.Host), Path: optionalResultString(http.Path),
	}
	if http.StatusCode != 0 {
		statusCode, err := resultInt32(http.StatusCode, "HTTP status code")
		if err != nil {
			return nil, err
		}
		converted.StatusCode = &statusCode
	}
	if http.Port != 0 {
		port, err := resultPort(http.Port, "HTTP port")
		if err != nil {
			return nil, err
		}
		converted.Port = &port
	}
	return converted, nil
}

func toProtoCertificate(certificate *contract.Certificate) (*pb.Certificate, error) {
	if certificate == nil {
		return nil, nil
	}
	notBefore, err := resultTimestamp(certificate.NotBefore, "certificate NotBefore")
	if err != nil {
		return nil, err
	}
	notAfter, err := resultTimestamp(certificate.NotAfter, "certificate NotAfter")
	if err != nil {
		return nil, err
	}
	converted := &pb.Certificate{
		Fingerprint: optionalResultString(certificate.Fingerprint), Serial: optionalResultString(certificate.Serial),
		SubjectCn: optionalResultString(certificate.SubjectCN), SubjectAn: slices.Clone(certificate.SubjectAN),
		SubjectOrg: optionalResultString(certificate.SubjectOrg), IssuerCn: optionalResultString(certificate.IssuerCN),
		IssuerOrg: optionalResultString(certificate.IssuerOrg), NotBefore: notBefore, NotAfter: notAfter,
	}
	if certificate.Wildcard != nil {
		wildcard := *certificate.Wildcard
		converted.Wildcard = &wildcard
	}
	return converted, nil
}
