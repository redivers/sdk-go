package client

import (
	"errors"
	"reflect"
	"testing"

	"github.com/redivers/sdk-go/internal/contract"
)

func TestParsePortsExpandsAndDeduplicatesAssignment(t *testing.T) {
	ports, err := parsePorts("443,80-82,81, 65535 ,1")
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{1, 80, 81, 82, 443, 65535}; !reflect.DeepEqual(ports, want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}
}

func TestParsePortsRejectsMalformedOrOutOfRangeAssignments(t *testing.T) {
	for _, spec := range []string{"", " ", "0", "65536", "-1", "90-80", "1-65536", "80-", "80-81-82", "80,,443", "http", "9999999999999999999999"} {
		t.Run(spec, func(t *testing.T) {
			if _, err := parsePorts(spec); !errors.Is(err, contract.ErrInvalidJob) {
				t.Fatalf("error = %v, want contract.ErrInvalidJob", err)
			}
		})
	}
}

func TestParsePortsSupportsFullPortRange(t *testing.T) {
	ports, err := parsePorts("1-65535")
	if err != nil || len(ports) != 65535 || ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Fatalf("full range length = %d, error = %v", len(ports), err)
	}
}
