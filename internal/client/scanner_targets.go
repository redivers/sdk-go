package client

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	pb "buf.build/gen/go/rediver/api/protocolbuffers/go/networkscan"
	"github.com/redivers/sdk-go/internal/contract"
)

func parsePorts(spec string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)
	for _, part := range strings.Split(spec, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("%w: invalid port range %q", contract.ErrInvalidJob, part)
		}
		start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
		if err != nil || start < 1 || start > 65535 {
			return nil, fmt.Errorf("%w: invalid port %q", contract.ErrInvalidJob, part)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil || end < start || end > 65535 {
				return nil, fmt.Errorf("%w: invalid port range %q", contract.ErrInvalidJob, part)
			}
		}
		for port := start; port <= end; port++ {
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}
	sort.Ints(ports)
	return ports, nil
}

// Decode job-wide options only once, preserving the post-Start validation point.
func scannerTargets(job *pb.Job) ([]contract.Target, error) {
	var ports []int
	var rate int
	if job.Scanner == pb.Scanner_SCANNER_SERVICE_DISCOVER {
		options := job.GetOptions().GetServiceDiscover()
		var err error
		ports, err = parsePorts(options.GetPorts())
		if err != nil {
			return nil, err
		}
		rate = int(options.GetRate())
		if rate <= 0 {
			return nil, fmt.Errorf("%w: service discovery requires a positive rate", contract.ErrInvalidJob)
		}
	}
	targets := make([]contract.Target, len(job.Targets))
	for index, target := range job.Targets {
		targets[index] = contract.BindTarget(contract.Target{Domain: target.GetDomain(), Host: target.GetHost(), Port: int(target.GetPort()), URL: target.GetUrl(), Ports: append([]int(nil), ports...), Rate: rate}, index)
	}
	return targets, nil
}
