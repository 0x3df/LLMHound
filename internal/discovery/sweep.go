package discovery

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

// TCPDialer dials a TCP address for Stage 1 open-port discovery.
type TCPDialer func(ctx context.Context, network, addr string) (net.Conn, error)

// SweepOpenPorts performs a fast bounded concurrent TCP connect sweep across
// hosts x ports (iterating port-outer so successive dials spread across hosts
// instead of bursting a single target). Returns map[host][port] = true for open ports.
func SweepOpenPorts(
	ctx context.Context,
	hosts []string,
	ports []int,
	concurrency int,
	timeout time.Duration,
	dialer TCPDialer,
) map[string]map[int]bool {
	open := make(map[string]map[int]bool)
	if len(hosts) == 0 || len(ports) == 0 {
		return open
	}
	if concurrency <= 0 {
		concurrency = 256
	}
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}
	if dialer == nil {
		d := &net.Dialer{Timeout: timeout}
		dialer = d.DialContext
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

outer:
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		portStr := strconv.Itoa(port)
		for _, host := range hosts {
			if ctx.Err() != nil {
				break outer
			}
			select {
			case <-ctx.Done():
				break outer
			case sem <- struct{}{}:
			}
			if ctx.Err() != nil {
				<-sem
				break outer
			}
			wg.Add(1)
			go func(h string, p int, ps string) {
				defer wg.Done()
				defer func() { <-sem }()

				dialCtx, cancel := context.WithTimeout(ctx, timeout)
				conn, err := dialer(dialCtx, "tcp", net.JoinHostPort(h, ps))
				cancel()
				if err != nil {
					return
				}
				if conn != nil {
					_ = conn.Close()
				}
				mu.Lock()
				if open[h] == nil {
					open[h] = make(map[int]bool)
				}
				open[h][p] = true
				mu.Unlock()
			}(host, port, portStr)
		}
	}

	wg.Wait()
	return open
}
