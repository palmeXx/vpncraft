package app

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	lookupTimeout     = 2 * time.Second
	lookupConcurrency = 16
)

// LookupNames resolves host names of addrs via reverse DNS (PTR). VPNs with
// their own DNS (e.g. Tailscale MagicDNS) answer for their peers. Addresses
// without a PTR record are omitted from the result.
func LookupNames(ctx context.Context, addrs []netip.Addr) map[netip.Addr]string {
	return lookupNames(ctx, addrs, net.DefaultResolver.LookupAddr)
}

func lookupNames(ctx context.Context, addrs []netip.Addr, lookup func(context.Context, string) ([]string, error)) map[netip.Addr]string {
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		names = make(map[netip.Addr]string, len(addrs))
		sem   = make(chan struct{}, lookupConcurrency)
	)
	for _, a := range addrs {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return names
		}
		wg.Go(func() {
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
			defer cancel()
			res, err := lookup(lctx, a.String())
			if err != nil || len(res) == 0 {
				return
			}
			mu.Lock()
			names[a] = strings.TrimSuffix(res[0], ".")
			mu.Unlock()
		})
	}
	wg.Wait()
	return names
}
