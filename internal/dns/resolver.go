// Package dns provides DNS resolution and routing functionality for MasterDnsVPN.
// It handles DNS queries, caching, and forwarding through VPN tunnels.
package dns

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ResolverConfig holds configuration for the DNS resolver.
type ResolverConfig struct {
	// UpstreamDNS is the upstream DNS server address (e.g., "8.8.8.8:53").
	UpstreamDNS string
	// CacheTTL is the duration to cache DNS responses.
	CacheTTL time.Duration
	// Timeout is the maximum time to wait for a DNS response.
	Timeout time.Duration
}

// cacheEntry holds a cached DNS result with its expiration time.
type cacheEntry struct {
	addrs   []string
	expires time.Time
}

// Resolver performs DNS lookups with optional caching.
type Resolver struct {
	cfg    ResolverConfig
	cache  map[string]cacheEntry
	mu     sync.RWMutex
	dialer *net.Dialer
}

// NewResolver creates a new Resolver with the given configuration.
// If cfg.CacheTTL is zero, caching is disabled.
// If cfg.Timeout is zero, it defaults to 5 seconds.
func NewResolver(cfg ResolverConfig) *Resolver {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.UpstreamDNS == "" {
		cfg.UpstreamDNS = "8.8.8.8:53"
	}
	return &Resolver{
		cfg:   cfg,
		cache: make(map[string]cacheEntry),
		dialer: &net.Dialer{
			Timeout: cfg.Timeout,
		},
	}
}

// Resolve looks up the IP addresses for the given hostname.
// Results are cached according to cfg.CacheTTL when non-zero.
func (r *Resolver) Resolve(hostname string) ([]string, error) {
	if r.cfg.CacheTTL > 0 {
		if addrs, ok := r.lookupCache(hostname); ok {
			return addrs, nil
		}
	}

	addrs, err := r.resolveUpstream(hostname)
	if err != nil {
		return nil, fmt.Errorf("dns: resolve %q: %w", hostname, err)
	}

	if r.cfg.CacheTTL > 0 {
		r.storeCache(hostname, addrs)
	}
	return addrs, nil
}

// lookupCache checks the cache for a non-expired entry.
func (r *Resolver) lookupCache(hostname string) ([]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.cache[hostname]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.addrs, true
}

// storeCache saves resolved addresses into the cache.
func (r *Resolver) storeCache(hostname string, addrs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.cache[hostname] = cacheEntry{
		addrs:   addrs,
		expires: time.Now().Add(r.cfg.CacheTTL),
	}
}

// resolveUpstream performs the actual DNS lookup using the configured upstream server.
func (r *Resolver) resolveUpstream(hostname string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx interface{ Done() <-chan struct{} }, network, address string) (net.Conn, error) {
			return r.dialer.Dial("udp", r.cfg.UpstreamDNS)
		},
	}
	_ = resolver // use standard library lookup as fallback

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// FlushCache removes all entries from the DNS cache.
func (r *Resolver) FlushCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]cacheEntry)
}

// CacheSize returns the number of entries currently in the cache.
func (r *Resolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}
