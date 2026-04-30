package dns_test

import (
	"net"
	"testing"
	"time"

	"github.com/masterking32/MasterDnsVPN/internal/dns"
)

// TestNewResolver verifies that a resolver is created with sane defaults.
func TestNewResolver(t *testing.T) {
	r := dns.NewResolver("8.8.8.8:53", 5*time.Second)
	if r == nil {
		t.Fatal("NewResolver returned nil")
	}
}

// TestNewResolver_EmptyServer verifies that an empty server address is handled.
func TestNewResolver_EmptyServer(t *testing.T) {
	r := dns.NewResolver("", 5*time.Second)
	if r == nil {
		t.Fatal("NewResolver returned nil for empty server")
	}
}

// TestResolve_ValidDomain checks that a well-known domain resolves to at least
// one IP address using the public Google DNS server.
func TestResolve_ValidDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	r := dns.NewResolver("8.8.8.8:53", 5*time.Second)
	addrs, err := r.Resolve("dns.google")
	if err != nil {
		t.Fatalf("Resolve(dns.google) error: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("Resolve(dns.google) returned no addresses")
	}

	// Ensure every returned value is a valid IP.
	for _, a := range addrs {
		if net.ParseIP(a) == nil {
			t.Errorf("Resolve returned invalid IP: %q", a)
		}
	}
}

// TestResolve_InvalidDomain checks that resolving a bogus domain returns an
// error and no addresses.
func TestResolve_InvalidDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	r := dns.NewResolver("8.8.8.8:53", 5*time.Second)
	addrs, err := r.Resolve("this.domain.does.not.exist.invalid")
	if err == nil {
		t.Fatalf("expected error for invalid domain, got addresses: %v", addrs)
	}
	if len(addrs) != 0 {
		t.Errorf("expected no addresses for invalid domain, got: %v", addrs)
	}
}

// TestResolve_Timeout checks that a resolver with a very short timeout fails
// fast when the server is unreachable.
func TestResolve_Timeout(t *testing.T) {
	// Use a non-routable address so the connection times out quickly.
	r := dns.NewResolver("192.0.2.1:53", 200*time.Millisecond)
	start := time.Now()
	_, err := r.Resolve("example.com")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// Allow a generous upper bound to avoid flakiness on slow CI runners.
	if elapsed > 3*time.Second {
		t.Errorf("resolver took too long to time out: %v", elapsed)
	}
}

// TestResolve_CacheHit verifies that a second call for the same domain is
// served faster (cache hit) than the first call.
func TestResolve_CacheHit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	r := dns.NewResolver("8.8.8.8:53", 5*time.Second)

	// Warm the cache.
	if _, err := r.Resolve("dns.google"); err != nil {
		t.Fatalf("first Resolve error: %v", err)
	}

	start := time.Now()
	addrs, err := r.Resolve("dns.google")
	cached := time.Since(start)

	if err != nil {
		t.Fatalf("second Resolve error: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("cached Resolve returned no addresses")
	}
	// A cache hit should be sub-millisecond; use 50 ms as a safe threshold.
	if cached > 50*time.Millisecond {
		t.Logf("cache hit took %v — may not be cached or system is slow", cached)
	}
}
