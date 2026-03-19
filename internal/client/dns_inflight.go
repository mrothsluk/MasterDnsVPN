// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"time"

	"masterdnsvpn-go/internal/inflight"
)

type dnsInflightEntry = inflight.Entry[struct{}]

type dnsInflightManager struct {
	inner *inflight.Manager[struct{}]
}

func newDNSInflightManager(timeout time.Duration) *dnsInflightManager {
	return &dnsInflightManager{
		inner: inflight.New[struct{}](timeout, 30*time.Second, nil),
	}
}

func (m *dnsInflightManager) Acquire(cacheKey []byte, now time.Time) (*dnsInflightEntry, bool) {
	if m == nil {
		return nil, false
	}
	return m.inner.Acquire(cacheKey, now)
}

func (m *dnsInflightManager) Begin(cacheKey []byte, now time.Time) bool {
	if m == nil {
		return false
	}
	return m.inner.Begin(cacheKey, now)
}

func (m *dnsInflightManager) Resolve(cacheKey []byte) {
	if m == nil {
		return
	}
	m.inner.Resolve(cacheKey, struct{}{}, false)
}

func (m *dnsInflightManager) Complete(cacheKey []byte) {
	m.Resolve(cacheKey)
}

func (m *dnsInflightManager) Wait(entry *dnsInflightEntry, timeout time.Duration) bool {
	if m == nil {
		return false
	}
	_, ok := m.inner.Wait(entry, timeout)
	return ok
}
