package tunnel

import (
	"fmt"
	"sync"
	"time"
)

// Manager keeps track of multiple named tunnels.
type Manager struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel
}

// NewManager creates an empty tunnel Manager.
func NewManager() *Manager {
	return &Manager{
		tunnels: make(map[string]*Tunnel),
	}
}

// Add registers a new tunnel by name. Returns an error if the name is already taken.
func (m *Manager) Add(name, serverAddr string, dialTimeout time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.tunnels[name]; exists {
		return fmt.Errorf("manager: tunnel %q already exists", name)
	}
	m.tunnels[name] = New(serverAddr, dialTimeout)
	return nil
}

// Get returns the tunnel with the given name, or an error if not found.
func (m *Manager) Get(name string) (*Tunnel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tunnels[name]
	if !ok {
		return nil, fmt.Errorf("manager: tunnel %q not found", name)
	}
	return t, nil
}

// Remove closes and removes a tunnel by name.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[name]
	if !ok {
		return fmt.Errorf("manager: tunnel %q not found", name)
	}
	_ = t.Close()
	delete(m.tunnels, name)
	return nil
}

// CloseAll closes every managed tunnel.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tunnels {
		_ = t.Close()
	}
}

// Count returns the number of registered tunnels.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tunnels)
}
