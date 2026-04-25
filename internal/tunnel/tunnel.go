package tunnel

import (
	"fmt"
	"net"
	"time"
)

// Status represents the current state of a tunnel connection.
type Status int

const (
	StatusDisconnected Status = iota
	StatusConnecting
	StatusConnected
	StatusError
)

func (s Status) String() string {
	switch s {
	case StatusDisconnected:
		return "disconnected"
	case StatusConnecting:
		return "connecting"
	case StatusConnected:
		return "connected"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// Tunnel holds state for a single VPN tunnel connection.
type Tunnel struct {
	ServerAddr string
	DialTimeout time.Duration
	conn        net.Conn
	status      Status
}

// New creates a new Tunnel with the given server address and dial timeout.
func New(serverAddr string, dialTimeout time.Duration) *Tunnel {
	return &Tunnel{
		ServerAddr:  serverAddr,
		DialTimeout: dialTimeout,
		status:      StatusDisconnected,
	}
}

// Connect establishes a TCP connection to the tunnel server.
func (t *Tunnel) Connect() error {
	t.status = StatusConnecting
	conn, err := net.DialTimeout("tcp", t.ServerAddr, t.DialTimeout)
	if err != nil {
		t.status = StatusError
		return fmt.Errorf("tunnel: connect to %s: %w", t.ServerAddr, err)
	}
	t.conn = conn
	t.status = StatusConnected
	return nil
}

// Close tears down the tunnel connection.
func (t *Tunnel) Close() error {
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	t.status = StatusDisconnected
	return err
}

// Status returns the current tunnel status.
func (t *Tunnel) Status() Status {
	return t.status
}

// Conn returns the underlying net.Conn (may be nil if not connected).
func (t *Tunnel) Conn() net.Conn {
	return t.conn
}
