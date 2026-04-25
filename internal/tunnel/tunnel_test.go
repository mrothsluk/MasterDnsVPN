package tunnel_test

import (
	"net"
	"testing"
	"time"

	"github.com/masterking32/MasterDnsVPN/internal/tunnel"
)

func TestNew(t *testing.T) {
	tn := tunnel.New("127.0.0.1:9999", 5*time.Second)
	if tn.ServerAddr != "127.0.0.1:9999" {
		t.Errorf("expected ServerAddr 127.0.0.1:9999, got %s", tn.ServerAddr)
	}
	if tn.Status() != tunnel.StatusDisconnected {
		t.Errorf("expected status disconnected, got %s", tn.Status())
	}
}

func TestConnect_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()

	tn := tunnel.New(ln.Addr().String(), 2*time.Second)
	if err := tn.Connect(); err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	defer tn.Close()

	if tn.Status() != tunnel.StatusConnected {
		t.Errorf("expected status connected, got %s", tn.Status())
	}
	if tn.Conn() == nil {
		t.Error("expected non-nil Conn after successful connect")
	}
}

func TestConnect_Failure(t *testing.T) {
	tn := tunnel.New("127.0.0.1:1", 500*time.Millisecond)
	err := tn.Connect()
	if err == nil {
		t.Fatal("expected error connecting to closed port")
	}
	if tn.Status() != tunnel.StatusError {
		t.Errorf("expected status error, got %s", tn.Status())
	}
}

func TestClose_Idempotent(t *testing.T) {
	tn := tunnel.New("127.0.0.1:9999", time.Second)
	if err := tn.Close(); err != nil {
		t.Errorf("Close on disconnected tunnel should not error: %v", err)
	}
}

func TestStatusString(t *testing.T) {
	cases := []struct {
		s    tunnel.Status
		want string
	}{
		{tunnel.StatusDisconnected, "disconnected"},
		{tunnel.StatusConnecting, "connecting"},
		{tunnel.StatusConnected, "connected"},
		{tunnel.StatusError, "error"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("Status(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}
