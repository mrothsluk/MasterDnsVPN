package tunnel_test

import (
	"net"
	"testing"
	"time"

	"github.com/masterking32/MasterDnsVPN/internal/tunnel"
)

func TestManager_AddAndGet(t *testing.T) {
	m := tunnel.NewManager()
	if err := m.Add("vpn1", "127.0.0.1:9000", time.Second); err != nil {
		t.Fatalf("Add() error: %v", err)
	}
	if m.Count() != 1 {
		t.Errorf("expected Count 1, got %d", m.Count())
	}
	tn, err := m.Get("vpn1")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if tn.ServerAddr != "127.0.0.1:9000" {
		t.Errorf("unexpected ServerAddr: %s", tn.ServerAddr)
	}
}

func TestManager_AddDuplicate(t *testing.T) {
	m := tunnel.NewManager()
	_ = m.Add("vpn1", "127.0.0.1:9000", time.Second)
	if err := m.Add("vpn1", "127.0.0.1:9001", time.Second); err == nil {
		t.Error("expected error on duplicate Add")
	}
}

func TestManager_GetMissing(t *testing.T) {
	m := tunnel.NewManager()
	if _, err := m.Get("missing"); err == nil {
		t.Error("expected error for missing tunnel")
	}
}

func TestManager_Remove(t *testing.T) {
	m := tunnel.NewManager()
	_ = m.Add("vpn1", "127.0.0.1:9000", time.Second)
	if err := m.Remove("vpn1"); err != nil {
		t.Fatalf("Remove() error: %v", err)
	}
	if m.Count() != 0 {
		t.Errorf("expected Count 0 after remove, got %d", m.Count())
	}
}

func TestManager_CloseAll(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	defer ln.Close()

	m := tunnel.NewManager()
	_ = m.Add("vpn1", ln.Addr().String(), time.Second)
	tn, _ := m.Get("vpn1")
	_ = tn.Connect()

	m.CloseAll()
	if tn.Status() != tunnel.StatusDisconnected {
		t.Errorf("expected disconnected after CloseAll, got %s", tn.Status())
	}
}
