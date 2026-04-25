package config

import (
	"os"
	"testing"
)

const validTOML = `
[general]
server_address = "vpn.example.com"
server_port = 8443
auth_token = "supersecrettoken"
reconnect = true
reconnect_delay = 5

[dns]
enabled = true
listen_address = "127.0.0.1"
listen_port = 5300
upstream_dns = ["8.8.8.8", "1.1.1.1"]
fake_ip_range = "198.18.0.0/15"

[vpn]
enabled = true
interface = "tun0"
mtu = 1400
local_ip = "10.8.0.2"
subnet_mask = "255.255.255.0"

[logging]
level = "debug"
stdout = true
`

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "mdvpn-config-*.toml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestLoad_ValidConfig(t *testing.T) {
	path := writeTempConfig(t, validTOML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if cfg.General.ServerAddress != "vpn.example.com" {
		t.Errorf("unexpected server address: %s", cfg.General.ServerAddress)
	}
	if cfg.VPN.MTU != 1400 {
		t.Errorf("expected MTU 1400, got %d", cfg.VPN.MTU)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected log level debug, got %s", cfg.Logging.Level)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoad_MissingServerAddress(t *testing.T) {
	toml := `
[general]
server_port = 8443
auth_token = "token"
`
	path := writeTempConfig(t, toml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for missing server_address")
	}
}

func TestValidate_DefaultsApplied(t *testing.T) {
	cfg := &ClientConfig{}
	cfg.General.ServerAddress = "example.com"
	cfg.General.ServerPort = 443
	cfg.General.AuthToken = "tok"
	cfg.DNS.Enabled = true
	cfg.DNS.ListenPort = 0
	cfg.VPN.Enabled = true
	cfg.VPN.MTU = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DNS.ListenPort != 5300 {
		t.Errorf("expected default DNS port 5300, got %d", cfg.DNS.ListenPort)
	}
	if cfg.VPN.MTU != 1500 {
		t.Errorf("expected default MTU 1500, got %d", cfg.VPN.MTU)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected default log level info, got %s", cfg.Logging.Level)
	}
}
