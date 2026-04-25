package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// ClientConfig holds the full client configuration.
type ClientConfig struct {
	General  GeneralConfig  `toml:"general"`
	DNS      DNSConfig      `toml:"dns"`
	VPN      VPNConfig      `toml:"vpn"`
	Logging  LoggingConfig  `toml:"logging"`
}

type GeneralConfig struct {
	ServerAddress string `toml:"server_address"`
	ServerPort    int    `toml:"server_port"`
	AuthToken     string `toml:"auth_token"`
	Reconnect     bool   `toml:"reconnect"`
	ReconnectDelay int   `toml:"reconnect_delay"`
}

type DNSConfig struct {
	Enabled       bool     `toml:"enabled"`
	ListenAddress string   `toml:"listen_address"`
	ListenPort    int      `toml:"listen_port"`
	UpstreamDNS   []string `toml:"upstream_dns"`
	FakeIPRange   string   `toml:"fake_ip_range"`
}

type VPNConfig struct {
	Enabled    bool   `toml:"enabled"`
	Interface  string `toml:"interface"`
	MTU        int    `toml:"mtu"`
	LocalIP    string `toml:"local_ip"`
	SubnetMask string `toml:"subnet_mask"`
}

type LoggingConfig struct {
	Level  string `toml:"level"`
	File   string `toml:"file"`
	Stdout bool   `toml:"stdout"`
}

// Load reads and parses a TOML config file from the given path.
func Load(path string) (*ClientConfig, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	var cfg ClientConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// Validate checks required fields and applies sensible defaults.
func (c *ClientConfig) Validate() error {
	if c.General.ServerAddress == "" {
		return fmt.Errorf("general.server_address is required")
	}
	if c.General.ServerPort <= 0 || c.General.ServerPort > 65535 {
		return fmt.Errorf("general.server_port must be between 1 and 65535")
	}
	if c.General.AuthToken == "" {
		return fmt.Errorf("general.auth_token is required")
	}
	if c.DNS.Enabled && c.DNS.ListenPort <= 0 {
		c.DNS.ListenPort = 5300
	}
	if c.VPN.Enabled && c.VPN.MTU == 0 {
		c.VPN.MTU = 1500
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	return nil
}
