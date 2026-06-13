package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the single config file format for both server and client mode
type Config struct {
	Mode string `yaml:"mode"`

	// shared
	Password    string        `yaml:"password"`
	PortHopping HopConfig     `yaml:"port_hopping"`
	Congestion  CongestionCfg `yaml:"congestion"`
	Traffic     TrafficConfig `yaml:"traffic"`

	// server
	Listen     string     `yaml:"listen"`
	TLS        TLSConfig  `yaml:"tls"`
	ECH        ECHConfig  `yaml:"ech"`
	Masquerade MasqConfig `yaml:"masquerade"`

	// client
	Server       string `yaml:"server"`
	ECHConfigB64 string `yaml:"ech_config"`
	SOCKS5Listen string `yaml:"socks5_listen"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		Listen:       ":443",
		SOCKS5Listen: "127.0.0.1:1080",
		ECH:          ECHConfig{PublicName: "cloudflare.com"},
		Traffic:      TrafficConfig{Profile: "browse"},
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.Mode != "server" && cfg.Mode != "client" {
		return nil, fmt.Errorf("mode must be \"server\" or \"client\", got %q", cfg.Mode)
	}
	return cfg, nil
}

func (c *Config) AsServerConfig() *ServerConfig {
	return &ServerConfig{
		Listen:      c.Listen,
		Password:    c.Password,
		TLS:         c.TLS,
		ECH:         c.ECH,
		Masquerade:  c.Masquerade,
		PortHopping: c.PortHopping,
		Congestion:  c.Congestion,
		Traffic:     c.Traffic,
	}
}

func (c *Config) AsClientConfig() *ClientConfig {
	return &ClientConfig{
		Server:       c.Server,
		Password:     c.Password,
		ECHConfig:    c.ECHConfigB64,
		SOCKS5Listen: c.SOCKS5Listen,
		Traffic:      c.Traffic,
		PortHopping:  c.PortHopping,
	}
}
