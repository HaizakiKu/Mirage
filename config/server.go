package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Listen   string `yaml:"listen"`
	Password string `yaml:"password"` // required

	TLS  TLSConfig  `yaml:"tls"`
	ACME ACMEConfig `yaml:"acme"`
	ECH  ECHConfig  `yaml:"ech"`

	Masquerade MasqConfig `yaml:"masquerade"`

	PortHopping HopConfig     `yaml:"port_hopping"`
	Congestion  CongestionCfg `yaml:"congestion"`
	Traffic     TrafficConfig `yaml:"traffic"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type ECHConfig struct {
	PublicName string `yaml:"public_name"`
	KeyFile    string `yaml:"key_file"`
}

type MasqConfig struct {
	URL string `yaml:"url"`
}

type ACMEConfig struct {
	Domain   string `yaml:"domain"`
	Email    string `yaml:"email"`
	CacheDir string `yaml:"cache_dir"` // defaults to /etc/mirage/acme-cache
}

type HopConfig struct {
	Enabled   bool   `yaml:"enabled"`
	PortRange string `yaml:"port_range"`
}

type CongestionCfg struct {
	// Authenticated connections always use BBR. Jitter is the ±fraction by which
	// the BBR congestion window drifts (e.g. 0.15; values above 0.5 fall back to
	// 0.15). 0 disables jitter.
	Jitter float64 `yaml:"jitter"`
}

type TrafficConfig struct {
	// Profile controls padding/burst behavior
	Profile string `yaml:"profile"`
}

func LoadServer(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &ServerConfig{
		Listen: ":443",
		ECH:    ECHConfig{PublicName: "cloudflare.com"},
		Traffic: TrafficConfig{Profile: "browse"},
	}
	return cfg, yaml.Unmarshal(data, cfg)
}
