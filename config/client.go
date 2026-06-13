package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ClientConfig struct {
	Server   string `yaml:"server"`   // required
	Password string `yaml:"password"` // required

	ECHConfig string `yaml:"ech_config"` // base64 ECHConfigList

	SOCKS5Listen string        `yaml:"socks5_listen"` // default: 127.0.0.1:1080
	Traffic      TrafficConfig `yaml:"traffic"`
	PortHopping  HopConfig     `yaml:"port_hopping"`
}

func LoadClient(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &ClientConfig{
		SOCKS5Listen: "127.0.0.1:1080",
		Traffic:      TrafficConfig{Profile: "browse"},
	}
	return cfg, yaml.Unmarshal(data, cfg)
}
