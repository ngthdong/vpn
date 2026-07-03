package config

import (
	"fmt"
	"os"
	"time"

	"go.yaml.in/yaml/v2"
)

type ServerConfig struct {
	Server struct {
		Listen string `yaml:"listen"`
	} `yaml:"server"`

	TUN struct {
		Name    string `yaml:"name"`
		Address string `yaml:"address"`
	} `yaml:"tun"`

	Metrics struct {
		Listen string `yaml:"listen"`
	} `yaml:"metrics"`

	NAT struct {
		TTL time.Duration `yaml:"ttl"`
	} `yaml:"nat"`
}

func LoadServer(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}
