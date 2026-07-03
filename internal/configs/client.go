package config

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v2"
)

type ClientConfig struct {
	Server struct {
		Address string `yaml:"address"`
	} `yaml:"server"`

	TUN struct {
		Name    string `yaml:"name"`
		Address string `yaml:"address"`
	} `yaml:"tun"`
}

func LoadClient(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}
