package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	URL        string `json:"url"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	Token      string `json:"token"`
	PrivateKey string `json:"privateKey"`
	Status     string `json:"status"`
}

func configPath() (string, error) {
	if p := os.Getenv("WARDENBROKER_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wardenbroker", "agent.json"), nil
}

var errNotRegistered = errors.New("this machine is not registered with a broker yet: run `wardenbroker register --url <broker> --name <agent name>`")

func loadConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNotRegistered
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", path, err)
	}
	return &c, nil
}

func (c *Config) save() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *Config) key() (*ecdh.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key in config: %w", err)
	}
	return ecdh.P256().NewPrivateKey(raw)
}
