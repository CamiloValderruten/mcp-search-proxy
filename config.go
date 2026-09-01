package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// ServerConfig defines the upstream configuration for a single MCP server.
type ServerConfig struct {
	Command     string            `json:"command,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	URL         string            `json:"url,omitempty"`
	ServerURL   string            `json:"serverUrl,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Description string            `json:"description,omitempty"`
}

// GetURL returns either URL or ServerURL.
func (s *ServerConfig) GetURL() string {
	if s.URL != "" {
		return s.URL
	}
	return s.ServerURL
}

// Config wraps the top-level MCP servers configuration.
type Config struct {
	MCPServers map[string]ServerConfig `json:"mcpServers"`
}

// LoadConfig reads and parses the JSON configuration from disk, expanding environment variables.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	// Expand ${ENV_VAR} syntax in config
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := json.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config json: %w", err)
	}

	if len(cfg.MCPServers) == 0 {
		return nil, fmt.Errorf("no servers defined under 'mcpServers' in %s", path)
	}

	return &cfg, nil
}
