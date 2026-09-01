package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ServerConfig defines the upstream configuration for a single MCP server.
type ServerConfig struct {
	Command      string            `json:"command,omitempty"`
	Args         []string          `json:"args,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	URL          string            `json:"url,omitempty"`
	ServerURL    string            `json:"serverUrl,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Description  string            `json:"description,omitempty"`
	Timeout      string            `json:"timeout,omitempty"`      // e.g. "30s", "1m"
	CacheTTL     string            `json:"cache_ttl,omitempty"`    // e.g. "5m", "1h"
	ReadOnly     bool              `json:"read_only,omitempty"`    // Blocks write/destructive mutations
	AllowedTools []string          `json:"allowed_tools,omitempty"`// Whitelist glob patterns
	BlockedTools []string          `json:"blocked_tools,omitempty"`// Blacklist glob patterns
}

// GetURL returns either URL or ServerURL.
func (s *ServerConfig) GetURL() string {
	if s.URL != "" {
		return s.URL
	}
	return s.ServerURL
}

// GetTimeout parses the timeout duration or returns the default.
func (s *ServerConfig) GetTimeout(defaultDur time.Duration) time.Duration {
	if s.Timeout == "" {
		return defaultDur
	}
	d, err := time.ParseDuration(s.Timeout)
	if err != nil {
		return defaultDur
	}
	return d
}

// GetCacheTTL parses the cache TTL duration or returns 0.
func (s *ServerConfig) GetCacheTTL() time.Duration {
	if s.CacheTTL == "" {
		return 0
	}
	d, err := time.ParseDuration(s.CacheTTL)
	if err != nil {
		return 0
	}
	return d
}

// SettingsConfig defines global proxy options.
type SettingsConfig struct {
	DefaultTimeout string `json:"defaultTimeout,omitempty"` // Default "60s"
}

// Config wraps the top-level MCP servers configuration.
type Config struct {
	Settings   SettingsConfig          `json:"settings,omitempty"`
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
