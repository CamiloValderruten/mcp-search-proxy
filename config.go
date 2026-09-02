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
	CacheTTL     string             `json:"cache_ttl,omitempty"`    // e.g. "5m", "1h"
	ReadOnly     bool               `json:"read_only,omitempty"`    // Blocks write/destructive mutations
	AllowedTools []string           `json:"allowed_tools,omitempty"`// Whitelist glob patterns
	BlockedTools []string           `json:"blocked_tools,omitempty"`// Blacklist glob patterns
	AuthType     string             `json:"auth_type,omitempty"`    // "bearer_token" (default) or "oauth2_pkce_per_user"
	OAuth2       *OAuthServerConfig `json:"oauth2,omitempty"`       // Upstream OAuth 2.0 configuration
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

// IdentityConfig defines RBAC, upstream identity mappings, and dynamic credentials for a caller client.
type IdentityConfig struct {
	Token           string                       `json:"token,omitempty"`             // Bearer token for HTTP auth
	AllowedServers  []string                     `json:"allowed_servers,omitempty"`   // Whitelist of server names (supports "*")
	AllowedTools    []string                     `json:"allowed_tools,omitempty"`     // Whitelist of tool names/globs (supports "*")
	BlockedTools    []string                     `json:"blocked_tools,omitempty"`     // Blacklist of tool names/globs
	ReadOnly        bool                         `json:"read_only,omitempty"`         // If true, enforces read-only tool execution
	UpstreamUserMap map[string]string            `json:"upstream_user_map,omitempty"` // Map upstream server -> backend user/account id
	UpstreamHeaders map[string]map[string]string `json:"upstream_headers,omitempty"`  // Map upstream server -> headers with secret URIs (e.g. op://, env://)
}

// OAuthServerConfig defines upstream OAuth 2.0 configuration for user delegation.
type OAuthServerConfig struct {
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	AuthURL      string   `json:"auth_url,omitempty"`
	TokenURL     string   `json:"token_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// EmbeddingsConfig defines optional OpenAI-compatible vector embeddings for semantic search.
type EmbeddingsConfig struct {
	APIKey string `json:"apiKey,omitempty"` // OpenAI API Key (or env var OPENAI_API_KEY)
	Model  string `json:"model,omitempty"`  // Default: text-embedding-3-small
	URL    string `json:"url,omitempty"`    // Default: https://api.openai.com/v1/embeddings
}

// SettingsConfig defines global proxy options.
type SettingsConfig struct {
	DefaultTimeout string `json:"defaultTimeout,omitempty"` // Default "60s"
	AuthKey        string `json:"authKey,omitempty"`        // Global master auth key for HTTP mode
	OpenAIKey      string `json:"openAIKey,omitempty"`      // Alternative shorthand for embeddings API key
	VaultPath      string `json:"vaultPath,omitempty"`      // Path to encrypted vault file (default: ~/.config/mcp-search-proxy/vault.enc)
	VaultKey       string `json:"vaultKey,omitempty"`       // Master key or secret URI (e.g. op://..., env://...) for vault
	PublicURL      string `json:"publicUrl,omitempty"`      // Base public URL for OAuth callbacks (e.g. "http://localhost:8080")
}

// Config wraps the top-level MCP servers configuration.
type Config struct {
	Settings   SettingsConfig            `json:"settings,omitempty"`
	Embeddings EmbeddingsConfig          `json:"embeddings,omitempty"`
	Identities map[string]IdentityConfig `json:"identities,omitempty"`
	MCPServers map[string]ServerConfig   `json:"mcpServers"`
}

// GetOpenAIKey returns the API key from Embeddings, Settings, or OPENAI_API_KEY environment variable.
func (c *Config) GetOpenAIKey() string {
	if c.Embeddings.APIKey != "" {
		return c.Embeddings.APIKey
	}
	if c.Settings.OpenAIKey != "" {
		return c.Settings.OpenAIKey
	}
	return os.Getenv("OPENAI_API_KEY")
}

// LoadConfig reads and parses the JSON configuration from disk, expanding environment variables.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

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
