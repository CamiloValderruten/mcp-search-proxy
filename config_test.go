package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigGetURL(t *testing.T) {
	cfg1 := ServerConfig{URL: "http://example.com/mcp", ServerURL: "http://other.com/mcp"}
	if cfg1.GetURL() != "http://example.com/mcp" {
		t.Errorf("Expected URL to take precedence, got %s", cfg1.GetURL())
	}

	cfg2 := ServerConfig{ServerURL: "http://other.com/mcp"}
	if cfg2.GetURL() != "http://other.com/mcp" {
		t.Errorf("Expected ServerURL to be used, got %s", cfg2.GetURL())
	}
}

func TestConfigGetTimeout(t *testing.T) {
	defaultDur := 10 * time.Second

	cfg1 := ServerConfig{}
	if cfg1.GetTimeout(defaultDur) != defaultDur {
		t.Errorf("Expected default duration")
	}

	cfg2 := ServerConfig{Timeout: "5s"}
	if cfg2.GetTimeout(defaultDur) != 5*time.Second {
		t.Errorf("Expected 5s duration")
	}

	cfg3 := ServerConfig{Timeout: "invalid"}
	if cfg3.GetTimeout(defaultDur) != defaultDur {
		t.Errorf("Expected default duration for invalid timeout")
	}
}

func TestConfigGetCacheTTL(t *testing.T) {
	cfg1 := ServerConfig{}
	if cfg1.GetCacheTTL() != 0 {
		t.Errorf("Expected 0 cache TTL")
	}

	cfg2 := ServerConfig{CacheTTL: "10m"}
	if cfg2.GetCacheTTL() != 10*time.Minute {
		t.Errorf("Expected 10m cache TTL")
	}

	cfg3 := ServerConfig{CacheTTL: "invalid"}
	if cfg3.GetCacheTTL() != 0 {
		t.Errorf("Expected 0 cache TTL for invalid format")
	}
}

func TestConfigIdentityMatchesEmail(t *testing.T) {
	id := IdentityConfig{
		Emails: []string{"test@example.com", "alias@example.com"},
	}

	if !id.MatchesEmail("user1", "test@example.com") {
		t.Errorf("Expected true for matching email")
	}
	if !id.MatchesEmail("user1", "TEST@example.com") { // case insensitive
		t.Errorf("Expected true for matching case-insensitive email")
	}
	if !id.MatchesEmail("user1", "user1@domain.com") {
		t.Errorf("Expected true for matching ID prefix")
	}
	if id.MatchesEmail("user1", "other@example.com") {
		t.Errorf("Expected false for non-matching email")
	}
	if id.MatchesEmail("user1", "") {
		t.Errorf("Expected false for empty email")
	}
}

func TestConfigGetOpenAIKey(t *testing.T) {
	cfg1 := Config{Embeddings: EmbeddingsConfig{APIKey: "key-1"}}
	if cfg1.GetOpenAIKey() != "key-1" {
		t.Errorf("Expected key-1")
	}

	cfg2 := Config{Settings: SettingsConfig{OpenAIKey: "key-2"}}
	if cfg2.GetOpenAIKey() != "key-2" {
		t.Errorf("Expected key-2")
	}

	os.Setenv("OPENAI_API_KEY", "key-3")
	defer os.Unsetenv("OPENAI_API_KEY")
	cfg3 := Config{}
	if cfg3.GetOpenAIKey() != "key-3" {
		t.Errorf("Expected key-3")
	}
}

func TestConfigLoadConfig(t *testing.T) {
	tmp, err := os.MkdirTemp("", "config-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	validJSON := `{
		"mcpServers": {
			"test": { "command": "echo" }
		}
	}`
	validPath := filepath.Join(tmp, "valid.json")
	_ = os.WriteFile(validPath, []byte(validJSON), 0644)

	invalidJSON := `{ "mcpServers": }`
	invalidPath := filepath.Join(tmp, "invalid.json")
	_ = os.WriteFile(invalidPath, []byte(invalidJSON), 0644)

	noServersJSON := `{}`
	noServersPath := filepath.Join(tmp, "noservers.json")
	_ = os.WriteFile(noServersPath, []byte(noServersJSON), 0644)

	cfg, err := LoadConfig(validPath)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(cfg.MCPServers) != 1 {
		t.Errorf("Expected 1 server")
	}

	_, err = LoadConfig(invalidPath)
	if err == nil {
		t.Errorf("Expected error for invalid json")
	}

	_, err = LoadConfig(noServersPath)
	if err == nil {
		t.Errorf("Expected error for missing servers")
	}

	_, err = LoadConfig("non_existent_file.json")
	if err == nil {
		t.Errorf("Expected error for missing file")
	}
}
