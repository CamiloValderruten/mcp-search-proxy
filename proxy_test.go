package main

import (
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestSearchToolsFormatConcise(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewProxy(logger, 5*time.Second)

	p.serverDescs["database"] = "Relational SQL database queries and analytics"
	p.tools["query_sql"] = &RegisteredTool{
		ServerName: "database",
		Tool: mcp.Tool{
			Name:        "query_sql",
			Description: "Execute a read-only SQL query on the database",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"query": map[string]any{"type": "string"},
				},
				Required: []string{"query"},
			},
		},
	}

	p.serverDescs["github"] = "GitHub issues, PRs, and commits"
	p.tools["create_issue"] = &RegisteredTool{
		ServerName: "github",
		Tool: mcp.Tool{
			Name:        "create_issue",
			Description: "Create a new issue in a GitHub repository",
		},
	}

	// Search for "sql"
	res := p.SearchToolsFormatConcise("sql", 5)
	if !contains(res, "query_sql") {
		t.Fatalf("expected query_sql in search result, got: %s", res)
	}

	// Search by server description "relational"
	resRel := p.SearchToolsFormatConcise("relational", 5)
	if !contains(resRel, "query_sql") {
		t.Fatalf("expected query_sql when searching for server description 'relational', got: %s", resRel)
	}

	// Wildcard search
	resAll := p.SearchToolsFormatConcise("*", 5)
	if !contains(resAll, "query_sql") || !contains(resAll, "create_issue") {
		t.Fatalf("expected all tools in wildcard search, got: %s", resAll)
	}
}

func TestSecurityPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewProxy(logger, 5*time.Second)

	// Read-only server
	regRO := &RegisteredTool{
		ServerName: "production-db",
		Tool: mcp.Tool{
			Name: "delete_user",
		},
		ServerConfig: ServerConfig{
			ReadOnly: true,
		},
	}

	err := p.enforcePolicy(regRO, nil)
	if err == nil {
		t.Fatal("expected policy rejection for delete_user on read-only server")
	}

	// Blacklisted tool
	regBlacklist := &RegisteredTool{
		ServerName: "admin-tools",
		Tool: mcp.Tool{
			Name: "drop_database",
		},
		ServerConfig: ServerConfig{
			BlockedTools: []string{"drop_*"},
		},
	}

	errBL := p.enforcePolicy(regBlacklist, nil)
	if errBL == nil {
		t.Fatal("expected policy rejection for blacklisted tool drop_database")
	}
}

func TestEnvVarExpansion(t *testing.T) {
	os.Setenv("TEST_MCP_TOKEN", "secret123")
	defer os.Unsetenv("TEST_MCP_TOKEN")

	tmpFile, err := os.CreateTemp("", "mcp_cfg_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := `{
		"mcpServers": {
			"dummy": {
				"command": "echo",
				"args": ["${TEST_MCP_TOKEN}"]
			}
		}
	}`
	_ = os.WriteFile(tmpFile.Name(), []byte(content), 0644)

	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.MCPServers["dummy"].Args[0] != "secret123" {
		t.Fatalf("expected secret123, got %s", cfg.MCPServers["dummy"].Args[0])
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > 0 && len(substr) > 0 && (stringContains(s, substr))))
}

func stringContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
