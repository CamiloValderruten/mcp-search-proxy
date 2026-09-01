package main

import (
	"context"
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
	ctx := context.Background()

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
	res := p.SearchToolsFormatConcise(ctx, "sql", 5)
	if !contains(res, "query_sql") {
		t.Fatalf("expected query_sql in search result, got: %s", res)
	}

	// Search by server description "relational"
	resRel := p.SearchToolsFormatConcise(ctx, "relational", 5)
	if !contains(resRel, "query_sql") {
		t.Fatalf("expected query_sql when searching for server description 'relational', got: %s", resRel)
	}

	// Wildcard search
	resAll := p.SearchToolsFormatConcise(ctx, "*", 5)
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

func TestIdentityRBAC(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewProxy(logger, 5*time.Second)

	p.serverDescs["github"] = "GitHub repos and PRs"
	p.tools["create_pr"] = &RegisteredTool{
		ServerName: "github",
		Tool: mcp.Tool{Name: "create_pr"},
	}

	p.serverDescs["orders"] = "Shopping orders"
	p.clients["github"] = nil; p.clients["orders"] = nil; p.tools["get_orders"] = &RegisteredTool{
		ServerName: "orders",
		Tool: mcp.Tool{Name: "get_orders"},
	}

	// 1. Restricted Identity: only allowed "orders"
	ctxRestricted := WithIdentity(context.Background(), "restricted-agent", IdentityConfig{
		AllowedServers: []string{"orders"},
		ReadOnly:       true,
	})

	// Check ListServers filtering
	servers := p.ListServers(ctxRestricted)
	if len(servers) != 1 || servers[0].Name != "orders" {
		t.Fatalf("expected only 'orders' server for restricted identity, got: %v", servers)
	}

	// Check SearchTools filtering: should find get_orders, but NOT create_pr
	searchRes := p.SearchToolsFormatConcise(ctxRestricted, "*", 10)
	if contains(searchRes, "create_pr") {
		t.Fatalf("restricted identity should NOT see create_pr in search results")
	}
	if !contains(searchRes, "get_orders") {
		t.Fatalf("restricted identity SHOULD see get_orders")
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
