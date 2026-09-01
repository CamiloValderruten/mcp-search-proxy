package main

import (
	"log/slog"
	"os"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestSearchTools(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	p := NewProxy(logger)

	p.tools["read_email"] = &RegisteredTool{
		ServerName: "gmail",
		Tool: mcp.Tool{
			Name:        "read_email",
			Description: "Read content of an email message by id",
		},
	}
	p.tools["get_orders"] = &RegisteredTool{
		ServerName: "orders",
		Tool: mcp.Tool{
			Name:        "get_orders",
			Description: "Fetch recent orders from Amazon or Target",
		},
	}
	p.tools["ha_get_state"] = &RegisteredTool{
		ServerName: "home-assistant",
		Tool: mcp.Tool{
			Name:        "ha_get_state",
			Description: "Get the current state of a smart home entity",
		},
	}

	// 1. Search email
	results := p.SearchTools("email")
	if len(results) != 1 {
		t.Fatalf("expected 1 result for 'email', got %d", len(results))
	}
	if results[0]["name"] != "read_email" {
		t.Errorf("expected 'read_email', got %v", results[0]["name"])
	}

	// 2. Search orders
	results = p.SearchTools("Amazon orders")
	if len(results) != 1 {
		t.Fatalf("expected 1 result for 'Amazon orders', got %d", len(results))
	}
	if results[0]["name"] != "get_orders" {
		t.Errorf("expected 'get_orders', got %v", results[0]["name"])
	}

	// 3. Search wild card
	results = p.SearchTools("*")
	if len(results) != 3 {
		t.Fatalf("expected 3 results for '*', got %d", len(results))
	}
}
