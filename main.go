package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var version = "0.3.0"

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func main() {
	configPath := flag.String("config", "", "Path to MCP servers configuration JSON file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mcp-search-proxy v%s\n", version)
		os.Exit(0)
	}

	if *configPath == "" {
		*configPath = os.Getenv("MCP_CONFIG_PATH")
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "Error: config path must be provided via -config flag or MCP_CONFIG_PATH env var")
		flag.Usage()
		os.Exit(1)
	}

	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down...")
		cancel()
	}()

	proxy := NewProxy(logger)
	defer proxy.Close()

	if err := proxy.InitUpstreams(ctx, cfg); err != nil {
		logger.Error("failed to initialize upstreams", "err", err)
	}

	s := server.NewMCPServer(
		"mcp-search-proxy",
		version,
		server.WithDescription("Dynamic search & execution proxy for upstream MCP servers"),
	)

	// Tool 1: list_servers
	listServersTool := mcp.NewTool(
		"list_servers",
		mcp.WithDescription("List all connected upstream MCP servers, their descriptions, and tool counts."),
	)
	s.AddTool(listServersTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		servers := proxy.ListServers()
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Connected Upstream Servers (%d):\n\n", len(servers)))
		for _, srv := range servers {
			desc := srv.Description
			if desc == "" {
				desc = "No description provided"
			}
			sb.WriteString(fmt.Sprintf("- **`%s`** (%d tools): %s\n", srv.Name, srv.ToolCount, desc))
		}
		return mcp.NewToolResultText(sb.String()), nil
	})

	// Tool 2: search_tools
	searchTool := mcp.NewTool(
		"search_tools",
		mcp.WithDescription("Search for available tools across upstream MCP servers. Returns tool names, signatures, and descriptions."),
		mcp.WithString("query", mcp.Required(), mcp.Description("Keywords describing what you need (e.g. 'email', 'nursery temperature', 'orders', or '*' for all).")),
	)

	s.AddTool(searchTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := request.RequireString("query")
		if err != nil {
			return mcp.NewToolResultError("missing required string parameter 'query'"), nil
		}
		summary := proxy.SearchToolsFormatConcise(query, 8)
		return mcp.NewToolResultText(summary), nil
	})

	// Tool 3: call_tool (relaxed & forgiving)
	callTool := mcp.NewTool(
		"call_tool",
		mcp.WithDescription("Execute any tool on upstream servers by name. Accepts arguments either nested under 'arguments' or at top-level."),
		mcp.WithString("tool_name", mcp.Required(), mcp.Description("Name of the tool to invoke (e.g. 'search_emails' or 'gmail:search_emails').")),
	)

	s.AddTool(callTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		toolName, err := request.RequireString("tool_name")
		if err != nil {
			return mcp.NewToolResultError("missing required string parameter 'tool_name'"), nil
		}

		args := request.GetArguments()
		if nested, ok := args["arguments"].(map[string]any); ok {
			args = nested
		} else {
			delete(args, "tool_name")
		}

		res, err := proxy.CallTool(ctx, toolName, args)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return res, nil
	})

	// Tool 4: describe_tool (optional schema inspection)
	describeTool := mcp.NewTool(
		"describe_tool",
		mcp.WithDescription("Get the detailed input schema and parameter descriptions for a single tool."),
		mcp.WithString("tool_name", mcp.Required(), mcp.Description("Exact name of the tool to inspect.")),
	)

	s.AddTool(describeTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		toolName, err := request.RequireString("tool_name")
		if err != nil {
			return mcp.NewToolResultError("missing parameter 'tool_name'"), nil
		}

		toolDef, srv, ok := proxy.GetTool(toolName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("tool %q not found", toolName)), nil
		}

		data, _ := json.MarshalIndent(map[string]any{
			"server":      srv,
			"name":        toolDef.Name,
			"description": toolDef.Description,
			"inputSchema": toolDef.InputSchema,
		}, "", "  ")

		return mcp.NewToolResultText(string(data)), nil
	})

	logger.Info("starting stdio server loop for mcp-search-proxy")

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			logger.Error("error reading stdin", "err", err)
			break
		}

		var rpcReq jsonRPCRequest
		if err := json.Unmarshal(line, &rpcReq); err != nil {
			continue
		}

		// Direct tool execution passthrough
		if rpcReq.Method == "tools/call" && rpcReq.Params != nil {
			var tp toolCallParams
			if err := json.Unmarshal(rpcReq.Params, &tp); err == nil {
				if tp.Name != "list_servers" && tp.Name != "search_tools" && tp.Name != "call_tool" && tp.Name != "describe_tool" {
					if proxy.HasTool(tp.Name) {
						logger.Info("transparent direct passthrough execution", "tool", tp.Name)
						callRes, callErr := proxy.CallTool(ctx, tp.Name, tp.Arguments)
						if callErr != nil {
							callRes = mcp.NewToolResultError(callErr.Error())
						}

						respMap := map[string]any{
							"jsonrpc": "2.0",
							"id":      rpcReq.ID,
							"result":  callRes,
						}
						respBytes, _ := json.Marshal(respMap)
						respBytes = append(respBytes, '\n')
						_, _ = os.Stdout.Write(respBytes)
						continue
					}
				}
			}
		}

		resp := s.HandleMessage(ctx, line)
		if resp != nil {
			respBytes, err := json.Marshal(resp)
			if err == nil {
				respBytes = append(respBytes, '\n')
				_, _ = os.Stdout.Write(respBytes)
			}
		}
	}
}
