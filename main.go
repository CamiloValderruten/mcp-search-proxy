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
	"sync"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var version = "1.0.0"

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

	defaultTimeout := 60 * time.Second
	if cfg.Settings.DefaultTimeout != "" {
		if d, err := time.ParseDuration(cfg.Settings.DefaultTimeout); err == nil {
			defaultTimeout = d
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS Signals (SIGINT, SIGTERM for graceful shutdown; SIGHUP for hot-reload)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down proxy...")
		cancel()
	}()

	proxy := NewProxy(logger, defaultTimeout)
	defer proxy.Close()

	if err := proxy.InitUpstreams(ctx, cfg); err != nil {
		logger.Error("failed to initialize upstreams", "err", err)
	}

	// Listen for SIGHUP for hot-reloading
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupCh:
				logger.Info("received SIGHUP, reloading configuration...", "path", *configPath)
				if newCfg, err := LoadConfig(*configPath); err == nil {
					_ = proxy.ReloadConfig(ctx, newCfg)
				} else {
					logger.Error("failed to reload config on SIGHUP", "err", err)
				}
			}
		}
	}()

	s := server.NewMCPServer(
		"mcp-search-proxy",
		version,
		server.WithDescription("High-performance dynamic search and federated gateway for Model Context Protocol servers"),
	)

	// Tool 1: list_servers
	listServersTool := mcp.NewTool(
		"list_servers",
		mcp.WithDescription("List all connected upstream MCP servers, their descriptions, tool counts, and security policies."),
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
			roFlag := ""
			if srv.ReadOnly {
				roFlag = " `[read-only]`"
			}
			sb.WriteString(fmt.Sprintf("- **`%s`** (%d tools)%s: %s\n", srv.Name, srv.ToolCount, roFlag, desc))
		}
		return mcp.NewToolResultText(sb.String()), nil
	})

	// Tool 2: search_tools
	searchTool := mcp.NewTool(
		"search_tools",
		mcp.WithDescription("Search for available tools across all connected upstream MCP servers. Returns tool names, signatures, and descriptions."),
		mcp.WithString("query", mcp.Required(), mcp.Description("Keywords describing what you need (e.g. 'search', 'email', 'database', or '*' for all).")),
	)
	s.AddTool(searchTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := request.RequireString("query")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter 'query'"), nil
		}
		summary := proxy.SearchToolsFormatConcise(query, 8)
		return mcp.NewToolResultText(summary), nil
	})

	// Tool 3: call_tool
	callTool := mcp.NewTool(
		"call_tool",
		mcp.WithDescription("Execute any tool on upstream servers by name. Accepts arguments either nested under 'arguments' or at top-level."),
		mcp.WithString("tool_name", mcp.Required(), mcp.Description("Name of the tool to invoke (e.g. 'query_db' or 'postgres:query_db').")),
	)
	s.AddTool(callTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		toolName, err := request.RequireString("tool_name")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter 'tool_name'"), nil
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

	// Tool 4: describe_tool
	describeTool := mcp.NewTool(
		"describe_tool",
		mcp.WithDescription("Get the detailed input schema and parameter descriptions for a specific tool."),
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

	// Tool 5: get_metrics
	metricsTool := mcp.NewTool(
		"get_metrics",
		mcp.WithDescription("Get gateway performance metrics: total calls, cache hit ratio, error rates, and active upstreams."),
	)
	s.AddTool(metricsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		m := proxy.GetMetrics()
		data, _ := json.MarshalIndent(m, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	})

	// Tool 6: reload_config
	reloadTool := mcp.NewTool(
		"reload_config",
		mcp.WithDescription("Reload configuration from disk in-flight without restarting the proxy."),
	)
	s.AddTool(reloadTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		newCfg, err := LoadConfig(*configPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to load config from %s: %v", *configPath, err)), nil
		}
		if err := proxy.ReloadConfig(ctx, newCfg); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to reload upstreams: %v", err)), nil
		}
		return mcp.NewToolResultText("Configuration reloaded successfully."), nil
	})

	logger.Info("starting concurrent stdio server loop for mcp-search-proxy")

	var stdoutMu sync.Mutex
	writeOutput := func(b []byte) {
		stdoutMu.Lock()
		defer stdoutMu.Unlock()
		b = append(b, '\n')
		_, _ = os.Stdout.Write(b)
	}

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

		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)

		// Concurrent Request Multiplexing: process each request in a goroutine
		go func(data []byte) {
			var rpcReq jsonRPCRequest
			if err := json.Unmarshal(data, &rpcReq); err != nil {
				return
			}

			// Direct tool execution passthrough
			if rpcReq.Method == "tools/call" && rpcReq.Params != nil {
				var tp toolCallParams
				if err := json.Unmarshal(rpcReq.Params, &tp); err == nil {
					builtin := map[string]bool{
						"list_servers": true, "search_tools": true,
						"call_tool": true, "describe_tool": true,
						"get_metrics": true, "reload_config": true,
					}
					if !builtin[tp.Name] && proxy.HasTool(tp.Name) {
						logger.Debug("direct tool passthrough", "tool", tp.Name)
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
						writeOutput(respBytes)
						return
					}
				}
			}

			// Standard MCP server request handling
			resp := s.HandleMessage(ctx, data)
			if resp != nil {
				respBytes, err := json.Marshal(resp)
				if err == nil {
					writeOutput(respBytes)
				}
			}
		}(lineCopy)
	}
}
