package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var version = "0.1.0"

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

	// Logging goes to stderr so stdout remains clean for MCP JSON-RPC
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

	// Create MCP server
	s := server.NewMCPServer(
		"mcp-search-proxy",
		version,
		server.WithDescription("Dynamic search & execution proxy for upstream MCP servers"),
	)

	// Tool 1: search_tools
	searchTool := mcp.NewTool(
		"search_tools",
		mcp.WithDescription("Search for available tools across upstream MCP servers. Returns tool names, descriptions, and input schemas matching your query. Use this first to discover capabilities."),
		mcp.WithString("query", mcp.Required(), mcp.Description("Keywords describing the tool or capability you are looking for (e.g. 'email', 'nursery temperature', 'orders', 'diapers', or '*' for all).")),
	)

	s.AddTool(searchTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := request.RequireString("query")
		if err != nil {
			return mcp.NewToolResultError("missing required string parameter 'query'"), nil
		}

		results := proxy.SearchTools(query)
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to serialize search results: %v", err)), nil
		}

		if len(results) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No tools found matching query %q. Try broader keywords or '*' to list all.", query)), nil
		}

		return mcp.NewToolResultText(string(data)), nil
	})

	// Tool 2: call_tool
	callTool := mcp.NewTool(
		"call_tool",
		mcp.WithDescription("Execute any discovered tool through the proxy by name. Pass the tool's required parameters in the arguments object."),
		mcp.WithString("tool_name", mcp.Required(), mcp.Description("Exact name of the tool to invoke (discovered via search_tools).")),
		mcp.WithObject("arguments", mcp.Description("Key-value map of arguments to pass to the target tool.")),
	)

	s.AddTool(callTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		toolName, err := request.RequireString("tool_name")
		if err != nil {
			return mcp.NewToolResultError("missing required string parameter 'tool_name'"), nil
		}

		args := request.GetArguments()
		// If nested under "arguments", extract it
		if nested, ok := args["arguments"].(map[string]any); ok {
			args = nested
		} else {
			// Remove tool_name from args map before forwarding
			delete(args, "tool_name")
		}

		res, err := proxy.CallTool(ctx, toolName, args)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("error executing %q on upstream: %v", toolName, err)), nil
		}

		return res, nil
	})

	logger.Info("starting stdio server for mcp-search-proxy")
	stdioServer := server.NewStdioServer(s)
	if err := stdioServer.Listen(ctx, os.Stdin, os.Stdout); err != nil {
		logger.Error("stdio server error", "err", err)
		os.Exit(1)
	}
}
