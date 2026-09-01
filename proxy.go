package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

// RegisteredTool wraps a tool and the client that provides it.
type RegisteredTool struct {
	ServerName string
	Tool       mcp.Tool
	Client     *client.Client
}

// Proxy manages upstream MCP clients and tool indexing.
type Proxy struct {
	logger  *slog.Logger
	mu      sync.RWMutex
	clients map[string]*client.Client
	tools   map[string]*RegisteredTool
}

// NewProxy creates a new Proxy instance.
func NewProxy(logger *slog.Logger) *Proxy {
	return &Proxy{
		logger:  logger,
		clients: make(map[string]*client.Client),
		tools:   make(map[string]*RegisteredTool),
	}
}

// InitUpstreams connects to all configured upstream MCP servers concurrently and indexes their tools.
func (p *Proxy) InitUpstreams(ctx context.Context, cfg *Config) error {
	var wg sync.WaitGroup

	for name, srv := range cfg.MCPServers {
		wg.Add(1)
		go func(serverName string, s ServerConfig) {
			defer wg.Done()
			p.initSingleUpstream(ctx, serverName, s)
		}(name, srv)
	}

	wg.Wait()

	p.mu.RLock()
	totalTools := len(p.tools)
	totalClients := len(p.clients)
	p.mu.RUnlock()

	p.logger.Info("upstream initialization complete", "servers", totalClients, "total_tools", totalTools)
	return nil
}

func (p *Proxy) initSingleUpstream(ctx context.Context, name string, srv ServerConfig) {
	p.logger.Info("connecting to upstream server", "server", name)

	var (
		c   *client.Client
		err error
	)

	if srv.Command != "" {
		var envSlice []string
		for _, e := range os.Environ() {
			envSlice = append(envSlice, e)
		}
		for k, v := range srv.Env {
			envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
		}
		c, err = client.NewStdioMCPClient(srv.Command, envSlice, srv.Args...)
		if err != nil {
			p.logger.Error("failed to create stdio client", "server", name, "err", err)
			return
		}
	} else if srv.GetURL() != "" {
		// Try Streamable HTTP transport first (modern MCP HTTP spec)
		var httpOpts []transport.StreamableHTTPCOption
		if len(srv.Headers) > 0 {
			httpOpts = append(httpOpts, transport.WithHTTPHeaders(srv.Headers))
		}
		c, err = client.NewStreamableHttpClient(srv.GetURL(), httpOpts...)
		if err == nil {
			startCtx, cancelStart := context.WithTimeout(ctx, 10*time.Second)
			if startErr := c.Start(startCtx); startErr != nil {
				cancelStart()
				_ = c.Close()
				// Fallback to legacy SSE transport
				var sseOpts []transport.ClientOption
				if len(srv.Headers) > 0 {
					sseOpts = append(sseOpts, transport.WithHeaders(srv.Headers))
				}
				c, err = client.NewSSEMCPClient(srv.GetURL(), sseOpts...)
				if err != nil {
					p.logger.Error("failed to create sse client fallback", "server", name, "err", err)
					return
				}
				sseStartCtx, cancelSSE := context.WithTimeout(ctx, 10*time.Second)
				if err = c.Start(sseStartCtx); err != nil {
					cancelSSE()
					p.logger.Error("failed to start sse transport", "server", name, "err", err)
					_ = c.Close()
					return
				}
				cancelSSE()
			} else {
				cancelStart()
			}
		}
	} else {
		p.logger.Warn("server has neither command nor url specified", "server", name)
		return
	}

	// Initialize upstream connection
	initCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "mcp-search-proxy",
		Version: "0.1.0",
	}

	_, err = c.Initialize(initCtx, initReq)
	cancel()
	if err != nil {
		p.logger.Error("failed to initialize upstream server", "server", name, "err", err)
		_ = c.Close()
		return
	}

	// List tools
	listCtx, cancelList := context.WithTimeout(ctx, 10*time.Second)
	toolsResult, err := c.ListTools(listCtx, mcp.ListToolsRequest{})
	cancelList()
	if err != nil {
		p.logger.Error("failed to list tools from upstream", "server", name, "err", err)
		_ = c.Close()
		return
	}

	p.mu.Lock()
	p.clients[name] = c
	for _, tool := range toolsResult.Tools {
		p.tools[tool.Name] = &RegisteredTool{
			ServerName: name,
			Tool:       tool,
			Client:     c,
		}
		p.logger.Debug("indexed tool", "server", name, "tool", tool.Name)
	}
	p.mu.Unlock()

	p.logger.Info("connected and indexed upstream", "server", name, "tool_count", len(toolsResult.Tools))
}

// SearchTools finds tools matching a keyword query.
func (p *Proxy) SearchTools(query string) []map[string]any {
	p.mu.RLock()
	defer p.mu.RUnlock()

	query = strings.TrimSpace(strings.ToLower(query))
	tokens := strings.Fields(query)

	var results []map[string]any

	for name, reg := range p.tools {
		matched := false
		if query == "" || query == "*" {
			matched = true
		} else {
			nameLower := strings.ToLower(name)
			descLower := strings.ToLower(reg.Tool.Description)
			serverLower := strings.ToLower(reg.ServerName)

			for _, t := range tokens {
				if strings.Contains(nameLower, t) ||
					strings.Contains(descLower, t) ||
					strings.Contains(serverLower, t) {
					matched = true
					break
				}
			}
		}

		if matched {
			results = append(results, map[string]any{
				"server":      reg.ServerName,
				"name":        reg.Tool.Name,
				"description": reg.Tool.Description,
				"inputSchema": reg.Tool.InputSchema,
			})
		}
	}

	return results
}

// CallTool routes a tool call to the owning upstream client.
func (p *Proxy) CallTool(ctx context.Context, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	p.mu.RLock()
	reg, ok := p.tools[toolName]
	p.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("tool %q not found across connected upstream servers", toolName)
	}

	req := mcp.CallToolRequest{}
	req.Params.Name = toolName
	req.Params.Arguments = args

	p.logger.Info("forwarding call to upstream", "server", reg.ServerName, "tool", toolName)
	return reg.Client.CallTool(ctx, req)
}

// Close closes all upstream clients.
func (p *Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for name, c := range p.clients {
		p.logger.Info("closing upstream client", "server", name)
		_ = c.Close()
	}
}
