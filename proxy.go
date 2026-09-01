package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
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
		Version: "0.2.0",
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

// HasTool returns true if the tool is known on any upstream server.
func (p *Proxy) HasTool(toolName string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.tools[toolName]
	return ok
}

// GetTool returns the tool definition.
func (p *Proxy) GetTool(toolName string) (mcp.Tool, string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	reg, ok := p.tools[toolName]
	if !ok {
		return mcp.Tool{}, "", false
	}
	return reg.Tool, reg.ServerName, true
}

// SearchToolsFormatConcise formats search results into compact, readable signatures.
func (p *Proxy) SearchToolsFormatConcise(query string, limit int) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	query = strings.TrimSpace(strings.ToLower(query))
	tokens := strings.Fields(query)

	type matchItem struct {
		score int
		reg   *RegisteredTool
	}

	var matches []matchItem

	for name, reg := range p.tools {
		score := 0
		if query == "" || query == "*" {
			score = 1
		} else {
			nameLower := strings.ToLower(name)
			descLower := strings.ToLower(reg.Tool.Description)
			serverLower := strings.ToLower(reg.ServerName)

			for _, t := range tokens {
				if nameLower == t {
					score += 10
				} else if strings.Contains(nameLower, t) {
					score += 5
				}
				if strings.Contains(serverLower, t) {
					score += 3
				}
				if strings.Contains(descLower, t) {
					score += 2
				}
			}
		}

		if score > 0 {
			matches = append(matches, matchItem{score: score, reg: reg})
		}
	}

	if len(matches) == 0 {
		return fmt.Sprintf("No tools found matching %q. Try broader keywords or '*' to list all.", query)
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return matches[i].reg.Tool.Name < matches[j].reg.Tool.Name
	})

	if limit <= 0 || limit > len(matches) {
		limit = len(matches)
	}
	if limit > 8 && query != "*" {
		limit = 8
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d matching tools (showing top %d):\n\n", len(matches), limit))

	for i := 0; i < limit; i++ {
		t := matches[i].reg.Tool
		server := matches[i].reg.ServerName

		// Extract compact param signature
		params := extractParamSignature(t.InputSchema)
		desc := strings.TrimSpace(t.Description)
		if len(desc) > 100 {
			desc = desc[:97] + "..."
		}

		sb.WriteString(fmt.Sprintf("- **`%s`** (%s)\n", t.Name, server))
		if params != "" {
			sb.WriteString(fmt.Sprintf("  `%s(%s)`\n", t.Name, params))
		}
		if desc != "" {
			sb.WriteString(fmt.Sprintf("  %s\n", desc))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("To invoke any tool above: call it directly by name or via `call_tool(tool_name=\"...\")`.")
	return sb.String()
}

func extractParamSignature(schema mcp.ToolInputSchema) string {
	props := schema.Properties; ok := true
	if !ok || len(props) == 0 {
		return ""
	}

	reqMap := make(map[string]bool)
	for _, r := range schema.Required {
		reqMap[r] = true
	}

	var parts []string
	for k, v := range props {
		typeStr := "any"
		if vm, ok := v.(map[string]any); ok {
			if t, ok := vm["type"].(string); ok {
				typeStr = t
			}
		}
		if reqMap[k] {
			parts = append(parts, fmt.Sprintf("%s: %s", k, typeStr))
		} else {
			parts = append(parts, fmt.Sprintf("%s?: %s", k, typeStr))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// CallTool routes a tool call to the owning upstream client.
func (p *Proxy) CallTool(ctx context.Context, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	p.mu.RLock()
	reg, ok := p.tools[toolName]
	p.mu.RUnlock()

	if !ok {
		// Find close matches to help the LLM self-correct
		suggestions := p.findSuggestions(toolName)
		if len(suggestions) > 0 {
			return nil, fmt.Errorf("tool %q not found. Did you mean: %s?", toolName, strings.Join(suggestions, ", "))
		}
		return nil, fmt.Errorf("tool %q not found across connected upstream servers", toolName)
	}

	req := mcp.CallToolRequest{}
	req.Params.Name = toolName
	req.Params.Arguments = args

	p.logger.Info("forwarding call to upstream", "server", reg.ServerName, "tool", toolName)
	return reg.Client.CallTool(ctx, req)
}

func (p *Proxy) findSuggestions(name string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	nameLower := strings.ToLower(name)
	var matches []string
	for t := range p.tools {
		tLower := strings.ToLower(t)
		if strings.Contains(tLower, nameLower) || strings.Contains(nameLower, tLower) {
			matches = append(matches, t)
			if len(matches) >= 3 {
				break
			}
		}
	}
	return matches
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
