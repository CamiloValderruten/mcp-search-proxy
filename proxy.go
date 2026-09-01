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

// ServerInfo holds metadata about an upstream server.
type ServerInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ToolCount   int    `json:"tool_count"`
}

// Proxy manages upstream MCP clients and tool indexing.
type Proxy struct {
	logger      *slog.Logger
	mu          sync.RWMutex
	clients     map[string]*client.Client
	tools       map[string]*RegisteredTool
	serverDescs map[string]string
}

// NewProxy creates a new Proxy instance.
func NewProxy(logger *slog.Logger) *Proxy {
	return &Proxy{
		logger:      logger,
		clients:     make(map[string]*client.Client),
		tools:       make(map[string]*RegisteredTool),
		serverDescs: make(map[string]string),
	}
}

// InitUpstreams connects to all configured upstream MCP servers concurrently and indexes their tools.
func (p *Proxy) InitUpstreams(ctx context.Context, cfg *Config) error {
	var wg sync.WaitGroup

	for name, srv := range cfg.MCPServers {
		p.mu.Lock()
		if srv.Description != "" {
			p.serverDescs[name] = srv.Description
		}
		p.mu.Unlock()

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

	initCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "mcp-search-proxy",
		Version: "0.3.0",
	}

	initResult, err := c.Initialize(initCtx, initReq)
	cancel()
	if err != nil {
		p.logger.Error("failed to initialize upstream server", "server", name, "err", err)
		_ = c.Close()
		return
	}

	// Capture upstream server description if provided and not explicitly overridden
	if srv.Description == "" && initResult != nil && initResult.ServerInfo.Description != "" {
		p.mu.Lock()
		p.serverDescs[name] = initResult.ServerInfo.Description
		p.mu.Unlock()
	}

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
		reg := &RegisteredTool{
			ServerName: name,
			Tool:       tool,
			Client:     c,
		}
		// Register by bare name
		p.tools[tool.Name] = reg
		// Also register by namespaced server:tool_name
		p.tools[name+":"+tool.Name] = reg
		p.logger.Debug("indexed tool", "server", name, "tool", tool.Name)
	}
	p.mu.Unlock()

	p.logger.Info("connected and indexed upstream", "server", name, "tool_count", len(toolsResult.Tools))
}

func (p *Proxy) HasTool(toolName string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.tools[toolName]
	return ok
}

func (p *Proxy) GetTool(toolName string) (mcp.Tool, string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	reg, ok := p.tools[toolName]
	if !ok {
		return mcp.Tool{}, "", false
	}
	return reg.Tool, reg.ServerName, true
}

// ListServers returns a clean list of connected servers with tool counts and descriptions.
func (p *Proxy) ListServers() []ServerInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	counts := make(map[string]int)
	for key, reg := range p.tools {
		// Only count bare names, not namespaced aliases
		if !strings.Contains(key, ":") {
			counts[reg.ServerName]++
		}
	}

	var servers []ServerInfo
	for name := range p.clients {
		servers = append(servers, ServerInfo{
			Name:        name,
			Description: p.serverDescs[name],
			ToolCount:   counts[name],
		})
	}

	sort.Slice(servers, func(i, j int) bool {
		return servers[i].Name < servers[j].Name
	})

	return servers
}

// SearchToolsFormatConcise formats search results using weighted multi-field relevance scoring.
func (p *Proxy) SearchToolsFormatConcise(query string, limit int) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	query = strings.TrimSpace(strings.ToLower(query))
	rawTokens := strings.Fields(query)

	// Filter out common english noise stop-words
	stopWords := map[string]bool{"a": true, "an": true, "the": true, "and": true, "or": true, "for": true, "to": true, "in": true, "of": true, "with": true, "on": true, "at": true}
	var tokens []string
	for _, t := range rawTokens {
		if !stopWords[t] || len(rawTokens) == 1 {
			tokens = append(tokens, t)
		}
	}

	type matchItem struct {
		score int
		reg   *RegisteredTool
	}

	var matches []matchItem
	seen := make(map[string]bool)

	for key, reg := range p.tools {
		// Avoid duplicate scoring of namespaced aliases
		if strings.Contains(key, ":") {
			continue
		}

		score := 0
		if query == "" || query == "*" {
			score = 1
		} else {
			nameLower := strings.ToLower(reg.Tool.Name)
			descLower := strings.ToLower(reg.Tool.Description)
			serverLower := strings.ToLower(reg.ServerName)
			serverDesc := strings.ToLower(p.serverDescs[reg.ServerName])

			for _, t := range tokens {
				// 1. Exact match in tool name (Highest confidence)
				if nameLower == t {
					score += 15
				} else if strings.Contains(nameLower, t) {
					score += 8
				}

				// 2. Server name match
				if strings.Contains(serverLower, t) {
					score += 5
				}

				// 3. Server description match
				if strings.Contains(serverDesc, t) {
					score += 4
				}

				// 4. Tool description match
				if strings.Contains(descLower, t) {
					score += 2
				}

				// 5. Parameter name match in schema
				for pName := range reg.Tool.InputSchema.Properties {
					if strings.Contains(strings.ToLower(pName), t) {
						score += 1
						break
					}
				}
			}
		}

		if score > 0 && !seen[reg.Tool.Name] {
			seen[reg.Tool.Name] = true
			matches = append(matches, matchItem{score: score, reg: reg})
		}
	}

	if len(matches) == 0 {
		return fmt.Sprintf("No tools found matching %q. Try broader keywords, list servers via list_servers, or use '*' to list all.", query)
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

	sb.WriteString("To invoke any tool above: call it via `call_tool(tool_name=\"...\")`.")
	return sb.String()
}

func extractParamSignature(schema mcp.ToolInputSchema) string {
	props := schema.Properties
	if len(props) == 0 {
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
		suggestions := p.findSuggestions(toolName)
		if len(suggestions) > 0 {
			return nil, fmt.Errorf("tool %q not found. Did you mean: %s?", toolName, strings.Join(suggestions, ", "))
		}
		return nil, fmt.Errorf("tool %q not found across connected upstream servers", toolName)
	}

	req := mcp.CallToolRequest{}
	// Use the original tool name on the upstream server, not the namespaced alias
	req.Params.Name = reg.Tool.Name
	req.Params.Arguments = args

	p.logger.Info("forwarding call to upstream", "server", reg.ServerName, "tool", reg.Tool.Name)
	return reg.Client.CallTool(ctx, req)
}

func (p *Proxy) findSuggestions(name string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	nameLower := strings.ToLower(name)
	var matches []string
	seen := make(map[string]bool)

	for t, reg := range p.tools {
		if strings.Contains(t, ":") {
			continue
		}
		tLower := strings.ToLower(reg.Tool.Name)
		if (strings.Contains(tLower, nameLower) || strings.Contains(nameLower, tLower)) && !seen[reg.Tool.Name] {
			seen[reg.Tool.Name] = true
			matches = append(matches, reg.Tool.Name)
			if len(matches) >= 3 {
				break
			}
		}
	}
	return matches
}

func (p *Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for name, c := range p.clients {
		p.logger.Info("closing upstream client", "server", name)
		_ = c.Close()
	}
}
