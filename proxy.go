package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

type identityContextKey struct{}

// CallerIdentity represents the authenticated client making the request.
type CallerIdentity struct {
	ID     string
	Config IdentityConfig
}

// WithIdentity returns a new context with the caller identity attached.
func WithIdentity(ctx context.Context, id string, cfg IdentityConfig) context.Context {
	return context.WithValue(ctx, identityContextKey{}, &CallerIdentity{
		ID:     id,
		Config: cfg,
	})
}

// GetCallerIdentity extracts the caller identity from the context, if present.
func GetCallerIdentity(ctx context.Context) *CallerIdentity {
	if val, ok := ctx.Value(identityContextKey{}).(*CallerIdentity); ok {
		return val
	}
	return nil
}

// RegisteredTool wraps a tool, its owning server name, configuration, and client.
type RegisteredTool struct {
	ServerName   string
	Tool         mcp.Tool
	Client       *client.Client
	ServerConfig ServerConfig
}

// ServerInfo holds metadata about an upstream server.
type ServerInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ToolCount   int    `json:"tool_count"`
	ReadOnly    bool   `json:"read_only,omitempty"`
}

type cacheEntry struct {
	result    *mcp.CallToolResult
	expiresAt time.Time
}

// Metrics tracks runtime performance and usage statistics.
type Metrics struct {
	TotalCalls      uint64 `json:"total_calls"`
	CacheHits       uint64 `json:"cache_hits"`
	Errors          uint64 `json:"errors"`
	ActiveUpstreams int    `json:"active_upstreams"`
	IndexedTools    int    `json:"indexed_tools"`
}

// Proxy manages upstream MCP clients, caching, identity RBAC, and tool indexing.
type Proxy struct {
	logger         *slog.Logger
	defaultTimeout time.Duration

	mu            sync.RWMutex
	clients       map[string]*client.Client
	tools         map[string]*RegisteredTool
	serverConfigs map[string]ServerConfig
	serverDescs   map[string]string
	identities    map[string]IdentityConfig

	cacheMu sync.RWMutex
	cache   map[string]cacheEntry

	totalCalls atomic.Uint64
	cacheHits  atomic.Uint64
	errors     atomic.Uint64
}

// NewProxy creates a new Proxy instance.
func NewProxy(logger *slog.Logger, defaultTimeout time.Duration) *Proxy {
	if defaultTimeout <= 0 {
		defaultTimeout = 60 * time.Second
	}
	return &Proxy{
		logger:         logger,
		defaultTimeout: defaultTimeout,
		clients:        make(map[string]*client.Client),
		tools:          make(map[string]*RegisteredTool),
		serverConfigs:  make(map[string]ServerConfig),
		serverDescs:    make(map[string]string),
		identities:     make(map[string]IdentityConfig),
		cache:          make(map[string]cacheEntry),
	}
}

// InitUpstreams connects to all configured upstream MCP servers concurrently and indexes their tools.
func (p *Proxy) InitUpstreams(ctx context.Context, cfg *Config) error {
	p.mu.Lock()
	p.identities = cfg.Identities
	p.mu.Unlock()

	var wg sync.WaitGroup

	for name, srv := range cfg.MCPServers {
		p.mu.Lock()
		p.serverConfigs[name] = srv
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

func (p *Proxy) initSingleUpstream(ctx context.Context, name string, srv ServerConfig) (*client.Client, error) {
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
			return nil, err
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
					return nil, err
				}
				sseStartCtx, cancelSSE := context.WithTimeout(ctx, 10*time.Second)
				if err = c.Start(sseStartCtx); err != nil {
					cancelSSE()
					p.logger.Error("failed to start sse transport", "server", name, "err", err)
					_ = c.Close()
					return nil, err
				}
				cancelSSE()
			} else {
				cancelStart()
			}
		}
	} else {
		p.logger.Warn("server has neither command nor url specified", "server", name)
		return nil, fmt.Errorf("server %q has neither command nor url", name)
	}

	initCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "mcp-search-proxy",
		Version: "1.1.0",
	}

	initResult, err := c.Initialize(initCtx, initReq)
	cancel()
	if err != nil {
		p.logger.Error("failed to initialize upstream server", "server", name, "err", err)
		_ = c.Close()
		return nil, err
	}

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
		return nil, err
	}

	p.mu.Lock()
	p.clients[name] = c
	for _, tool := range toolsResult.Tools {
		reg := &RegisteredTool{
			ServerName:   name,
			Tool:         tool,
			Client:       c,
			ServerConfig: srv,
		}
		p.tools[tool.Name] = reg
		p.tools[name+":"+tool.Name] = reg
		p.logger.Debug("indexed tool", "server", name, "tool", tool.Name)
	}
	p.mu.Unlock()

	p.logger.Info("connected and indexed upstream", "server", name, "tool_count", len(toolsResult.Tools))
	return c, nil
}

// ResolveIdentity looks up a configured identity by token, API key, or ID.
func (p *Proxy) ResolveIdentity(tokenOrID string) (string, IdentityConfig, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if tokenOrID == "" {
		return "", IdentityConfig{}, false
	}

	// Match by ID
	if cfg, ok := p.identities[tokenOrID]; ok {
		return tokenOrID, cfg, true
	}

	// Match by Token
	for id, cfg := range p.identities {
		if cfg.Token != "" && cfg.Token == tokenOrID {
			return id, cfg, true
		}
	}

	return "", IdentityConfig{}, false
}

// ReloadConfig dynamically reloads configuration and updates upstream servers in-flight.
func (p *Proxy) ReloadConfig(ctx context.Context, cfg *Config) error {
	p.logger.Info("reloading proxy configuration...")
	return p.InitUpstreams(ctx, cfg)
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

// ListServers returns a clean list of connected servers filtered by caller identity.
func (p *Proxy) ListServers(ctx context.Context) []ServerInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ident := GetCallerIdentity(ctx)

	counts := make(map[string]int)
	for key, reg := range p.tools {
		if !strings.Contains(key, ":") {
			// Check if tool is accessible to identity
			if p.isToolAccessible(ident, reg.ServerName, reg.Tool.Name) {
				counts[reg.ServerName]++
			}
		}
	}

	var servers []ServerInfo
	for name := range p.clients {
		if !p.isServerAccessible(ident, name) {
			continue
		}
		cfg := p.serverConfigs[name]
		ro := cfg.ReadOnly
		if ident != nil && ident.Config.ReadOnly {
			ro = true
		}
		servers = append(servers, ServerInfo{
			Name:        name,
			Description: p.serverDescs[name],
			ToolCount:   counts[name],
			ReadOnly:    ro,
		})
	}

	sort.Slice(servers, func(i, j int) bool {
		return servers[i].Name < servers[j].Name
	})

	return servers
}

// GetMetrics returns real-time usage statistics.
func (p *Proxy) GetMetrics() Metrics {
	p.mu.RLock()
	activeUpstreams := len(p.clients)
	toolCount := 0
	for k := range p.tools {
		if !strings.Contains(k, ":") {
			toolCount++
		}
	}
	p.mu.RUnlock()

	return Metrics{
		TotalCalls:      p.totalCalls.Load(),
		CacheHits:       p.cacheHits.Load(),
		Errors:          p.errors.Load(),
		ActiveUpstreams: activeUpstreams,
		IndexedTools:    toolCount,
	}
}

// SearchToolsFormatConcise formats search results filtered by caller identity.
func (p *Proxy) SearchToolsFormatConcise(ctx context.Context, query string, limit int) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ident := GetCallerIdentity(ctx)

	query = strings.TrimSpace(strings.ToLower(query))
	rawTokens := strings.Fields(query)

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
		if strings.Contains(key, ":") {
			continue
		}

		// Identity-Aware Filtering
		if !p.isToolAccessible(ident, reg.ServerName, reg.Tool.Name) {
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
				if nameLower == t {
					score += 15
				} else if strings.Contains(nameLower, t) {
					score += 8
				}

				if strings.Contains(serverLower, t) {
					score += 5
				}

				if strings.Contains(serverDesc, t) {
					score += 4
				}

				if strings.Contains(descLower, t) {
					score += 2
				}

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
		return fmt.Sprintf("No tools found matching %q. Try broader keywords or run list_servers.", query)
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

// CallTool routes a tool call to the owning upstream client with timeouts, caching, identity RBAC, and backend user mapping.
func (p *Proxy) CallTool(ctx context.Context, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	p.totalCalls.Add(1)

	p.mu.RLock()
	reg, ok := p.tools[toolName]
	p.mu.RUnlock()

	if !ok {
		p.errors.Add(1)
		suggestions := p.findSuggestions(toolName)
		if len(suggestions) > 0 {
			return nil, fmt.Errorf("tool %q not found. Did you mean: %s?", toolName, strings.Join(suggestions, ", "))
		}
		return nil, fmt.Errorf("tool %q not found across connected upstream servers", toolName)
	}

	ident := GetCallerIdentity(ctx)

	// 1. Identity RBAC Enforcement
	if ident != nil {
		if !p.isServerAccessible(ident, reg.ServerName) {
			p.errors.Add(1)
			return nil, fmt.Errorf("access denied: caller %q is not authorized to access server %q", ident.ID, reg.ServerName)
		}
		if !p.isToolAccessible(ident, reg.ServerName, reg.Tool.Name) {
			p.errors.Add(1)
			return nil, fmt.Errorf("access denied: caller %q is not authorized to execute tool %q", ident.ID, reg.Tool.Name)
		}
		if ident.Config.ReadOnly {
			if p.isDestructiveTool(reg.Tool.Name) {
				p.errors.Add(1)
				return nil, fmt.Errorf("access denied: caller %q is in read_only mode; mutating tool %q blocked", ident.ID, reg.Tool.Name)
			}
		}

		// 2. Dynamic Backend Identity Mapping (Caller Identity -> Backend User/Account)
		if ident.Config.UpstreamUserMap != nil {
			if backendUser, mapped := ident.Config.UpstreamUserMap[reg.ServerName]; mapped && backendUser != "" {
				if args == nil {
					args = make(map[string]any)
				}
				// Automatically bind backend identity to common account/user fields if not overridden
				if _, hasAccount := args["account"]; !hasAccount {
					args["account"] = backendUser
				}
				if _, hasUser := args["user"]; !hasUser {
					args["user"] = backendUser
				}
				p.logger.Debug("mapped caller identity to upstream user", "caller", ident.ID, "server", reg.ServerName, "backend_user", backendUser)
			}
		}
	}

	// 3. Server-Level Policy Enforcement & Guardrails
	if err := p.enforcePolicy(reg, args); err != nil {
		p.errors.Add(1)
		p.logger.Warn("tool call blocked by policy", "tool", toolName, "server", reg.ServerName, "err", err)
		return nil, err
	}

	// 4. Cache Lookup
	cacheKey := ""
	cacheTTL := reg.ServerConfig.GetCacheTTL()
	if cacheTTL > 0 {
		cacheKey = p.computeCacheKey(reg.ServerName, reg.Tool.Name, args)
		p.cacheMu.RLock()
		entry, found := p.cache[cacheKey]
		p.cacheMu.RUnlock()

		if found && time.Now().Before(entry.expiresAt) {
			p.cacheHits.Add(1)
			p.logger.Debug("cache hit for tool call", "tool", toolName, "server", reg.ServerName)
			return entry.result, nil
		}
	}

	// 5. Execution with Bounded Timeout
	timeout := reg.ServerConfig.GetTimeout(p.defaultTimeout)
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := mcp.CallToolRequest{}
	req.Params.Name = reg.Tool.Name
	req.Params.Arguments = args

	p.logger.Info("forwarding call to upstream", "server", reg.ServerName, "tool", reg.Tool.Name, "timeout", timeout)
	res, err := reg.Client.CallTool(execCtx, req)

	// 6. Auto-Reconnect Recovery on Broken Pipe
	if err != nil && (strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "transport closed") || strings.Contains(err.Error(), "EOF")) {
		p.logger.Warn("upstream connection severed, attempting automatic reconnection", "server", reg.ServerName)
		newClient, reconnErr := p.initSingleUpstream(ctx, reg.ServerName, reg.ServerConfig)
		if reconnErr == nil {
			p.logger.Info("reconnection successful, retrying tool call", "server", reg.ServerName, "tool", reg.Tool.Name)
			res, err = newClient.CallTool(execCtx, req)
		}
	}

	if err != nil {
		p.errors.Add(1)
		if execCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("tool %q timed out after %s on upstream server %q", reg.Tool.Name, timeout, reg.ServerName)
		}
		return nil, err
	}

	// 7. Store in Cache if configured and successful
	if cacheKey != "" && res != nil && !res.IsError {
		p.cacheMu.Lock()
		p.cache[cacheKey] = cacheEntry{
			result:    res,
			expiresAt: time.Now().Add(cacheTTL),
		}
		p.cacheMu.Unlock()
	}

	return res, nil
}

func (p *Proxy) isServerAccessible(ident *CallerIdentity, serverName string) bool {
	if ident == nil || len(ident.Config.AllowedServers) == 0 {
		return true
	}
	for _, s := range ident.Config.AllowedServers {
		if s == "*" || s == serverName {
			return true
		}
	}
	return false
}

func (p *Proxy) isToolAccessible(ident *CallerIdentity, serverName, toolName string) bool {
	if ident == nil {
		return true
	}
	if !p.isServerAccessible(ident, serverName) {
		return false
	}
	// Blacklist check
	for _, pattern := range ident.Config.BlockedTools {
		matched, _ := filepath.Match(pattern, toolName)
		if matched || pattern == toolName {
			return false
		}
	}
	// Whitelist check
	if len(ident.Config.AllowedTools) > 0 {
		allowed := false
		for _, pattern := range ident.Config.AllowedTools {
			matched, _ := filepath.Match(pattern, toolName)
			if matched || pattern == toolName || pattern == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

func (p *Proxy) isDestructiveTool(toolName string) bool {
	nameLower := strings.ToLower(toolName)
	verbs := []string{"create", "delete", "drop", "update", "write", "set", "remove", "kill", "post", "put", "modify", "clear"}
	for _, verb := range verbs {
		if strings.HasPrefix(nameLower, verb) || strings.Contains(nameLower, "_"+verb) {
			return true
		}
	}
	return false
}

func (p *Proxy) enforcePolicy(reg *RegisteredTool, args map[string]any) error {
	cfg := reg.ServerConfig

	if cfg.ReadOnly && p.isDestructiveTool(reg.Tool.Name) {
		return fmt.Errorf("security policy: server %q is configured in read_only mode; tool %q is blocked", reg.ServerName, reg.Tool.Name)
	}

	for _, pattern := range cfg.BlockedTools {
		matched, _ := filepath.Match(pattern, reg.Tool.Name)
		if matched || pattern == reg.Tool.Name {
			return fmt.Errorf("security policy: tool %q is explicitly blocked on server %q", reg.Tool.Name, reg.ServerName)
		}
	}

	if len(cfg.AllowedTools) > 0 {
		allowed := false
		for _, pattern := range cfg.AllowedTools {
			matched, _ := filepath.Match(pattern, reg.Tool.Name)
			if matched || pattern == reg.Tool.Name || pattern == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("security policy: tool %q is not in the allowed_tools whitelist for server %q", reg.Tool.Name, reg.ServerName)
		}
	}

	return nil
}

func (p *Proxy) computeCacheKey(server, tool string, args map[string]any) string {
	b, _ := json.Marshal(args)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%s:%s:%s", server, tool, hex.EncodeToString(h[:]))
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
