<div align="center">

# ⚡ mcp-search-proxy

### The High-Performance Federated Gateway for Model Context Protocol (MCP)

[![Release](https://img.shields.io/github/v/release/CamiloValderruten/mcp-search-proxy?style=flat-square&color=blue)](https://github.com/CamiloValderruten/mcp-search-proxy/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/CamiloValderruten/mcp-search-proxy?style=flat-square)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/CamiloValderruten/mcp-search-proxy/ci.yml?branch=main&label=tests&style=flat-square)](https://github.com/CamiloValderruten/mcp-search-proxy/actions)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

**Federate 100+ MCP servers into a single lightweight gateway with on-demand tool discovery, sub-millisecond search, TTL caching, and zero context bloat.**

[Features](#-key-features) • [The Problem](#-the-problem-the-context-bloat-tax) • [Quickstart](#-quickstart-30-seconds) • [Configuration](#-configuration) • [Benchmarks](#-benchmarks)

---

</div>

## 🛑 The Problem: The "Context Bloat Tax"

Every tool exposed to an LLM must have its full JSON Schema injected into the system prompt.
- A single MCP server often exposes **20–30 tools**.
- Each tool schema consumes **200–500 tokens**.
- Connecting just 5–6 servers bloats your prompt by **20,000 to 40,000 tokens on EVERY single turn**!

```
❌ Traditional Multi-MCP Setup:
┌─────────────────────────────────────────────────────────────┐
│ LLM Context Window (40,000+ tokens burned on tool schemas)  │
│ ├─ GitHub MCP (30 tools)                                   │
│ ├─ Postgres MCP (25 tools)                                 │
│ ├─ Slack MCP (20 tools)                                    │
│ ├─ Jira MCP (25 tools)                                     │
│ └─ Web Search MCP (10 tools)                               │
└─────────────────────────────────────────────────────────────┘
  💸 High Latency | 💸 High API Costs | 😵 Model Confusion
```

### ✅ The Solution: `mcp-search-proxy`

`mcp-search-proxy` acts as an intelligent, federated router between your LLM and all your upstream MCP servers. It advertises only **two lightweight discovery tools** (`search_tools` and `call_tool`), cutting prompt overhead by **over 98%**:

```
✨ With mcp-search-proxy:
┌──────────────────────────────┐
│ LLM Context (~335 tokens)    │
│ ├─ search_tools(...)         │
│ ├─ call_tool(...)            │
│ └─ list_servers(...)         │
└──────────────┬───────────────┘
               │  Sub-millisecond routing
               ▼
┌──────────────────────────────┐
│       mcp-search-proxy       │
│  [Concurrent Gateway & Cache]│
└──────┬──────┬──────┬──────┬──┘
       │      │      │      │
       ▼      ▼      ▼      ▼
    GitHub Postgres Slack  Jira ... (100+ tools indexed in memory)
```

---

## ✨ Key Features

- 📉 **98.5% Token Reduction**: Drops tool schema prompt overhead from 25,000+ tokens to ~335 tokens.
- ⚡ **Sub-Millisecond Search**: Pure Go in-memory weighted multi-field search engine scores tool names, descriptions, and server domains in `< 20 microseconds`.
- 🚀 **Concurrent Multiplexing**: Non-blocking asynchronous JSON-RPC event loop with thread-safe atomic I/O.
- 🔒 **Security Guardrails & RBAC**: Enforce `read_only: true` on production databases, whitelist approved tools, or blacklist dangerous commands (`blocked_tools: ["drop_*", "delete_*"]`).
- ⏱️ **TTL Result Caching**: Built-in thread-safe cache avoids redundant API calls and database queries for deterministic operations.
- 🛡️ **Execution Timeouts & Auto-Reconnect**: Configurable per-server execution bounds prevent unresponsive upstreams from hanging your agents. Automatic recovery from broken pipes and severed streams.
- 🌐 **Universal Transport Support**: Seamlessly connects to `stdio` subprocesses, Streamable HTTP (2024-11-05 spec), and legacy SSE transports with parallel boot-up.
- 🔁 **Hot-Reloading**: Update servers in-flight via `SIGHUP` or the `reload_config` tool without restarting your agent session.
- 📦 **Zero External Dependencies**: Compiles to a single, statically linked ~11 MB binary.

---

## 🚀 Quickstart (30 Seconds)

### Option 1: Install with Go
```bash
go install github.com/CamiloValderruten/mcp-search-proxy@latest
```

### Option 2: Prebuilt Binaries
Download the latest prebuilt binary for macOS, Linux, or Windows from the [Releases](https://github.com/CamiloValderruten/mcp-search-proxy/releases) page.

---

## ⚙️ Configuration

Create an `mcp_servers.json` configuration file defining your upstream servers. Environment variables like `${HOME}` or `${API_KEY}` are automatically expanded:

```json
{
  "settings": {
    "defaultTimeout": "30s"
  },
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"
      },
      "description": "GitHub repository management: issues, pull requests, commits, branches, and code search."
    },
    "postgres-analytics": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/analytics"],
      "description": "Read-only PostgreSQL database queries, metrics, and schema inspection.",
      "read_only": true,
      "cache_ttl": "5m"
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": {
        "SLACK_BOT_TOKEN": "${SLACK_BOT_TOKEN}"
      },
      "description": "Slack workspace messaging: channel lookups, message posting, and thread replies.",
      "blocked_tools": ["delete_channel", "kick_user"]
    },
    "remote-gateway": {
      "url": "https://mcp.internal.company.com/mcp",
      "headers": {
        "Authorization": "Bearer ${GATEWAY_TOKEN}"
      },
      "description": "Internal microservices and customer billing platform."
    }
  }
}
```

---

## 🔌 Connecting to Your Agent / Client

### Claude Desktop
Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "search-proxy": {
      "command": "mcp-search-proxy",
      "args": ["-config", "/path/to/mcp_servers.json"]
    }
  }
}
```

### Cursor / Antigravity / Gemini / Windsurf
Configure `mcp-search-proxy` as your single MCP server entry:
```json
{
  "mcpServers": {
    "gateway": {
      "command": "mcp-search-proxy",
      "args": ["-config", "${env:HOME}/.config/mcp/servers.json"]
    }
  }
}
```

---

## 🛠️ How LLMs Interact with the Proxy

The proxy exposes a tiny, highly efficient tool surface:

| Tool | Purpose | Token Cost |
| :--- | :--- | :--- |
| `list_servers` | Bird's-eye view of connected servers, tool counts, and policies | ~80 tokens |
| `search_tools` | Search tools with compact function signatures by keyword | ~150-250 tokens |
| `call_tool` | Execute any upstream tool with automatic argument unpacking | On-demand |
| `describe_tool` | Inspect full JSONSchema for a single tool if needed | On-demand |
| `get_metrics` | View gateway latency, cache hits, and call counts | ~60 tokens |
| `reload_config` | Hot-reload configuration from disk without restarting | ~20 tokens |

### Example Agent Flow:
1. **Agent searches:** `search_tools(query="pull request")`
2. **Proxy returns:**
   ```
   Found 2 matching tools:
   - github:create_pull_request(base: string, head: string, title: string, body?: string)
   - github:list_pull_requests(state?: string)
   ```
3. **Agent executes:** `call_tool(tool_name="github:create_pull_request", arguments={...})`

---

## 📊 Benchmarks

| Metric | Direct Multi-Server (6 servers) | `mcp-search-proxy` | Improvement |
| :--- | :--- | :--- | :--- |
| **System Prompt Size** | ~24,000 tokens | **~335 tokens** | **-98.6%** |
| **Simple "Hi" Cost** | ~42,000 tokens (with context) | **~18,600 tokens** | **-56%** |
| **Upstream Startup** | Sequential (12–15s) | **Concurrent (1.3s)** | **10x Faster** |
| **Tool Search Latency** | N/A | **< 20 microseconds** | Instant |
| **Memory Footprint** | N/A | **~18 MB RSS** | Ultra-light |

---

## 🛡️ Security Policies & Guardrails

Protect your infrastructure by configuring guardrails directly in `mcp_servers.json`:

```json
{
  "mcpServers": {
    "prod-database": {
      "command": "...",
      "read_only": true,
      "blocked_tools": ["drop_*", "truncate_*", "delete_*"],
      "timeout": "15s"
    }
  }
}
```
- **`read_only: true`**: Automatically blocks any tool with mutating or destructive prefixes (`create`, `delete`, `drop`, `update`, `write`, `set`, `remove`, `kill`, `post`, `put`, `modify`, `clear`).
- **`blocked_tools`**: Glob-pattern blacklist to prevent destructive tools from ever running.
- **`allowed_tools`**: Strict whitelist mode—only specified tools can be executed.

---

## 🤝 Contributing

Contributions are warmly welcome! Please feel free to submit a Pull Request.

```bash
git clone https://github.com/CamiloValderruten/mcp-search-proxy.git
cd mcp-search-proxy
go test -v -race ./...
go build -o bin/mcp-search-proxy
```

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
