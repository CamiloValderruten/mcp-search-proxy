<div align="center">

# ⚡ mcp-search-proxy

### The High-Performance Federated Gateway, Identity Router & Tool Cache for Model Context Protocol (MCP)

[![Release](https://img.shields.io/github/v/release/CamiloValderruten/mcp-search-proxy?style=flat-square&color=blue)](https://github.com/CamiloValderruten/mcp-search-proxy/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/CamiloValderruten/mcp-search-proxy?style=flat-square)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/CamiloValderruten/mcp-search-proxy/ci.yml?branch=main&label=tests&style=flat-square)](https://github.com/CamiloValderruten/mcp-search-proxy/actions)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

**Federate 100+ MCP servers into a single lightweight gateway with on-demand tool discovery, sub-millisecond search, TTL result caching, caller identity RBAC, optional neural vector search, and dual STDIO/HTTP daemon modes.**

[Features](#-key-features) • [The Problem](#-the-problem-the-context-bloat-tax) • [Quickstart](#-quickstart-30-seconds) • [HTTP Daemon Mode](#-http-daemon-mode) • [Identity RBAC](#-identity-aware-tool-routing--rbac) • [Semantic Search](#-semantic-vector-search-optional) • [Benchmarks](#-performance--efficiency-benchmarks)

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

`mcp-search-proxy` acts as an intelligent, federated router between your LLM and all your upstream MCP servers. It advertises only **lightweight discovery tools** (`search_tools`, `call_tool`, `list_servers`), cutting prompt overhead by **over 98%**:

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
- 🧠 **Optional Semantic Vector Search**: Configure an OpenAI API key (`text-embedding-3-small` or Ollama) for neural vector embeddings and cosine similarity matching.
- 🌐 **Dual-Mode (STDIO + HTTP)**: Run as a standard CLI STDIO process or as a persistent 24/7 HTTP/SSE daemon (`-listen :8080`) shared across your network.
- 🔑 **Identity-Aware RBAC & User Mapping**: Expose only authorized tools per client token, enforce read-only policies, and dynamically map caller identities to backend accounts.
- 🚀 **Concurrent Multiplexing**: Non-blocking asynchronous JSON-RPC event loop with thread-safe atomic I/O.
- 🔒 **Security Guardrails**: Enforce `read_only: true` on production databases, whitelist approved tools, or blacklist dangerous commands (`blocked_tools: ["drop_*", "delete_*"]`).
- ⏱️ **TTL Result Caching**: Built-in thread-safe cache avoids redundant API calls and database queries for deterministic operations.
- 🛡️ **Execution Timeouts & Auto-Reconnect**: Configurable per-server execution bounds prevent unresponsive upstreams from hanging your agents. Automatic recovery from broken pipes and severed streams.
- 🔁 **Hot-Reloading**: Update servers in-flight via `SIGHUP` or the `reload_config` tool without restarting your agent session.
- 📦 **Zero External Dependencies**: Compiles to a single, statically linked ~11 MB binary.

---

## 🚀 Quickstart (30 Seconds)

### Option 1: Install with Go
```bash
go install github.com/CamiloValderruten/mcp-search-proxy@latest
```

### Option 2: Prebuilt Binaries
Download the latest prebuilt binary for macOS (Apple Silicon & Intel), Linux (amd64 & arm64), or Windows from the [Releases](https://github.com/CamiloValderruten/mcp-search-proxy/releases) page.

---

## 🌐 HTTP Daemon Mode

Run `mcp-search-proxy` as a persistent background daemon on your machine or server:

```bash
mcp-search-proxy -config servers.json -listen 0.0.0.0:8080
```

### Why HTTP Daemon Mode is a Game-Changer:
1. **Zero Cold Starts**: Subprocesses (Node, Python, Docker) stay warm 24/7. Tool calls execute with 0ms connection lag.
2. **Shared In-Memory Cache**: Multiple chat windows or agents share the same cached results.
3. **No Process Duplication**: 5 IDE windows talk to **1 central proxy** instead of spawning 30 duplicate background processes.
4. **Network Access**: Connect remote laptops, VMs, or web-based AI clients (Open WebUI, LibreChat, Dify, LangChain).

### Built-In Endpoints:
- `POST /mcp` — Modern Streamable HTTP transport
- `GET /mcp` — SSE stream connection
- `GET /health` — `{"status":"ok","version":"1.2.0","active_upstreams":4,"indexed_tools":85}`
- `GET /metrics` — Live Prometheus/JSON performance stats

---

## 🔑 Identity-Aware Tool Routing & RBAC

Control exactly which tools each user or AI agent is permitted to discover and execute. You can also **map the caller's identity to backend credentials** on upstream servers:

```json
{
  "identities": {
    "admin": {
      "token": "admin-secret-token",
      "allowed_servers": ["*"]
    },
    "guest-agent": {
      "token": "guest-agent-token",
      "allowed_servers": ["brave-search", "github"],
      "allowed_tools": ["search_*", "get_*", "list_*"],
      "read_only": true
    },
    "developer-alice": {
      "token": "alice-personal-token",
      "allowed_servers": ["github", "postgres-analytics"],
      "upstream_user_map": {
        "github": "alice_github_user",
        "postgres-analytics": "app_user_alice"
      }
    }
  }
}
```

### How Identity Works:
1. **Dynamic Tool Masking**: When `guest-agent` calls `search_tools` or `list_servers`, the proxy filters out unapproved servers and destructive tools. The agent never even sees them!
2. **Backend Identity Mapping**: When `developer-alice` invokes `postgres-analytics`, the proxy automatically injects her mapped backend username into the execution context.
3. **HTTP Authentication**: Pass your identity token via `Authorization: Bearer <token>`, `X-API-Key: <token>`, or `X-Client-Id: <id>`.
4. **STDIO Authentication**: Pass `-client-id <id>` when launching in STDIO mode.

---

## 🧠 Semantic Vector Search (Optional)

`mcp-search-proxy` works out of the box with zero external dependencies using fast lexical search. If you prefer **neural semantic search**, configure an OpenAI API key or any OpenAI-compatible `/v1/embeddings` endpoint (e.g. Ollama, LM Studio, vLLM):

```json
{
  "embeddings": {
    "apiKey": "${OPENAI_API_KEY}",
    "model": "text-embedding-3-small",
    "url": "https://api.openai.com/v1/embeddings"
  }
}
```
*(Or simply add `"openAIKey": "${OPENAI_API_KEY}"` under `"settings"` or export `OPENAI_API_KEY` in your shell).*

### How Semantic Search Works:
1. At startup, the proxy generates vector embeddings for all unique upstream tools in a single batch call (~100ms, costs ~$0.00005).
2. When `search_tools` is called, it embeds the query and calculates cosine similarity across in-memory vectors.
3. Natural concepts (e.g. `"find pull requests for auth refactor"`, `"query database user billing"`, `"post deployment alert"`) automatically match tools with similarity scores:
   ```
   Found 2 matching tools via semantic search (showing top 2):
   - github:list_pull_requests(state?: string) [sim: 0.88]
   - github:get_pull_request(pull_number: number) [sim: 0.84]
   ```
4. If no API key is provided, the proxy falls back automatically to its instant lexical search!

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

### Claude Desktop (STDIO Mode)
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

### Cursor / Antigravity / Gemini / Windsurf (HTTP Mode)
Connect via HTTP to the running daemon:
```json
{
  "mcpServers": {
    "search-proxy": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer admin-secret-token"
      }
    }
  }
}
```

---

## 🛠️ How LLMs Interact with the Proxy

The proxy exposes a tiny, highly efficient tool surface:

| Tool | Purpose | Token Cost |
| :--- | :--- | :--- |
| `list_servers` | Bird's-eye view of authorized servers, tool counts, and policies | ~80 tokens |
| `search_tools` | Search authorized tools with compact function signatures | ~150-250 tokens |
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

## 📊 Performance & Efficiency Benchmarks

*Measurements taken in a standard multi-server deployment (5 upstream servers exposing ~100 total tools):*

| Benchmark Metric | Direct Multi-Server Exposure | With `mcp-search-proxy` | Efficiency Gain |
| :--- | :--- | :--- | :--- |
| **Tool Schema Prompt Cost** | ~25,000 tokens / turn | **~335 tokens / turn** | **98.6% reduction** |
| **Tokens Saved per 10 Turns** | 0 tokens (wasted) | **~246,000 tokens saved** | **Massive cost savings** |
| **Upstream Init Time (5 servers)** | ~10–15s (sequential) | **< 1.5s (parallel goroutines)** | **10x faster boot** |
| **In-Memory Search Latency** | N/A | **< 20 microseconds** | Sub-millisecond |
| **Proxy Process Memory** | N/A | **~15–20 MB RSS** | Minimal footprint |
| **Cache Response Latency** | 100–500ms (network roundtrip) | **< 1 microsecond (RAM cache)** | **99.9% faster** |

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
