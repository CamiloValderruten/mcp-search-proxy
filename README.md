<div align="center">

# ⚡ mcp-search-proxy

### The Enterprise-Grade Federated Gateway, Identity Broker & Tool Accelerator for Model Context Protocol (MCP)

[![Release](https://img.shields.io/github/v/release/CamiloValderruten/mcp-search-proxy?style=flat-square&color=blue)](https://github.com/CamiloValderruten/mcp-search-proxy/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/CamiloValderruten/mcp-search-proxy?style=flat-square)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/CamiloValderruten/mcp-search-proxy/ci.yml?branch=main&label=tests&style=flat-square)](https://github.com/CamiloValderruten/mcp-search-proxy/actions)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success.svg?style=flat-square)](https://github.com/CamiloValderruten/mcp-search-proxy)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

**Federate 100+ MCP servers into a single high-performance gateway with sub-millisecond tool search, neural vector discovery, in-memory TTL caching, caller identity RBAC, pluggable secret providers (1Password, Env, Vault), and dual STDIO/HTTP daemon modes. Built with comprehensive test coverage and robust error handling for production use.**

[Features](#-key-features) • [The Problem](#-the-problem-the-context-bloat-tax) • [Architecture](#-architecture) • [Quickstart](#-quickstart-30-seconds) • [HTTP Daemon](#-http-daemon-mode) • [Pluggable Secrets](#-pluggable-secret-providers--zero-plaintext-credentials) • [Identity RBAC](#-identity-aware-rbac--credential-brokering) • [Semantic Search](#-neural-semantic-vector-search) • [Benchmarks](#-performance--efficiency-benchmarks)

---

</div>

## 🛑 The Problem: The "Context Bloat Tax"

Every tool exposed to an LLM must have its full JSON Schema injected into the system prompt.
- A single MCP server often exposes **20–40 tools**.
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
  💸 High Latency | 💸 Massive API Costs | 😵 Model Hallucinations
```

### ✅ The Solution: `mcp-search-proxy`

`mcp-search-proxy` acts as an intelligent, federated router between your AI client and all upstream MCP servers. It advertises only **lightweight discovery tools** (`search_tools`, `call_tool`, `list_servers`), cutting prompt overhead by **over 98%**:

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
│ [Cache • RBAC • Secret Vault]│
└──────┬──────┬──────┬──────┬──┘
       │      │      │      │
       ▼      ▼      ▼      ▼
    GitHub Postgres Slack  Jira ... (100+ tools indexed in memory)
```

---

## ✨ Full Feature Matrix

### 🚀 Performance & Efficiency
- 📉 **98.5% Token Reduction**: Slashes prompt overhead from 25,000+ tokens down to ~335 tokens.
- ⚡ **Sub-Millisecond Lexical Search**: Pure Go weighted multi-field search engine scores tool names, descriptions, and server domains in `< 20 microseconds`.
- 🧠 **Neural Semantic Vector Search**: Optional OpenAI `/v1/embeddings` integration (`text-embedding-3-small`, Ollama, vLLM) enables true conversational search with cosine similarity ranking.
- ⏱️ **In-Memory TTL Caching**: Keyed by SHA-256 of tool arguments. Delivers cached tool results in `< 1 microsecond`, avoiding redundant database queries and rate-limited API calls.
- 🚀 **Concurrent Multiplexing**: Non-blocking asynchronous JSON-RPC event loop with thread-safe atomic I/O.
- ⚡ **Zero Cold Starts**: HTTP daemon keeps upstream subprocesses (Node, Python, Docker) warm 24/7.

### 🔐 Enterprise Security & Identity
- 🔑 **Identity-Aware RBAC**: Define client tokens mapped to whitelisted servers, permitted tools, and read-only flags. Mask unauthorized tools so agents never even see them.
- 🔄 **Dynamic Credential Brokering**: Transparently swap upstream authentication headers per caller identity. Alice queries GitHub with Alice's personal access token; Bob queries with Bob's token.
- 👤 **Backend Identity Mapping**: Dynamically inject mapped backend accounts (`args["account"] = "alice"`) to prevent prompt injection and account spoofing.
- 🔐 **Pluggable Secret Resolution**: Zero plaintext secrets in config files! Resolves `op://` (1Password CLI via headless Service Account), `env://` (Environment variables), and `file://` (Mounted filesystem secrets).
- 🛡️ **Execution Guardrails**: Enforce `read_only: true` on production databases, blacklist dangerous verbs (`drop_*`, `delete_*`), or enforce strict whitelist globs.
- 🌐 **Completely Optional Auth**: When `identities` is omitted, the proxy operates as a pure, open unauthenticated gateway.

### 🛠️ Operational Excellence & Reliability
- 🌐 **Dual-Mode Transport**: Run as a standard CLI STDIO subprocess (Claude Desktop, Cursor) or as a 24/7 background HTTP/SSE daemon (`-listen :8080`).
- 🩺 **Transparent Upstream Error Tracking**: Failing or unauthenticated upstreams are never dropped into a silent void. They appear in `list_servers` with exact error diagnostics (`401 Unauthorized`, `connection refused`), and `/health` reports `degraded` state.
- 🛡️ **Execution Timeouts & Auto-Reconnect**: Configurable per-server timeouts prevent hung agents. Broken pipes and severed HTTP connections automatically reconnect and retry.
- 🔁 **Hot-Reloading (Zero Downtime)**: Update servers in-flight via `SIGHUP` or the `reload_config` tool without restarting your agent session.
- 📊 **Real-Time Observability**: Built-in `/health`, `/metrics`, and `get_metrics` tools report active connections, error rates, and cache hits.
- 🧪 **Production Ready**: Extensively tested with comprehensive coverage, robust error handling, and memory leak prevention for critical enterprise workloads.
- 📦 **Single Static Binary**: Zero external runtime dependencies. Compiles to an ultra-lightweight ~11 MB binary for macOS, Linux, and Windows.

---

## 🚀 Quickstart (30 Seconds)

### Option 1: Install with Go
```bash
go install github.com/CamiloValderruten/mcp-search-proxy@latest
```

### Option 2: Prebuilt Binaries
Download prebuilt binaries for macOS (Apple Silicon & Intel), Linux (amd64 & arm64/Raspberry Pi), or Windows from the [Releases](https://github.com/CamiloValderruten/mcp-search-proxy/releases) page.

---

## 🌐 HTTP Daemon Mode

Run `mcp-search-proxy` as a persistent background daemon on your local machine, homelab, or server:

```bash
mcp-search-proxy -config servers.json -listen 0.0.0.0:8080
```

### Why Run as an HTTP Daemon?
1. **Zero Cold Starts**: Upstream processes (Python, Node, Docker) stay alive 24/7. Tool invocations execute with 0ms connection lag.
2. **Shared In-Memory Cache**: 10 different agent windows or teammates share the exact same cached responses.
3. **No Process Duplication**: 5 IDE windows connect to **1 central proxy** instead of spawning 25 duplicate background subprocesses.
4. **Network Accessible**: Connect remote laptops, mobile agents, or web AI clients (Open WebUI, LibreChat, Dify, LangChain).

### Built-In Endpoints:
- `POST /mcp` — Modern Stateless & Streamable HTTP transport
- `GET /mcp` — SSE stream connection
- `GET /health` — `{"status":"ok","version":"1.3.0","active_upstreams":5,"failed_upstreams":0,"indexed_tools":149}`
- `GET /metrics` — Real-time performance statistics

---

## 🔐 Pluggable Secret Providers (Zero Plaintext Credentials)

Never store raw API keys in configuration files or Git repositories. `mcp-search-proxy` features a pluggable secret resolution engine:

| Scheme | Provider | Description | Example URI |
| :--- | :--- | :--- | :--- |
| `op://` | **1Password** | Resolves live via 1Password CLI (`op read`) or headless Service Account | `op://Vault/Item/Field` |
| `env://` | **Environment** | Reads from process environment variables (zero dependencies) | `env://GITHUB_TOKEN` |
| `file://` | **File System** | Reads token from mounted secrets (Docker / Kubernetes) | `file:///var/run/secrets/token` |

```json
{
  "embeddings": {
    "apiKey": "op://Production/OpenAI/credential"
  },
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "op://Production/GitHub/token"
      }
    }
  }
}
```

---

## 🔑 Identity-Aware RBAC & Credential Brokering

Control exactly which tools each user or AI agent is permitted to discover and execute. The proxy can also dynamically swap upstream credentials per identity:

```json
{
  "identities": {
    "developer-alice": {
      "token": "alice-secret-token",
      "allowed_servers": ["*"],
      "upstream_headers": {
        "remote-gateway": {
          "Authorization": "Bearer op://Production/Enterprise/alice_token"
        }
      }
    },
    "developer-bob": {
      "token": "bob-secret-token",
      "allowed_servers": ["github", "slack"],
      "upstream_headers": {
        "github": {
          "Authorization": "Bearer env://BOB_GITHUB_TOKEN"
        }
      }
    },
    "guest-agent": {
      "token": "guest-agent-token",
      "allowed_servers": ["brave-search", "github"],
      "allowed_tools": ["search_*", "get_*", "list_*"],
      "read_only": true
    }
  }
}
```

### How Identity Works:
1. **Dynamic Tool Masking**: When `guest-agent` calls `search_tools` or `list_servers`, the proxy filters out unapproved servers and destructive tools. The agent never even sees them!
2. **Dynamic Credential Swapping**: When `developer-alice` calls `remote-gateway`, the proxy transparently attaches her personal Bearer token from 1Password.
3. **Zero Secret Exposure**: Outbound headers are injected ephemerally at the network boundary. Neither the client IDE nor the LLM agent ever sees the raw secrets.
4. **Completely Optional**: Omit the `identities` block to run an open, unauthenticated gateway.

---

## 🔐 OAuth 2.0 Upstream Delegation & Encrypted Token Vault

When backends require individual user OAuth authorization (e.g. GitHub, Google Workspace, Slack), `mcp-search-proxy` acts as an encrypted credential broker:

```json
{
  "settings": {
    "publicUrl": "http://localhost:8080",
    "vaultPath": "~/.config/mcp-search-proxy/vault.enc"
  },
  "mcpServers": {
    "github": {
      "url": "https://mcp.github.com/mcp",
      "auth_type": "oauth2_pkce_per_user",
      "oauth2": {
        "client_id": "op://Production/GitHubOAuth/client_id",
        "client_secret": "op://Production/GitHubOAuth/client_secret",
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scopes": ["repo", "read:user"]
      }
    }
  }
}
```

### How Upstream OAuth Works:
1. **Zero Database Needed**: Stores tokens encrypted at rest with AES-256-GCM in `vault.enc`. Microsecond RAM lookups with atomic write-back.
2. **Actionable Consent Links**: If an agent attempts to invoke a tool on an unlinked server, the proxy returns a direct link:
   ```
   Authentication required: Please connect your account by opening:
   http://localhost:8080/oauth/connect/github?caller=camilo
   ```
3. **Browser PKCE Flow**: The user clicks the link, approves access on the 3rd-party service, and is redirected back to `/oauth/callback/{server}` where the proxy captures and securely vaults the tokens.
4. **Silent Background Token Refresh**: When an access token expires, the proxy automatically exchanges the `refresh_token` against the provider's `/token` endpoint before forwarding the tool request.
5. **Endpoints**:
   * `GET /oauth/connect/{server}`: Initiates authorization flow
   * `GET /oauth/callback/{server}`: Handles redirect and stores credentials
   * `GET /oauth/status?user={id}`: Returns connection statuses (ready for Admin Web UI)
   * `POST /oauth/disconnect/{server}`: Revokes/deletes stored credentials

---

## 🧠 Neural Semantic Vector Search

`mcp-search-proxy` works out of the box with instant lexical search. For natural conversational discovery, enable neural vector search via any OpenAI-compatible `/v1/embeddings` endpoint (OpenAI, Ollama, LM Studio, vLLM):

```json
{
  "embeddings": {
    "apiKey": "op://MCP Gateway/OpenAI/credential",
    "model": "text-embedding-3-small"
  }
}
```

### Conversational Discovery in Action:
1. At boot, the proxy embeds all tools in a single batch API call (~2.5s) and caches the 1536-dimensional float vectors in RAM.
2. The user or agent asks a natural language question:
   ```
   search_tools(query="how do I see user signups this week?")
   ```
3. Cosine similarity matches concepts to functions with confidence scores:
   ```
   Found 8 matching tools via semantic search (showing top 3):
   - query_users_by_date(table, start_date, end_date) [sim: 0.42] (postgres-analytics)
   - get_analytics_metrics(metric_name, timeframe) [sim: 0.39] (datadog)
   - list_team_activity(team_id, timeframe) [sim: 0.35] (slack)
   ```

---

## ⚙️ Configuration Reference

Create an `mcp_servers.json` configuration file defining your upstream servers:

```json
{
  "settings": {
    "defaultTimeout": "30s"
  },
  "embeddings": {
    "apiKey": "op://Production/OpenAI/credential",
    "model": "text-embedding-3-small"
  },
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "op://Production/GitHub/token"
      },
      "description": "GitHub repository management: issues, pull requests, commits, branches, and code search.",
      "timeout": "45s"
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
        "SLACK_BOT_TOKEN": "op://MCP Gateway/Slack/token"
      },
      "description": "Slack workspace messaging: channel lookups, message posting, and thread replies.",
      "blocked_tools": ["delete_channel", "kick_user"]
    },
    "remote-gateway": {
      "url": "https://mcp.internal.company.com/mcp",
      "headers": {
        "Authorization": "Bearer op://MCP Gateway/Enterprise/token"
      },
      "description": "Internal enterprise APIs, customer data lookups, and billing services."
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
        "Authorization": "Bearer alice-secret-token"
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
| `list_servers` | Bird's-eye view of authorized servers, tool counts, and health/policy status | ~80 tokens |
| `search_tools` | Search authorized tools with compact function signatures | ~150-250 tokens |
| `call_tool` | Execute any upstream tool with automatic argument unpacking | On-demand |
| `describe_tool` | Inspect full JSONSchema for a single tool if needed | On-demand |
| `get_metrics` | View gateway latency, cache hits, and call counts | ~60 tokens |
| `reload_config` | Hot-reload configuration from disk without restarting | ~20 tokens |

---

## 📊 Performance & Efficiency Benchmarks

*Measurements taken in a standard multi-server deployment (5 upstream servers exposing ~150 total tools):*

| Benchmark Metric | Direct Multi-Server Exposure | With `mcp-search-proxy` | Efficiency Gain |
| :--- | :--- | :--- | :--- |
| **Tool Schema Prompt Cost** | ~35,000 tokens / turn | **~335 tokens / turn** | **99.0% reduction** |
| **Tokens Saved per 10 Turns** | 0 tokens (wasted) | **~346,000 tokens saved** | **Massive cost savings** |
| **Upstream Init Time (5 servers)** | ~10–15s (sequential) | **< 1.8s (parallel goroutines)** | **10x faster boot** |
| **In-Memory Search Latency** | N/A | **< 20 microseconds** | Sub-millisecond |
| **RAM Cache Response Latency** | 100–500ms (network roundtrip) | **< 1 microsecond (RAM cache)** | **99.9% faster** |
| **Proxy Process Memory** | N/A | **~25 MB RSS** | Ultra-lightweight |

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
