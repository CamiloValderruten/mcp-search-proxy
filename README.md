# mcp-search-proxy 🔍⚡

A fast, lightweight Model Context Protocol (MCP) search & execution proxy written in Go.

It eliminates **LLM context bloat** by federating any number of upstream MCP servers behind only **two dynamic tools**:
- `search_tools(query)`: Finds relevant tools by keyword or capability.
- `call_tool(tool_name, arguments)`: Executes the discovered tool on the appropriate upstream server.

Instead of burning **20,000+ tokens** of static JSON schemas on every conversation turn, your LLM only sees **~300 tokens** of tool definitions while retaining access to your entire tool library.

---

## Why Go?

- **Zero dependencies**: Single static binary (~11 MB). No `node_modules`, no python virtualenvs.
- **Lightning fast**: Boots in `< 5ms` with `~10 MB` RAM footprint.
- **Resilient concurrency**: Goroutines manage upstream stdio child processes and remote SSE/HTTP connections reliably.
- Built on [`mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go).

---

## How It Works

```
AI Agent (Antigravity / Cursor / Claude Desktop)
                   │
                   ▼  (Only 2 tools exposed: ~300 tokens!)
┌────────────────────────────────────────────────────────┐
│                   mcp-search-proxy                     │
│  • search_tools(query: string)                         │
│  • call_tool(tool_name: string, args: object)          │
└──────────────────────────┬─────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       ▼                   ▼                   ▼
 [Home Assistant]       [Gmail]           [Orders MCP]
  (Remote HTTP)      (Local stdio)       (Local stdio)
```

1. You define all your upstream MCP servers in a standard `mcp_servers.json` file.
2. At startup, `mcp-search-proxy` connects to each server, retrieves its tool catalog, and indexes them in memory.
3. The LLM calls `search_tools` when it needs to accomplish a task, finds the exact tool schema, and invokes `call_tool`.

---

## Installation

### Via Go
```bash
go install github.com/CamiloValderruten/mcp-search-proxy@latest
```

### From Source
```bash
git clone https://github.com/CamiloValderruten/mcp-search-proxy.git
cd mcp-search-proxy
go build -o bin/mcp-search-proxy
```

---

## Configuration

Create an `mcp_servers.json` file listing the upstream MCP servers you want to federate:

```json
{
  "mcpServers": {
    "gmail": {
      "command": "npx",
      "args": ["-y", "@artymclabin/gmail-mcp"]
    },
    "orders": {
      "command": "node",
      "args": ["/path/to/orders-mcp/src/stdio.js"]
    },
    "home-assistant": {
      "url": "http://192.168.1.199:8086/mcp"
    },
    "hindsight": {
      "url": "http://192.168.1.199:9000/mcp/",
      "headers": {
        "Authorization": "Bearer YOUR_SECRET_TOKEN"
      }
    }
  }
}
```

Both local `stdio` (`command`, `args`, `env`) and remote `HTTP/SSE` (`url`, `serverUrl`, `headers`) are supported.

---

## Client Setup Examples

### Claude Desktop / Cursor / Antigravity

Replace your long list of servers in your client's `mcp.json` with a single entry:

```json
{
  "mcpServers": {
    "mcp-search-proxy": {
      "command": "mcp-search-proxy",
      "args": [
        "-config", "/path/to/mcp_servers.json"
      ]
    }
  }
}
```

Or set the environment variable:

```json
{
  "mcpServers": {
    "mcp-search-proxy": {
      "command": "mcp-search-proxy",
      "env": {
        "MCP_CONFIG_PATH": "/path/to/mcp_servers.json"
      }
    }
  }
}
```

---

## License

MIT © 2026 Camilo Valderruten
