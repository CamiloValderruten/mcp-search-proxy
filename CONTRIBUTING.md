# Contributing to mcp-search-proxy

Thank you for your interest in contributing to `mcp-search-proxy`! We welcome bug reports, feature requests, documentation improvements, and pull requests.

## Development Setup

### Prerequisites
- [Go](https://go.dev/) 1.22 or higher
- Git

### Building Locally
```bash
git clone https://github.com/CamiloValderruten/mcp-search-proxy.git
cd mcp-search-proxy
go test -v -race ./...
go build -o bin/mcp-search-proxy
```

## Pull Request Guidelines

1. Fork the repository and create your branch from `main`.
2. Ensure all tests pass with the race detector:
   ```bash
   go test -v -race ./...
   ```
3. Format your code with `gofmt` or `goimports`:
   ```bash
   gofmt -s -w .
   ```
4. Follow conventional commit messages (e.g., `feat: ...`, `fix: ...`, `docs: ...`).
5. Submit your pull request with a clear description of the problem and your solution.

## Reporting Issues

When reporting an issue, please include:
- Operating system and architecture (`uname -a`)
- Go version (`go version`)
- Steps to reproduce
- Relevant sanitized configuration and error logs
