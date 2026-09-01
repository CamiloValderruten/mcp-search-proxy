package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SecretProvider defines the interface for pluggable secret resolution backends.
type SecretProvider interface {
	Scheme() string
	Resolve(ctx context.Context, ref string) (string, error)
}

// EnvSecretProvider resolves environment variables (e.g. "env://MY_TOKEN" or "env:MY_TOKEN").
type EnvSecretProvider struct{}

func (p *EnvSecretProvider) Scheme() string { return "env" }
func (p *EnvSecretProvider) Resolve(ctx context.Context, ref string) (string, error) {
	varName := strings.TrimPrefix(ref, "env://")
	varName = strings.TrimPrefix(varName, "env:")
	val := os.Getenv(varName)
	if val == "" {
		return "", fmt.Errorf("environment variable %q is not set", varName)
	}
	return val, nil
}

// OnePasswordSecretProvider resolves references using the 1Password CLI (e.g. "op://vault/item/field").
type OnePasswordSecretProvider struct{}

func (p *OnePasswordSecretProvider) Scheme() string { return "op" }
func (p *OnePasswordSecretProvider) Resolve(ctx context.Context, ref string) (string, error) {
	cmd := exec.CommandContext(ctx, "op", "read", ref)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("1password cli (op read) failed for reference %q: %w", ref, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// FileSecretProvider resolves secrets from files on disk (e.g. "file:///var/run/secrets/token").
type FileSecretProvider struct{}

func (p *FileSecretProvider) Scheme() string { return "file" }
func (p *FileSecretProvider) Resolve(ctx context.Context, ref string) (string, error) {
	path := strings.TrimPrefix(ref, "file://")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read secret file %q: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

type cachedSecret struct {
	value     string
	expiresAt time.Time
}

// SecretManager manages pluggable providers and caches resolved secrets in memory.
type SecretManager struct {
	mu        sync.RWMutex
	providers map[string]SecretProvider
	cache     map[string]cachedSecret
	ttl       time.Duration
}

var uriRegex = regexp.MustCompile(`([a-zA-Z0-9_-]+)://[^\s"'<>]+`)

// NewSecretManager creates a SecretManager with default providers (env, op, file).
func NewSecretManager(ttl time.Duration) *SecretManager {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	sm := &SecretManager{
		providers: make(map[string]SecretProvider),
		cache:     make(map[string]cachedSecret),
		ttl:       ttl,
	}

	sm.Register(&EnvSecretProvider{})
	sm.Register(&OnePasswordSecretProvider{})
	sm.Register(&FileSecretProvider{})

	return sm
}

// Register adds or replaces a SecretProvider.
func (sm *SecretManager) Register(p SecretProvider) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.providers[p.Scheme()] = p
}

// Resolve fetches a secret using the appropriate provider based on its URI scheme.
func (sm *SecretManager) Resolve(ctx context.Context, ref string) (string, error) {
	sm.mu.RLock()
	if cached, ok := sm.cache[ref]; ok && time.Now().Before(cached.expiresAt) {
		sm.mu.RUnlock()
		return cached.value, nil
	}
	sm.mu.RUnlock()

	parts := strings.SplitN(ref, "://", 2)
	if len(parts) != 2 {
		return ref, nil // Not a URI scheme, return as-is
	}
	scheme := parts[0]

	sm.mu.RLock()
	provider, exists := sm.providers[scheme]
	sm.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("no secret provider registered for scheme %q (ref: %s)", scheme, ref)
	}

	val, err := provider.Resolve(ctx, ref)
	if err != nil {
		return "", err
	}

	sm.mu.Lock()
	sm.cache[ref] = cachedSecret{
		value:     val,
		expiresAt: time.Now().Add(sm.ttl),
	}
	sm.mu.Unlock()

	return val, nil
}

// ResolveTemplate searches for secret URIs inside a string (e.g. "Bearer op://vault/item/token") and replaces them.
func (sm *SecretManager) ResolveTemplate(ctx context.Context, template string) (string, error) {
	matches := uriRegex.FindAllString(template, -1)
	if len(matches) == 0 {
		return template, nil
	}

	result := template
	for _, match := range matches {
		secretVal, err := sm.Resolve(ctx, match)
		if err != nil {
			return "", err
		}
		result = strings.ReplaceAll(result, match, secretVal)
	}

	return result, nil
}
