package main

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestEnvSecretProvider(t *testing.T) {
	os.Setenv("TEST_MCP_SECRET", "super-secret-pass")
	defer os.Unsetenv("TEST_MCP_SECRET")

	sm := NewSecretManager(1 * time.Minute)
	ctx := context.Background()

	// Resolve raw ref
	val, err := sm.Resolve(ctx, "env://TEST_MCP_SECRET")
	if err != nil {
		t.Fatalf("failed to resolve env secret: %v", err)
	}
	if val != "super-secret-pass" {
		t.Fatalf("expected 'super-secret-pass', got: %s", val)
	}

	// Resolve template string
	template := "Bearer env://TEST_MCP_SECRET"
	resolved, err := sm.ResolveTemplate(ctx, template)
	if err != nil {
		t.Fatalf("failed to resolve template: %v", err)
	}
	if resolved != "Bearer super-secret-pass" {
		t.Fatalf("expected 'Bearer super-secret-pass', got: %s", resolved)
	}
}

func TestFileSecretProvider(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "secret_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	_ = os.WriteFile(tmpFile.Name(), []byte("file-based-token\n"), 0600)

	sm := NewSecretManager(1 * time.Minute)
	ctx := context.Background()

	val, err := sm.Resolve(ctx, "file://"+tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to resolve file secret: %v", err)
	}
	if val != "file-based-token" {
		t.Fatalf("expected 'file-based-token', got: %s", val)
	}
}

type mockCustomProvider struct{}

func (m *mockCustomProvider) Scheme() string { return "custom" }
func (m *mockCustomProvider) Resolve(ctx context.Context, ref string) (string, error) {
	return "custom-resolved-secret", nil
}

func TestPluggableCustomProvider(t *testing.T) {
	sm := NewSecretManager(1 * time.Minute)
	sm.Register(&mockCustomProvider{})

	ctx := context.Background()
	val, err := sm.Resolve(ctx, "custom://vault/token")
	if err != nil {
		t.Fatalf("failed to resolve custom provider: %v", err)
	}
	if val != "custom-resolved-secret" {
		t.Fatalf("expected 'custom-resolved-secret', got: %s", val)
	}
}
