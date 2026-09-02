package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedFileTokenStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vault_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vaultPath := filepath.Join(tmpDir, "vault.enc")
	masterKey := "super-secret-master-key-12345"

	store, err := NewEncryptedFileTokenStore(vaultPath, masterKey)
	if err != nil {
		t.Fatalf("failed to initialize vault: %v", err)
	}

	ctx := context.Background()

	// 1. Get non-existent
	_, err = store.Get(ctx, "camilo", "github")
	if err != ErrTokenNotFound {
		t.Fatalf("expected ErrTokenNotFound, got: %v", err)
	}

	// 2. Put token
	expiry := time.Now().Add(1 * time.Hour)
	token := &TokenSet{
		AccessToken:  "gho_test_access_token",
		RefreshToken: "ghr_test_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    expiry,
		Scopes:       []string{"repo", "user"},
	}

	if err := store.Put(ctx, "camilo", "github", token); err != nil {
		t.Fatalf("failed to put token: %v", err)
	}

	// 3. Verify file exists on disk and is not plaintext
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("vault file not found: %v", err)
	}
	if stringContains(string(data), "gho_test_access_token") {
		t.Fatal("security violation: access token was found in plaintext in vault file")
	}

	// 4. Retrieve token
	retrieved, err := store.Get(ctx, "camilo", "github")
	if err != nil {
		t.Fatalf("failed to get token: %v", err)
	}
	if retrieved.AccessToken != "gho_test_access_token" {
		t.Fatalf("expected 'gho_test_access_token', got: %s", retrieved.AccessToken)
	}
	if retrieved.IsExpired(5 * time.Minute) {
		t.Fatal("token should not be expired with 1 hour remaining")
	}

	// 5. Test ListConnections
	connections, err := store.ListConnections(ctx, "camilo")
	if err != nil {
		t.Fatalf("failed to list connections: %v", err)
	}
	if len(connections) != 1 || connections[0].ServerName != "github" || !connections[0].Connected {
		t.Fatalf("unexpected connection list: %+v", connections)
	}

	// 6. Reload from disk with same key
	reloaded, err := NewEncryptedFileTokenStore(vaultPath, masterKey)
	if err != nil {
		t.Fatalf("failed to reload vault: %v", err)
	}
	reloadedToken, err := reloaded.Get(ctx, "camilo", "github")
	if err != nil || reloadedToken.AccessToken != "gho_test_access_token" {
		t.Fatalf("failed to read reloaded token: %v", err)
	}

	// 7. Reload with WRONG key must fail decryption
	_, errWrongKey := NewEncryptedFileTokenStore(vaultPath, "wrong-key")
	if errWrongKey == nil {
		t.Fatal("expected error when loading vault with wrong key, got nil")
	}

	// 8. Delete token
	if err := store.Delete(ctx, "camilo", "github"); err != nil {
		t.Fatalf("failed to delete token: %v", err)
	}
	_, err = store.Get(ctx, "camilo", "github")
	if err != ErrTokenNotFound {
		t.Fatalf("expected ErrTokenNotFound after delete, got: %v", err)
	}
}
