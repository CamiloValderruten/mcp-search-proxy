package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrTokenNotFound is returned when no token exists for the requested user and server.
var ErrTokenNotFound = errors.New("token not found in vault")

// TokenSet holds OAuth tokens and metadata for a specific user on an upstream server.
type TokenSet struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// IsExpired returns true if the token is expired or will expire within the given margin.
func (t *TokenSet) IsExpired(margin time.Duration) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(margin).After(t.ExpiresAt)
}

// ConnectionStatus provides connection metadata for the Admin UI and status endpoints.
type ConnectionStatus struct {
	ServerName string     `json:"server_name"`
	User       string     `json:"user"`
	Connected  bool       `json:"connected"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Scopes     []string   `json:"scopes,omitempty"`
}

// TokenStore defines the storage interface for OAuth tokens.
type TokenStore interface {
	Get(ctx context.Context, user, server string) (*TokenSet, error)
	Put(ctx context.Context, user, server string, token *TokenSet) error
	Delete(ctx context.Context, user, server string) error
	ListConnections(ctx context.Context, user string) ([]ConnectionStatus, error)
}

// EncryptedFileTokenStore implements TokenStore using an AES-256-GCM encrypted local file.
type EncryptedFileTokenStore struct {
	mu     sync.RWMutex
	path   string
	key    []byte
	tokens map[string]*TokenSet
}

func deriveKey(rawKey string) []byte {
	h := sha256.Sum256([]byte(rawKey))
	return h[:]
}

// NewEncryptedFileTokenStore initializes the token store from path using rawKey.
func NewEncryptedFileTokenStore(path, rawKey string) (*EncryptedFileTokenStore, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		path = filepath.Join(home, ".config", "mcp-search-proxy", "vault.enc")
	}

	if rawKey == "" {
		rawKey = os.Getenv("MCP_VAULT_KEY")
	}

	keyFilePath := path + ".key"
	if rawKey == "" {
		if data, err := os.ReadFile(keyFilePath); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			rawKey = strings.TrimSpace(string(data))
		} else {
			// Auto-generate a secure random 32-byte key
			randomBytes := make([]byte, 32)
			if _, rErr := io.ReadFull(rand.Reader, randomBytes); rErr != nil {
				return nil, fmt.Errorf("generating vault master key: %w", rErr)
			}
			rawKey = fmt.Sprintf("%x", randomBytes)
			_ = os.MkdirAll(filepath.Dir(keyFilePath), 0700)
			_ = os.WriteFile(keyFilePath, []byte(rawKey), 0600)
		}
	}

	key := deriveKey(rawKey)
	store := &EncryptedFileTokenStore{
		path:   path,
		key:    key,
		tokens: make(map[string]*TokenSet),
	}

	if err := store.load(); err != nil {
		return nil, err
	}

	return store, nil
}

func vaultKey(user, server string) string {
	return strings.ToLower(user) + ":" + strings.ToLower(server)
}

func (s *EncryptedFileTokenStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.tokens = make(map[string]*TokenSet)
			return nil
		}
		return fmt.Errorf("reading vault file %q: %w", s.path, err)
	}

	if len(data) == 0 {
		s.tokens = make(map[string]*TokenSet)
		return nil
	}

	decrypted, err := decryptGCM(data, s.key)
	if err != nil {
		return fmt.Errorf("decrypting vault %q: %w", s.path, err)
	}

	var m map[string]*TokenSet
	if err := json.Unmarshal(decrypted, &m); err != nil {
		return fmt.Errorf("unmarshaling vault json: %w", err)
	}

	s.tokens = m
	return nil
}

func (s *EncryptedFileTokenStore) saveLocked() error {
	data, err := json.Marshal(s.tokens)
	if err != nil {
		return fmt.Errorf("marshaling vault tokens: %w", err)
	}

	encrypted, err := encryptGCM(data, s.key)
	if err != nil {
		return fmt.Errorf("encrypting vault: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating vault directory %q: %w", dir, err)
	}

	tmpFile, err := os.CreateTemp(dir, "vault_*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp vault file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if _, err := tmpFile.Write(encrypted); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("writing temp vault file: %w", err)
	}
	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmodding temp vault file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp vault file: %w", err)
	}

	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("renaming temp vault file to %q: %w", s.path, err)
	}

	return nil
}

func (s *EncryptedFileTokenStore) Get(ctx context.Context, user, server string) (*TokenSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k := vaultKey(user, server)
	token, ok := s.tokens[k]
	if !ok {
		return nil, ErrTokenNotFound
	}

	cp := *token
	return &cp, nil
}

func (s *EncryptedFileTokenStore) Put(ctx context.Context, user, server string, token *TokenSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := vaultKey(user, server)
	token.UpdatedAt = time.Now()
	s.tokens[k] = token

	return s.saveLocked()
}

func (s *EncryptedFileTokenStore) Delete(ctx context.Context, user, server string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := vaultKey(user, server)
	if _, ok := s.tokens[k]; !ok {
		return nil
	}

	delete(s.tokens, k)
	return s.saveLocked()
}

func (s *EncryptedFileTokenStore) ListConnections(ctx context.Context, user string) ([]ConnectionStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userPrefix := strings.ToLower(user) + ":"
	var list []ConnectionStatus

	for k, token := range s.tokens {
		if strings.HasPrefix(k, userPrefix) {
			serverName := strings.TrimPrefix(k, userPrefix)
			var exp *time.Time
			if !token.ExpiresAt.IsZero() {
				t := token.ExpiresAt
				exp = &t
			}
			list = append(list, ConnectionStatus{
				ServerName: serverName,
				User:       user,
				Connected:  true,
				ExpiresAt:  exp,
				Scopes:     token.Scopes,
			})
		}
	}

	return list, nil
}

func encryptGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptGCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, encrypted, nil)
}
