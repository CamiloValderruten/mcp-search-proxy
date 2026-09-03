package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOAuthLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir, err := os.MkdirTemp("", "oauth_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vaultStore, err := NewEncryptedFileTokenStore(filepath.Join(tmpDir, "vault.enc"), "test-key-1234")
	if err != nil {
		t.Fatal(err)
	}

	secretMgr := NewSecretManager(1 * time.Minute)

	// Mock Upstream OAuth Server (e.g. mock GitHub / Google)
	var mockTokenReqs []string
	mockOAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mockTokenReqs = append(mockTokenReqs, string(body))

		vals, _ := url.ParseQuery(string(body))
		grantType := vals.Get("grant_type")

		w.Header().Set("Content-Type", "application/json")
		if grantType == "authorization_code" {
			_ = json.NewEncoder(w).Encode(oauthTokenResponse{
				AccessToken:  "mock_access_token_abc",
				RefreshToken: "mock_refresh_token_xyz",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			})
		} else if grantType == "refresh_token" {
			_ = json.NewEncoder(w).Encode(oauthTokenResponse{
				AccessToken:  "mock_refreshed_access_token_def",
				RefreshToken: "mock_refresh_token_xyz",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			})
		} else {
			http.Error(w, "unsupported grant", http.StatusBadRequest)
		}
	}))
	defer mockOAuthServer.Close()

	servers := map[string]ServerConfig{
		"mock-service": {
			AuthType: "oauth2_pkce_per_user",
			OAuth2: &OAuthServerConfig{
				ClientID:     "client_id_123",
				ClientSecret: "client_secret_456",
				AuthURL:      mockOAuthServer.URL + "/auth",
				TokenURL:     mockOAuthServer.URL + "/token",
				Scopes:       []string{"read", "write"},
			},
		},
	}

	oauthMgr := NewOAuthManager(vaultStore, secretMgr, "http://localhost:8080", servers, logger)

	// 1. Test HandleConnect redirects to mock AuthURL with PKCE challenge & state
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/connect/mock-service?caller=camilo", nil)
	oauthMgr.HandleConnect(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d: %s", rec.Code, rec.Body.String())
	}

	loc := rec.Header().Get("Location")
	parsedLoc, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect location: %v", err)
	}

	stateNonce := parsedLoc.Query().Get("state")
	if stateNonce == "" {
		t.Fatal("missing state parameter in redirect")
	}
	if parsedLoc.Query().Get("code_challenge") == "" {
		t.Fatal("missing code_challenge in redirect")
	}

	// 2. Test HandleCallback exchanges code and stores tokens
	recCb := httptest.NewRecorder()
	reqCb := httptest.NewRequest(http.MethodGet, "/oauth/callback/mock-service?code=test_code_123&state="+stateNonce, nil)
	oauthMgr.HandleCallback(recCb, reqCb)

	if recCb.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from callback, got %d: %s", recCb.Code, recCb.Body.String())
	}
	if !strings.Contains(recCb.Body.String(), "Successfully Connected!") {
		t.Fatalf("expected success HTML, got: %s", recCb.Body.String())
	}

	// Verify token in store
	token, err := vaultStore.Get(context.Background(), "camilo", "mock-service")
	if err != nil {
		t.Fatalf("token not found in store: %v", err)
	}
	if token.AccessToken != "mock_access_token_abc" {
		t.Fatalf("expected 'mock_access_token_abc', got: %s", token.AccessToken)
	}

	// 3. Test RefreshToken silently refreshes the token
	refreshed, err := oauthMgr.RefreshToken(context.Background(), "camilo", "mock-service")
	if err != nil {
		t.Fatalf("failed to refresh token: %v", err)
	}
	if refreshed.AccessToken != "mock_refreshed_access_token_def" {
		t.Fatalf("expected 'mock_refreshed_access_token_def', got: %s", refreshed.AccessToken)
	}

	// Verify updated in store
	tokenAfterRefresh, _ := vaultStore.Get(context.Background(), "camilo", "mock-service")
	if tokenAfterRefresh.AccessToken != "mock_refreshed_access_token_def" {
		t.Fatalf("expected store to contain refreshed token, got: %s", tokenAfterRefresh.AccessToken)
	}
}

func TestDynamicUpstreamDiscovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir, err := os.MkdirTemp("", "oauth_disc_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vaultStore, _ := NewEncryptedFileTokenStore(filepath.Join(tmpDir, "vault.enc"), "key-1234")
	secretMgr := NewSecretManager(1 * time.Minute)

	// Mock Upstream Authorization Server (e.g. Okta / Keycloak)
	var mockAS *httptest.Server
	mockAS = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			_ = json.NewEncoder(w).Encode(authServerMetadata{
				Issuer:                mockAS.URL,
				AuthorizationEndpoint: mockAS.URL + "/oauth2/authorize",
				TokenEndpoint:         mockAS.URL + "/oauth2/token",
				RegistrationEndpoint:  mockAS.URL + "/oauth2/register",
				ScopesSupported:       []string{"read", "write"},
			})
			return
		}
		if r.URL.Path == "/oauth2/register" {
			_ = json.NewEncoder(w).Encode(dynamicClientRegistrationResponse{
				ClientID:     "dyn_client_id_okta_999",
				ClientSecret: "dyn_client_secret_xyz",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockAS.Close()

	// Mock Remote Upstream MCP Server (e.g. NerdOracle / Atlassian)
	mockMCPServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			_ = json.NewEncoder(w).Encode(protectedResourceMetadata{
				Resource:             "http://nerdoracle.internal/mcp",
				AuthorizationServers: []string{mockAS.URL},
				ScopesSupported:      []string{"openid", "profile", "nerdoracle:read"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockMCPServer.Close()

	oauthMgr := NewOAuthManager(vaultStore, secretMgr, "http://localhost:8080", nil, logger)

	// Proactively discover OAuth without ANY manual config!
	disc, err := oauthMgr.DiscoverUpstreamOAuth(context.Background(), "nerdoracle", mockMCPServer.URL+"/mcp", "")
	if err != nil {
		t.Fatalf("dynamic discovery failed: %v", err)
	}

	if disc.AuthURL != mockAS.URL+"/oauth2/authorize" {
		t.Fatalf("unexpected AuthURL: %s", disc.AuthURL)
	}
	if disc.TokenURL != mockAS.URL+"/oauth2/token" {
		t.Fatalf("unexpected TokenURL: %s", disc.TokenURL)
	}
	if disc.ClientID != "dyn_client_id_okta_999" {
		t.Fatalf("expected dynamic registration client ID, got: %s", disc.ClientID)
	}
	if !oauthMgr.IsOAuthRequired("nerdoracle") {
		t.Fatal("expected IsOAuthRequired to return true for discovered server")
	}

	// Verify getEffectiveOAuthConfig uses the discovered config
	eff, err := oauthMgr.getEffectiveOAuthConfig(context.Background(), "nerdoracle")
	if err != nil || eff.AuthURL != mockAS.URL+"/oauth2/authorize" {
		t.Fatalf("effective oauth config resolution failed: %v", err)
	}
}

func TestOAuthUpdateServers(t *testing.T) {
	mgr := NewOAuthManager(nil, nil, "http://localhost", nil, slog.Default())
	servers := map[string]ServerConfig{"test-server": {AuthType: "oauth2_pkce_per_user"}}
	mgr.UpdateServers(servers)
	
	if len(mgr.servers) != 1 {
		t.Errorf("Expected 1 server, got %d", len(mgr.servers))
	}
	if mgr.servers["test-server"].AuthType != "oauth2_pkce_per_user" {
		t.Errorf("Expected oauth2_pkce_per_user")
	}
}

func TestOAuthHandleStatus(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "oauth_status_test_*")
	defer os.RemoveAll(tmpDir)
	store, _ := NewEncryptedFileTokenStore(filepath.Join(tmpDir, "vault.enc"), "key-1234")
	_ = store.Put(context.Background(), "user1", "test-server", &TokenSet{AccessToken: "token"})

	servers := map[string]ServerConfig{"test-server": {AuthType: "oauth2_pkce_per_user"}}
	mgr := NewOAuthManager(store, nil, "http://localhost", servers, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "/oauth/status?user=user1", nil)
	rec := httptest.NewRecorder()
	mgr.HandleStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", rec.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	conns, ok := resp["connections"].([]any)
	if !ok || len(conns) == 0 {
		t.Errorf("Expected connections array, got %v", resp)
	}
}

func TestOAuthHandleDisconnect(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "oauth_disc_test_*")
	defer os.RemoveAll(tmpDir)
	store, _ := NewEncryptedFileTokenStore(filepath.Join(tmpDir, "vault.enc"), "key-1234")
	_ = store.Put(context.Background(), "user1", "test-server", &TokenSet{AccessToken: "token"})

	mgr := NewOAuthManager(store, nil, "http://localhost", nil, slog.Default())

	req := httptest.NewRequest(http.MethodPost, "/oauth/disconnect/test-server?user=user1", nil)
	rec := httptest.NewRecorder()
	mgr.HandleDisconnect(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", rec.Code)
	}

	_, err := store.Get(context.Background(), "user1", "test-server")
	if err == nil {
		t.Errorf("Expected error after deletion")
	}
}
