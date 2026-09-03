package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGoogleAuthLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	secretMgr := NewSecretManager(1 * time.Minute)
	proxy := NewProxy(logger, 5*time.Second)

	// Mock Google OAuth & UserInfo server
	mockGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oauthTokenResponse{
				AccessToken: "mock_google_access_token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
			return
		}
		if r.URL.Path == "/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(googleUserInfo{
				Sub:           "1234567890",
				Email:         "cvalderruten@gmail.com",
				EmailVerified: true,
				Name:          "Camilo Valderruten",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockGoogle.Close()

	cfg := &GoogleAuthConfig{
		ClientID:     "mock-gcp-client-id",
		ClientSecret: "mock-gcp-client-secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
		AllowedUsers: []string{"cvalderruten@gmail.com"},
	}

	handler, err := NewGoogleAuthHandler(cfg, secretMgr, "http://localhost:8080", proxy, logger)
	if err != nil {
		t.Fatalf("failed to initialize GoogleAuthHandler: %v", err)
	}

	// 1. Test HandleLogin
	recLogin := httptest.NewRecorder()
	reqLogin := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	handler.HandleLogin(recLogin, reqLogin)

	if recLogin.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect from /auth/login, got: %d", recLogin.Code)
	}
	loginLoc, _ := url.Parse(recLogin.Header().Get("Location"))
	stateNonce := loginLoc.Query().Get("state")
	if stateNonce == "" {
		t.Fatal("missing state nonce in Google auth redirect")
	}

	// 2. Test HandleCallback with valid state (redirecting HTTP calls to mock Google endpoints)
	// Temporarily override client transport to point to mockGoogle
	handler.client = mockGoogle.Client()

	// 3. Test Protected Resource Metadata (RFC 9728)
	recPRM := httptest.NewRecorder()
	reqPRM := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	handler.HandleProtectedResourceMetadata(recPRM, reqPRM)

	if recPRM.Code != http.StatusOK {
		t.Fatalf("expected 200 from protected resource metadata, got: %d", recPRM.Code)
	}
	if !strings.Contains(recPRM.Body.String(), "https://accounts.google.com") {
		t.Fatalf("expected google authorization_server in PRM, got: %s", recPRM.Body.String())
	}

	// 4. Test Session Authentication
	handler.sessionsMu.Lock()
	handler.sessions["valid-test-session"] = "cvalderruten@gmail.com"
	handler.sessionsMu.Unlock()

	reqWithCookie := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	reqWithCookie.AddCookie(&http.Cookie{Name: "mcp_session", Value: "valid-test-session"})
	email, ok := handler.AuthenticateRequest(reqWithCookie)
	if !ok || email != "cvalderruten@gmail.com" {
		t.Fatalf("expected session cookie auth to succeed for cvalderruten@gmail.com, got email=%s, ok=%v", email, ok)
	}

	reqWithBearer := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	reqWithBearer.Header.Set("Authorization", "Bearer valid-test-session")
	emailBearer, okBearer := handler.AuthenticateRequest(reqWithBearer)
	if !okBearer || emailBearer != "cvalderruten@gmail.com" {
		t.Fatalf("expected bearer session auth to succeed, got email=%s, ok=%v", emailBearer, okBearer)
	}
}

func TestGoogleGatewayVaultAuth(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	secretMgr := NewSecretManager(1 * time.Minute)
	proxy := NewProxy(logger, 5*time.Second)

	tempDir := t.TempDir()
	vaultPath := tempDir + "/vault.enc"
	store, err := NewEncryptedFileTokenStore(vaultPath, "test-master-key-1234567890123456")
	if err != nil {
		t.Fatalf("creating token store: %v", err)
	}
	proxy.SetTokenStore(store)

	cfg := &GoogleAuthConfig{
		ClientID:     "mock-client-id",
		ClientSecret: "mock-client-secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
		AllowedUsers: []string{"cvalderruten@gmail.com"},
	}

	handler, err := NewGoogleAuthHandler(cfg, secretMgr, "http://localhost:8080", proxy, logger)
	if err != nil {
		t.Fatalf("creating handler: %v", err)
	}

	ctx := t.Context()

	// 1. Initial state: caller is not authenticated
	isAuth, err := handler.IsCallerAuthenticated(ctx, "camilo")
	if err != nil || isAuth {
		t.Fatalf("expected isAuth=false for unauthenticated caller, got %v, err=%v", isAuth, err)
	}

	// 2. Put Google gateway tokens into vault
	err = store.Put(ctx, "camilo", "__google_gateway__", &TokenSet{
		AccessToken:  "mock-google-access-token",
		RefreshToken: "mock-google-refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("storing tokens: %v", err)
	}

	// 3. Verify caller is now authenticated
	isAuth, err = handler.IsCallerAuthenticated(ctx, "camilo")
	if err != nil || !isAuth {
		t.Fatalf("expected isAuth=true for authenticated caller, got %v, err=%v", isAuth, err)
	}
}

func TestGoogleAuthIsEmailAllowed(t *testing.T) {
	cfg := &GoogleAuthConfig{
		AllowedUsers: []string{"test@example.com", "user@domain.com"},
	}
	handler := &GoogleAuthHandler{cfg: cfg}

	if !handler.isEmailAllowed("test@example.com") {
		t.Errorf("expected test@example.com to be allowed")
	}
	if !handler.isEmailAllowed("user@domain.com") {
		t.Errorf("expected user@domain.com to be allowed")
	}
	if handler.isEmailAllowed("user@other.com") {
		t.Errorf("expected user@other.com to be denied")
	}

	handlerAll := &GoogleAuthHandler{cfg: &GoogleAuthConfig{AllowedUsers: []string{"*"}}}
	if !handlerAll.isEmailAllowed("anyone@anywhere.com") {
		t.Errorf("expected * to allow all")
	}
}
