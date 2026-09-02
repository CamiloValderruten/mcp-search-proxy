package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type oauthState struct {
	State        string
	Caller       string
	Server       string
	CodeVerifier string
	CreatedAt    time.Time
}

type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// OAuthManager manages upstream OAuth2 authentication flows, callbacks, and token refreshes.
type OAuthManager struct {
	store     TokenStore
	secretMgr *SecretManager
	publicURL string
	servers   map[string]ServerConfig
	logger    *slog.Logger
	client    *http.Client

	statesMu sync.Mutex
	states   map[string]oauthState
}

// NewOAuthManager creates a new OAuthManager instance.
func NewOAuthManager(store TokenStore, secretMgr *SecretManager, publicURL string, servers map[string]ServerConfig, logger *slog.Logger) *OAuthManager {
	if publicURL == "" {
		publicURL = "http://localhost:8080"
	}
	publicURL = strings.TrimSuffix(publicURL, "/")

	return &OAuthManager{
		store:     store,
		secretMgr: secretMgr,
		publicURL: publicURL,
		servers:   servers,
		logger:    logger,
		client:    &http.Client{Timeout: 30 * time.Second},
		states:    make(map[string]oauthState),
	}
}

// UpdateServers updates the upstream server configs map on reload.
func (m *OAuthManager) UpdateServers(servers map[string]ServerConfig) {
	m.statesMu.Lock()
	defer m.statesMu.Unlock()
	m.servers = servers
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// GetConnectURL returns the browser authorization URL for a given server and caller.
func (m *OAuthManager) GetConnectURL(serverName, caller string) string {
	return fmt.Sprintf("%s/oauth/connect/%s?caller=%s", m.publicURL, url.PathEscape(serverName), url.QueryEscape(caller))
}

// HandleConnect starts the authorization code flow with PKCE for an upstream server.
func (m *OAuthManager) HandleConnect(w http.ResponseWriter, r *http.Request) {
	serverName := strings.TrimPrefix(r.URL.Path, "/oauth/connect/")
	serverName = strings.Trim(serverName, "/")
	if serverName == "" {
		serverName = r.URL.Query().Get("server")
	}

	caller := r.URL.Query().Get("caller")
	if caller == "" {
		caller = "default"
	}

	m.statesMu.Lock()
	srv, ok := m.servers[serverName]
	m.statesMu.Unlock()

	if !ok || srv.OAuth2 == nil || srv.OAuth2.AuthURL == "" || srv.OAuth2.TokenURL == "" {
		http.Error(w, fmt.Sprintf("Server %q is not configured for OAuth2 delegation", serverName), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	clientID, err := m.secretMgr.ResolveTemplate(ctx, srv.OAuth2.ClientID)
	if err != nil || clientID == "" {
		http.Error(w, fmt.Sprintf("Failed to resolve client_id for server %q: %v", serverName, err), http.StatusInternalServerError)
		return
	}

	stateNonce := generateRandomString(32)
	verifier := generateRandomString(43)
	challenge := pkceChallenge(verifier)

	m.statesMu.Lock()
	// Prune expired states (> 15 minutes)
	cutoff := time.Now().Add(-15 * time.Minute)
	for k, st := range m.states {
		if st.CreatedAt.Before(cutoff) {
			delete(m.states, k)
		}
	}
	m.states[stateNonce] = oauthState{
		State:        stateNonce,
		Caller:       caller,
		Server:       serverName,
		CodeVerifier: verifier,
		CreatedAt:    time.Now(),
	}
	m.statesMu.Unlock()

	callbackURL := fmt.Sprintf("%s/oauth/callback/%s", m.publicURL, url.PathEscape(serverName))

	authURL, err := url.Parse(srv.OAuth2.AuthURL)
	if err != nil {
		http.Error(w, "Invalid auth_url in server config", http.StatusInternalServerError)
		return
	}

	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", callbackURL)
	q.Set("state", stateNonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if len(srv.OAuth2.Scopes) > 0 {
		q.Set("scope", strings.Join(srv.OAuth2.Scopes, " "))
	}
	// For Google OAuth, request refresh token explicitly
	if strings.Contains(srv.OAuth2.AuthURL, "google") {
		q.Set("access_type", "offline")
		q.Set("prompt", "consent")
	}
	authURL.RawQuery = q.Encode()

	m.logger.Info("redirecting user to upstream oauth provider", "server", serverName, "caller", caller, "url", authURL.String())
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// HandleCallback processes the upstream OAuth redirect, exchanges the code, and saves the tokens.
func (m *OAuthManager) HandleCallback(w http.ResponseWriter, r *http.Request) {
	serverName := strings.TrimPrefix(r.URL.Path, "/oauth/callback/")
	serverName = strings.Trim(serverName, "/")
	if serverName == "" {
		serverName = r.URL.Query().Get("server")
	}

	if errStr := r.URL.Query().Get("error"); errStr != "" {
		desc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("OAuth error from provider: %s (%s)", errStr, desc), http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	stateNonce := r.URL.Query().Get("state")
	if code == "" || stateNonce == "" {
		http.Error(w, "Missing 'code' or 'state' parameter in callback", http.StatusBadRequest)
		return
	}

	m.statesMu.Lock()
	st, exists := m.states[stateNonce]
	if exists {
		delete(m.states, stateNonce)
	}
	srv, srvExists := m.servers[serverName]
	m.statesMu.Unlock()

	if !exists || st.Server != serverName {
		http.Error(w, "Invalid or expired OAuth state parameter (CSRF protection)", http.StatusForbidden)
		return
	}
	if !srvExists || srv.OAuth2 == nil {
		http.Error(w, "Server configuration not found", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	clientID, _ := m.secretMgr.ResolveTemplate(ctx, srv.OAuth2.ClientID)
	clientSecret, _ := m.secretMgr.ResolveTemplate(ctx, srv.OAuth2.ClientSecret)

	callbackURL := fmt.Sprintf("%s/oauth/callback/%s", m.publicURL, url.PathEscape(serverName))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", callbackURL)
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	form.Set("code_verifier", st.CodeVerifier)

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.OAuth2.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, fmt.Sprintf("Creating token request failed: %v", err), http.StatusInternalServerError)
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(tokenReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Exchanging code with token endpoint failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Token endpoint returned HTTP %d: %s", resp.StatusCode, string(respBody)), http.StatusBadGateway)
		return
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		// Some older OAuth servers return form-encoded bodies instead of JSON
		if vals, pErr := url.ParseQuery(string(respBody)); pErr == nil && vals.Get("access_token") != "" {
			tokenResp.AccessToken = vals.Get("access_token")
			tokenResp.RefreshToken = vals.Get("refresh_token")
			tokenResp.TokenType = vals.Get("token_type")
		} else {
			http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
			return
		}
	}

	if tokenResp.AccessToken == "" {
		http.Error(w, fmt.Sprintf("Token endpoint did not return an access_token: %s", string(respBody)), http.StatusBadRequest)
		return
	}

	var expiry time.Time
	if tokenResp.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	var scopes []string
	if tokenResp.Scope != "" {
		scopes = strings.Fields(tokenResp.Scope)
	} else {
		scopes = srv.OAuth2.Scopes
	}

	tokenSet := &TokenSet{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    expiry,
		Scopes:       scopes,
		UpdatedAt:    time.Now(),
	}

	if err := m.store.Put(ctx, st.Caller, st.Server, tokenSet); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save tokens into vault: %v", err), http.StatusInternalServerError)
		return
	}

	m.logger.Info("successfully stored oauth tokens for user and server", "user", st.Caller, "server", st.Server)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Connected to %s</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); text-align: center; max-width: 420px; }
    .icon { font-size: 3rem; margin-bottom: 1rem; }
    h1 { margin: 0 0 0.5rem 0; font-size: 1.5rem; color: #38bdf8; }
    p { color: #94a3b8; line-height: 1.5; margin-bottom: 1.5rem; }
    .btn { display: inline-block; background: #2563eb; color: #fff; padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; font-weight: 500; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>Successfully Connected!</h1>
    <p>Your account (<strong>%s</strong>) is now linked to <strong>%s</strong>. You may close this tab and continue in your AI assistant.</p>
  </div>
</body>
</html>`, htmlEscape(serverName), htmlEscape(st.Caller), htmlEscape(serverName))
}

// RefreshToken silently refreshes an expired access token using the stored refresh token.
func (m *OAuthManager) RefreshToken(ctx context.Context, user, serverName string) (*TokenSet, error) {
	current, err := m.store.Get(ctx, user, serverName)
	if err != nil {
		return nil, fmt.Errorf("getting token for refresh: %w", err)
	}

	if current.RefreshToken == "" {
		return nil, fmt.Errorf("server %q for user %q has no refresh_token; user must re-authenticate", serverName, user)
	}

	m.statesMu.Lock()
	srv, ok := m.servers[serverName]
	m.statesMu.Unlock()

	if !ok || srv.OAuth2 == nil || srv.OAuth2.TokenURL == "" {
		return nil, fmt.Errorf("server %q is not configured with an oauth2 token_url", serverName)
	}

	clientID, _ := m.secretMgr.ResolveTemplate(ctx, srv.OAuth2.ClientID)
	clientSecret, _ := m.secretMgr.ResolveTemplate(ctx, srv.OAuth2.ClientSecret)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", current.RefreshToken)
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.OAuth2.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating refresh request: %w", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh endpoint returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing refresh response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("refresh endpoint returned no access_token: %s", string(respBody))
	}

	// Preserve refresh token if provider did not issue a new one
	if tokenResp.RefreshToken != "" {
		current.RefreshToken = tokenResp.RefreshToken
	}
	current.AccessToken = tokenResp.AccessToken
	if tokenResp.TokenType != "" {
		current.TokenType = tokenResp.TokenType
	}
	if tokenResp.ExpiresIn > 0 {
		current.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}
	current.UpdatedAt = time.Now()

	if err := m.store.Put(ctx, user, serverName, current); err != nil {
		return nil, fmt.Errorf("saving refreshed token: %w", err)
	}

	m.logger.Info("silently refreshed oauth token", "user", user, "server", serverName, "expires_at", current.ExpiresAt)
	return current, nil
}

// HandleStatus returns connected integrations for a user.
func (m *OAuthManager) HandleStatus(w http.ResponseWriter, r *http.Request) {
	caller := r.URL.Query().Get("user")
	if caller == "" {
		caller = "default"
	}

	connections, err := m.store.ListConnections(r.Context(), caller)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list connections: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user":        caller,
		"connections": connections,
	})
}

// HandleDisconnect removes stored tokens for a user and server.
func (m *OAuthManager) HandleDisconnect(w http.ResponseWriter, r *http.Request) {
	serverName := strings.TrimPrefix(r.URL.Path, "/oauth/disconnect/")
	serverName = strings.Trim(serverName, "/")
	if serverName == "" {
		serverName = r.URL.Query().Get("server")
	}

	caller := r.URL.Query().Get("user")
	if caller == "" {
		caller = "default"
	}

	if err := m.store.Delete(r.Context(), caller, serverName); err != nil {
		http.Error(w, fmt.Sprintf("Failed to disconnect: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "disconnected",
		"server": serverName,
		"user":   caller,
	})
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
