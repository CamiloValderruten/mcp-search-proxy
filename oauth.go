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

	discoveredMu sync.RWMutex
	discovered   map[string]*DiscoveredOAuth
}

// DiscoveredOAuth holds dynamically discovered OAuth2 endpoints from an upstream MCP server.
type DiscoveredOAuth struct {
	ServerName          string   `json:"server_name"`
	ResourceMetadataURL string   `json:"resource_metadata_url,omitempty"`
	AuthServerURL       string   `json:"auth_server_url,omitempty"`
	AuthURL             string   `json:"auth_url"`
	TokenURL            string   `json:"token_url"`
	RegistrationURL     string   `json:"registration_url,omitempty"`
	ClientID            string   `json:"client_id,omitempty"`
	ClientSecret        string   `json:"client_secret,omitempty"`
	Scopes              []string `json:"scopes,omitempty"`
}

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

type authServerMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

type dynamicClientRegistrationResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// NewOAuthManager creates a new OAuthManager instance.
func NewOAuthManager(store TokenStore, secretMgr *SecretManager, publicURL string, servers map[string]ServerConfig, logger *slog.Logger) *OAuthManager {
	if publicURL == "" {
		publicURL = "http://localhost:8080"
	}
	publicURL = strings.TrimSuffix(publicURL, "/")

	return &OAuthManager{
		store:      store,
		secretMgr:  secretMgr,
		publicURL:  publicURL,
		servers:    servers,
		logger:     logger,
		client:     &http.Client{Timeout: 30 * time.Second},
		states:     make(map[string]oauthState),
		discovered: make(map[string]*DiscoveredOAuth),
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

// DiscoverUpstreamOAuth probes an upstream MCP server for RFC 9728 and RFC 8414 metadata.
func (m *OAuthManager) DiscoverUpstreamOAuth(ctx context.Context, serverName, serverURL, wwwAuthHeader string) (*DiscoveredOAuth, error) {
	m.discoveredMu.RLock()
	if existing, found := m.discovered[serverName]; found && existing != nil {
		m.discoveredMu.RUnlock()
		return existing, nil
	}
	m.discoveredMu.RUnlock()

	// 1. Determine PRM URL
	prmURL := ""
	if wwwAuthHeader != "" {
		if idx := strings.Index(wwwAuthHeader, "resource_metadata=\""); idx != -1 {
			sub := wwwAuthHeader[idx+len("resource_metadata=\""):]
			if endIdx := strings.Index(sub, "\""); endIdx != -1 {
				prmURL = sub[:endIdx]
			}
		}
	}

	if prmURL == "" {
		parsed, err := url.Parse(serverURL)
		if err != nil {
			return nil, fmt.Errorf("invalid server URL %q: %w", serverURL, err)
		}
		prmURL = fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", parsed.Scheme, parsed.Host)
	}

	m.logger.Info("probing upstream protected resource metadata", "server", serverName, "url", prmURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, prmURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching protected resource metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("protected resource metadata returned HTTP %d", resp.StatusCode)
	}

	var prm protectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		return nil, fmt.Errorf("decoding protected resource metadata: %w", err)
	}

	if len(prm.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("protected resource metadata listed no authorization servers")
	}

	asURL := prm.AuthorizationServers[0]
	m.logger.Info("discovered authorization server for upstream", "server", serverName, "as_url", asURL)

	// 2. Fetch Authorization Server Metadata (RFC 8414)
	asMetaURL := strings.TrimSuffix(asURL, "/") + "/.well-known/oauth-authorization-server"
	asReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, asMetaURL, nil)
	asReq.Header.Set("Accept", "application/json")

	asResp, asErr := m.client.Do(asReq)
	var asMeta authServerMetadata
	if asErr == nil && asResp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(asResp.Body).Decode(&asMeta)
		asResp.Body.Close()
	} else {
		if asResp != nil {
			asResp.Body.Close()
		}
		// Fallback to OpenID configuration
		oidcMetaURL := strings.TrimSuffix(asURL, "/") + "/.well-known/openid-configuration"
		oidcReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, oidcMetaURL, nil)
		oidcReq.Header.Set("Accept", "application/json")
		if oidcResp, oidcErr := m.client.Do(oidcReq); oidcErr == nil && oidcResp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(oidcResp.Body).Decode(&asMeta)
			oidcResp.Body.Close()
		}
	}

	if asMeta.AuthorizationEndpoint == "" || asMeta.TokenEndpoint == "" {
		return nil, fmt.Errorf("authorization server %q did not advertise authorization_endpoint or token_endpoint", asURL)
	}

	disc := &DiscoveredOAuth{
		ServerName:          serverName,
		ResourceMetadataURL: prmURL,
		AuthServerURL:       asURL,
		AuthURL:             asMeta.AuthorizationEndpoint,
		TokenURL:            asMeta.TokenEndpoint,
		RegistrationURL:     asMeta.RegistrationEndpoint,
		Scopes:              prm.ScopesSupported,
	}

	// 3. Dynamic Client Registration (RFC 7591) if supported
	if asMeta.RegistrationEndpoint != "" {
		callbackURL := fmt.Sprintf("%s/oauth/callback/%s", m.publicURL, url.PathEscape(serverName))
		dcrPayload := map[string]any{
			"client_name":    "mcp-search-proxy",
			"redirect_uris":  []string{callbackURL},
			"grant_types":    []string{"authorization_code", "refresh_token"},
			"response_types": []string{"code"},
		}
		dcrBody, _ := json.Marshal(dcrPayload)
		dcrReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, asMeta.RegistrationEndpoint, strings.NewReader(string(dcrBody)))
		dcrReq.Header.Set("Content-Type", "application/json")
		dcrReq.Header.Set("Accept", "application/json")

		if dcrResp, dcrErr := m.client.Do(dcrReq); dcrErr == nil && (dcrResp.StatusCode == http.StatusOK || dcrResp.StatusCode == http.StatusCreated) {
			var dcrResult dynamicClientRegistrationResponse
			if err := json.NewDecoder(dcrResp.Body).Decode(&dcrResult); err == nil && dcrResult.ClientID != "" {
				disc.ClientID = dcrResult.ClientID
				disc.ClientSecret = dcrResult.ClientSecret
				m.logger.Info("dynamically registered oauth client with upstream AS", "server", serverName, "client_id", disc.ClientID)
			}
			dcrResp.Body.Close()
		}
	}

	m.discoveredMu.Lock()
	m.discovered[serverName] = disc
	m.discoveredMu.Unlock()

	return disc, nil
}

func (m *OAuthManager) getEffectiveOAuthConfig(ctx context.Context, serverName string) (*OAuthServerConfig, error) {
	m.statesMu.Lock()
	srv, ok := m.servers[serverName]
	m.statesMu.Unlock()

	// If explicit OAuth2 config is present and complete, use it
	if ok && srv.OAuth2 != nil && srv.OAuth2.AuthURL != "" && srv.OAuth2.TokenURL != "" {
		return srv.OAuth2, nil
	}

	// Otherwise check discovered config
	m.discoveredMu.RLock()
	disc, hasDisc := m.discovered[serverName]
	m.discoveredMu.RUnlock()

	if hasDisc && disc != nil && disc.AuthURL != "" && disc.TokenURL != "" {
		return &OAuthServerConfig{
			ClientID:     disc.ClientID,
			ClientSecret: disc.ClientSecret,
			AuthURL:      disc.AuthURL,
			TokenURL:     disc.TokenURL,
			Scopes:       disc.Scopes,
		}, nil
	}

	// If server has a URL, try automatic discovery on the fly!
	if ok && srv.GetURL() != "" {
		disc, err := m.DiscoverUpstreamOAuth(ctx, serverName, srv.GetURL(), "")
		if err == nil && disc != nil {
			return &OAuthServerConfig{
				ClientID:     disc.ClientID,
				ClientSecret: disc.ClientSecret,
				AuthURL:      disc.AuthURL,
				TokenURL:     disc.TokenURL,
				Scopes:       disc.Scopes,
			}, nil
		}
	}

	return nil, fmt.Errorf("server %q has no oauth configuration and discovery failed", serverName)
}

// IsOAuthRequired returns true if the server is configured with or discovered to require OAuth.
func (m *OAuthManager) IsOAuthRequired(serverName string) bool {
	m.statesMu.Lock()
	srv, ok := m.servers[serverName]
	m.statesMu.Unlock()

	if ok && (srv.AuthType == "oauth2_pkce_per_user" || (srv.OAuth2 != nil && srv.OAuth2.AuthURL != "")) {
		return true
	}

	m.discoveredMu.RLock()
	defer m.discoveredMu.RUnlock()
	_, found := m.discovered[serverName]
	return found
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

	ctx := r.Context()
	oauthCfg, err := m.getEffectiveOAuthConfig(ctx, serverName)
	if err != nil || oauthCfg.AuthURL == "" {
		http.Error(w, fmt.Sprintf("Server %q OAuth resolution failed: %v", serverName, err), http.StatusBadRequest)
		return
	}

	clientID := oauthCfg.ClientID
	if clientID != "" {
		if resolved, err := m.secretMgr.ResolveTemplate(ctx, clientID); err == nil && resolved != "" {
			clientID = resolved
		}
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

	authURL, err := url.Parse(oauthCfg.AuthURL)
	if err != nil {
		http.Error(w, "Invalid auth_url for server", http.StatusInternalServerError)
		return
	}

	q := authURL.Query()
	q.Set("response_type", "code")
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	q.Set("redirect_uri", callbackURL)
	q.Set("state", stateNonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if len(oauthCfg.Scopes) > 0 {
		q.Set("scope", strings.Join(oauthCfg.Scopes, " "))
	}
	if strings.Contains(oauthCfg.AuthURL, "google") {
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
	m.statesMu.Unlock()

	if !exists || st.Server != serverName {
		http.Error(w, "Invalid or expired OAuth state parameter (CSRF protection)", http.StatusForbidden)
		return
	}

	ctx := r.Context()
	oauthCfg, err := m.getEffectiveOAuthConfig(ctx, serverName)
	if err != nil || oauthCfg.TokenURL == "" {
		http.Error(w, fmt.Sprintf("OAuth configuration for server %q not found: %v", serverName, err), http.StatusInternalServerError)
		return
	}

	clientID := oauthCfg.ClientID
	if clientID != "" {
		if resolved, err := m.secretMgr.ResolveTemplate(ctx, clientID); err == nil && resolved != "" {
			clientID = resolved
		}
	}
	clientSecret := oauthCfg.ClientSecret
	if clientSecret != "" {
		if resolved, err := m.secretMgr.ResolveTemplate(ctx, clientSecret); err == nil && resolved != "" {
			clientSecret = resolved
		}
	}

	callbackURL := fmt.Sprintf("%s/oauth/callback/%s", m.publicURL, url.PathEscape(serverName))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", callbackURL)
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	form.Set("code_verifier", st.CodeVerifier)

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthCfg.TokenURL, strings.NewReader(form.Encode()))
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
	} else if oauthCfg != nil {
		scopes = oauthCfg.Scopes
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

	oauthCfg, err := m.getEffectiveOAuthConfig(ctx, serverName)
	if err != nil || oauthCfg.TokenURL == "" {
		return nil, fmt.Errorf("server %q is not configured with an oauth2 token_url: %w", serverName, err)
	}

	clientID := oauthCfg.ClientID
	if clientID != "" {
		if resolved, err := m.secretMgr.ResolveTemplate(ctx, clientID); err == nil && resolved != "" {
			clientID = resolved
		}
	}
	clientSecret := oauthCfg.ClientSecret
	if clientSecret != "" {
		if resolved, err := m.secretMgr.ResolveTemplate(ctx, clientSecret); err == nil && resolved != "" {
			clientSecret = resolved
		}
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", current.RefreshToken)
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthCfg.TokenURL, strings.NewReader(form.Encode()))
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
