package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type gcpKeyFile struct {
	Web *struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
	} `json:"web"`
	Installed *struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
	} `json:"installed"`
}

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

type googleAuthState struct {
	CreatedAt time.Time
	Caller    string
}

// GoogleAuthHandler handles Inbound "Sign in with Google" to authenticate AI clients and users to the proxy.
type GoogleAuthHandler struct {
	cfg          *GoogleAuthConfig
	secretMgr    *SecretManager
	publicURL    string
	proxy        *Proxy
	logger       *slog.Logger
	client       *http.Client
	clientID     string
	clientSecret string
	redirectURL  string

	sessionsMu sync.RWMutex
	sessions   map[string]string // sessionToken -> email

	statesMu sync.Mutex
	states   map[string]googleAuthState
}

// NewGoogleAuthHandler creates a new GoogleAuthHandler.
func NewGoogleAuthHandler(cfg *GoogleAuthConfig, secretMgr *SecretManager, publicURL string, proxy *Proxy, logger *slog.Logger) (*GoogleAuthHandler, error) {
	if cfg == nil {
		return nil, nil
	}

	h := &GoogleAuthHandler{
		cfg:       cfg,
		secretMgr: secretMgr,
		publicURL: strings.TrimSuffix(publicURL, "/"),
		proxy:     proxy,
		logger:    logger,
		client:    &http.Client{Timeout: 15 * time.Second},
		sessions:  make(map[string]string),
		states:    make(map[string]googleAuthState),
	}

	// 1. Resolve credentials from KeyFile if specified
	if cfg.KeyFile != "" {
		keyPath := cfg.KeyFile
		if strings.HasPrefix(keyPath, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				keyPath = filepath.Join(home, keyPath[2:])
			}
		}
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("reading google oauth keyfile %q: %w", keyPath, err)
		}

		var kf gcpKeyFile
		if err := json.Unmarshal(data, &kf); err != nil {
			return nil, fmt.Errorf("parsing google oauth keyfile %q: %w", keyPath, err)
		}

		if kf.Web != nil {
			h.clientID = kf.Web.ClientID
			h.clientSecret = kf.Web.ClientSecret
		} else if kf.Installed != nil {
			h.clientID = kf.Installed.ClientID
			h.clientSecret = kf.Installed.ClientSecret
		}
	}

	// 2. Direct config values override or fill in
	ctx := context.Background()
	if cfg.ClientID != "" {
		if val, err := secretMgr.ResolveTemplate(ctx, cfg.ClientID); err == nil {
			h.clientID = val
		}
	}
	if cfg.ClientSecret != "" {
		if val, err := secretMgr.ResolveTemplate(ctx, cfg.ClientSecret); err == nil {
			h.clientSecret = val
		}
	}
	if cfg.RedirectURL != "" {
		h.redirectURL = cfg.RedirectURL
	}
	if h.redirectURL == "" {
		h.redirectURL = fmt.Sprintf("%s/auth/callback", h.publicURL)
	}

	if h.clientID == "" {
		return nil, fmt.Errorf("google oauth client_id is not set")
	}

	h.logger.Info("initialized google inbound authentication", "client_id", h.clientID[:min(len(h.clientID), 12)]+"...", "redirect_url", h.redirectURL)
	return h, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// HandleLogin initiates the browser redirect to Google OAuth.
func (h *GoogleAuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateRandomString(32)
	caller := r.URL.Query().Get("caller")

	h.statesMu.Lock()
	// Prune old states
	cutoff := time.Now().Add(-15 * time.Minute)
	for k, t := range h.states {
		if t.CreatedAt.Before(cutoff) {
			delete(h.states, k)
		}
	}
	h.states[state] = googleAuthState{CreatedAt: time.Now(), Caller: caller}
	h.statesMu.Unlock()

	authURL, _ := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
	q := authURL.Query()
	q.Set("client_id", h.clientID)
	q.Set("redirect_uri", h.redirectURL)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("access_type", "offline")
	q.Set("prompt", "consent select_account")
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// HandleCallback exchanges code with Google for tokens and logs the user in.
func (h *GoogleAuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing 'code' or 'state' in callback", http.StatusBadRequest)
		return
	}

	h.statesMu.Lock()
	st, exists := h.states[state]
	if exists {
		delete(h.states, state)
	}
	h.statesMu.Unlock()

	if !exists {
		http.Error(w, "Invalid or expired state nonce (CSRF protection)", http.StatusForbidden)
		return
	}

	// Exchange code at Google Token endpoint
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", h.clientID)
	form.Set("client_secret", h.clientSecret)
	form.Set("redirect_uri", h.redirectURL)
	form.Set("grant_type", "authorization_code")

	tokenReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.client.Do(tokenReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Exchanging code with Google failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Google returned HTTP %d: %s", resp.StatusCode, string(body)), http.StatusBadGateway)
		return
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		http.Error(w, "Failed to parse Google token response", http.StatusInternalServerError)
		return
	}

	// Fetch user info using access token
	userReq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	userResp, err := h.client.Do(userReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Fetching userinfo failed: %v", err), http.StatusBadGateway)
		return
	}
	defer userResp.Body.Close()

	userBody, _ := io.ReadAll(userResp.Body)
	var uInfo googleUserInfo
	if err := json.Unmarshal(userBody, &uInfo); err != nil || uInfo.Email == "" {
		http.Error(w, "Failed to retrieve user email from Google", http.StatusInternalServerError)
		return
	}

	// Check whitelist
	if !h.isEmailAllowed(uInfo.Email) {
		http.Error(w, fmt.Sprintf("Access denied: %s is not in the allowed users list", uInfo.Email), http.StatusForbidden)
		return
	}

	// Determine caller identity
	callerID := st.Caller
	if callerID == "" {
		if h.proxy != nil {
			h.proxy.mu.RLock()
			for id, c := range h.proxy.identities {
				if c.MatchesEmail(id, uInfo.Email) {
					callerID = id
					break
				}
			}
			h.proxy.mu.RUnlock()
		}
	}
	if callerID == "" {
		callerID = uInfo.Email
	}

	// Persist tokens to vault
	if h.proxy != nil && h.proxy.TokenStore() != nil {
		var exp time.Time
		if tokenResp.ExpiresIn > 0 {
			exp = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		}
		tSet := &TokenSet{
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			TokenType:    tokenResp.TokenType,
			ExpiresAt:    exp,
			Scopes:       strings.Split(tokenResp.Scope, " "),
			UpdatedAt:    time.Now(),
		}
		if tSet.TokenType == "" {
			tSet.TokenType = "Bearer"
		}
		// Preserve existing refresh token if Google omitted it in this exchange
		if tSet.RefreshToken == "" {
			if existing, err := h.proxy.TokenStore().Get(r.Context(), callerID, "__google_gateway__"); err == nil && existing != nil {
				tSet.RefreshToken = existing.RefreshToken
			}
		}

		if err := h.proxy.TokenStore().Put(r.Context(), callerID, "__google_gateway__", tSet); err != nil {
			h.logger.Error("failed to persist google gateway tokens to vault", "caller", callerID, "err", err)
		} else {
			h.logger.Info("successfully persisted google gateway tokens in vault", "caller", callerID, "email", uInfo.Email, "has_refresh", tSet.RefreshToken != "")
		}
	}

	// Create session token for browser cookie
	sessionToken := generateRandomString(32)
	h.sessionsMu.Lock()
	h.sessions[sessionToken] = uInfo.Email
	h.sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "mcp_session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.publicURL, "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30, // 30 days
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Signed In</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); text-align: center; max-width: 440px; }
    .icon { font-size: 3rem; margin-bottom: 1rem; }
    h1 { margin: 0 0 0.5rem 0; font-size: 1.5rem; color: #38bdf8; }
    p { color: #94a3b8; line-height: 1.5; }
    .token-box { background: #0f172a; padding: 0.8rem; border-radius: 6px; font-family: monospace; font-size: 0.85rem; color: #a5f3fc; word-break: break-all; margin: 1rem 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔒</div>
    <h1>Signed In with Google</h1>
    <p>Authenticated as <strong>%s</strong>.<br/>Your session is active. You can now connect your AI assistant to <code>%s/mcp</code>.</p>
    <p style="font-size: 0.85rem;">If your MCP client uses Bearer token authorization, use this token:</p>
    <div class="token-box">%s</div>
  </div>
</body>
</html>`, htmlEscape(uInfo.Email), htmlEscape(h.publicURL), sessionToken)
}

func (h *GoogleAuthHandler) isEmailAllowed(email string) bool {
	if len(h.cfg.AllowedUsers) > 0 {
		for _, allowed := range h.cfg.AllowedUsers {
			if allowed == "*" || strings.EqualFold(allowed, email) {
				return true
			}
		}
		return false
	}
	if h.proxy != nil {
		h.proxy.mu.RLock()
		defer h.proxy.mu.RUnlock()
		for id, ident := range h.proxy.identities {
			if ident.MatchesEmail(id, email) {
				return true
			}
		}
	}
	return true
}

// AuthenticateRequest checks for an active Google session cookie or bearer token.
func (h *GoogleAuthHandler) AuthenticateRequest(r *http.Request) (string, bool) {
	// 1. Check Cookie
	if cookie, err := r.Cookie("mcp_session"); err == nil && cookie.Value != "" {
		h.sessionsMu.RLock()
		email, ok := h.sessions[cookie.Value]
		h.sessionsMu.RUnlock()
		if ok {
			return email, true
		}
	}

	// 2. Check Authorization Header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		h.sessionsMu.RLock()
		email, ok := h.sessions[token]
		h.sessionsMu.RUnlock()
		if ok {
			return email, true
		}
	}

	return "", false
}

// HandleProtectedResourceMetadata serves RFC 9728 Protected Resource Metadata for the gateway.
func (h *GoogleAuthHandler) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":              fmt.Sprintf("%s/mcp", h.publicURL),
		"authorization_servers": []string{"https://accounts.google.com"},
		"scopes_supported":      []string{"openid", "email", "profile", "tools:read", "tools:call"},
	})
}

// IsCallerAuthenticated checks whether the given callerID has a valid (or refreshable) Google gateway token in the vault.
func (h *GoogleAuthHandler) IsCallerAuthenticated(ctx context.Context, callerID string) (bool, error) {
	if h == nil || h.proxy == nil || h.proxy.TokenStore() == nil {
		return true, nil
	}
	if callerID == "" {
		return false, nil
	}

	token, err := h.proxy.TokenStore().Get(ctx, callerID, "__google_gateway__")
	if err != nil || token == nil || token.AccessToken == "" {
		return false, nil
	}

	// If token has not expired (with 1-minute buffer), it's valid
	if !token.IsExpired(1 * time.Minute) {
		return true, nil
	}

	// If token has expired, attempt silent refresh if refresh token is available
	if token.RefreshToken != "" {
		refreshed, err := h.RefreshToken(ctx, callerID)
		if err == nil && refreshed != nil {
			return true, nil
		}
		h.logger.Warn("failed to refresh expired google gateway token", "caller", callerID, "err", err)
	}

	return false, nil
}

// RefreshToken silently refreshes an expired Google Gateway access token.
func (h *GoogleAuthHandler) RefreshToken(ctx context.Context, callerID string) (*TokenSet, error) {
	token, err := h.proxy.TokenStore().Get(ctx, callerID, "__google_gateway__")
	if err != nil {
		return nil, fmt.Errorf("getting token from vault: %w", err)
	}
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available for caller %q", callerID)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", token.RefreshToken)
	form.Set("client_id", h.clientID)
	form.Set("client_secret", h.clientSecret)

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token refresh request: %w", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.client.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google returned HTTP %d on token refresh: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	var exp time.Time
	if tokenResp.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	token.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		token.RefreshToken = tokenResp.RefreshToken
	}
	token.ExpiresAt = exp
	token.UpdatedAt = time.Now()

	if err := h.proxy.TokenStore().Put(ctx, callerID, "__google_gateway__", token); err != nil {
		return nil, fmt.Errorf("saving refreshed token: %w", err)
	}
	h.logger.Info("successfully refreshed google gateway token", "caller", callerID)
	return token, nil
}
