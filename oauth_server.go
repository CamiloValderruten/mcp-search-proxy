package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

// PersistentClientStore implements oauth2.ClientStore with file-backed persistence.
type PersistentClientStore struct {
	mu       sync.RWMutex
	filePath string
	clients  map[string]*models.Client
	logger   *slog.Logger
}

// NewPersistentClientStore loads or creates a persistent client store.
func NewPersistentClientStore(filePath string, logger *slog.Logger) (*PersistentClientStore, error) {
	if filePath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		filePath = filepath.Join(home, ".config", "mcp-search-proxy", "oauth_clients.json")
	}

	cs := &PersistentClientStore{
		filePath: filePath,
		clients:  make(map[string]*models.Client),
		logger:   logger,
	}

	if err := cs.load(); err != nil && !os.IsNotExist(err) {
		logger.Warn("could not load oauth clients file, starting fresh", "path", filePath, "err", err)
	}

	return cs, nil
}

func (cs *PersistentClientStore) load() error {
	data, err := os.ReadFile(cs.filePath)
	if err != nil {
		return err
	}
	var loaded map[string]*models.Client
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.clients = loaded
	return nil
}

func (cs *PersistentClientStore) save() error {
	data, err := json.MarshalIndent(cs.clients, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cs.filePath), 0700); err != nil {
		return err
	}
	return os.WriteFile(cs.filePath, data, 0600)
}

// GetByID retrieves a client by ID.
func (cs *PersistentClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	cli, ok := cs.clients[id]
	if !ok {
		return nil, errors.ErrInvalidClient
	}
	return cli, nil
}

// Set stores or updates a client.
func (cs *PersistentClientStore) Set(id string, cli oauth2.ClientInfo) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	mCli := &models.Client{
		ID:     cli.GetID(),
		Secret: cli.GetSecret(),
		Domain: cli.GetDomain(),
		UserID: cli.GetUserID(),
	}
	cs.clients[id] = mCli
	if err := cs.save(); err != nil {
		cs.logger.Warn("failed to persist oauth client to disk", "path", cs.filePath, "err", err)
	}
	return nil
}

// OAuthServer manages the inbound OAuth 2.1 Authorization Server for Gemini Spark and other AI clients.
type OAuthServer struct {
	manager     *manage.Manager
	server      *server.Server
	clientStore *PersistentClientStore
	tokenStore  oauth2.TokenStore
	googleAuth  *GoogleAuthHandler
	proxy       *Proxy
	publicURL   string
	logger      *slog.Logger
}

// DynamicClientRegistrationRequest represents an RFC 7591 client registration request.
type DynamicClientRegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// DynamicClientRegistrationResponse represents an RFC 7591 client registration response.
type DynamicClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// NewOAuthServer initializes an OAuth 2.1 authorization server.
func NewOAuthServer(publicURL string, clientStorePath string, googleAuth *GoogleAuthHandler, proxy *Proxy, logger *slog.Logger) (*OAuthServer, error) {
	if publicURL == "" {
		publicURL = "http://localhost:8080"
	}
	publicURL = strings.TrimSuffix(publicURL, "/")

	cs, err := NewPersistentClientStore(clientStorePath, logger)
	if err != nil {
		return nil, fmt.Errorf("creating client store: %w", err)
	}

	mgr := manage.NewDefaultManager()
	mgr.MapClientStorage(cs)
	tStore, _ := store.NewMemoryTokenStore()
	mgr.MapTokenStorage(tStore)

	// Token lifetime policies
	mgr.SetAuthorizeCodeExp(10 * time.Minute)
	mgr.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    24 * time.Hour,
		RefreshTokenExp:   30 * 24 * time.Hour,
		IsGenerateRefresh: true,
	})

	// Flexible URI validator: allows exact match or any domain-matched URI from space/comma separated list
	mgr.SetValidateURIHandler(func(baseURI, redirectURI string) error {
		if baseURI == "" || redirectURI == "" {
			return nil
		}
		allowedURIs := strings.FieldsFunc(baseURI, func(r rune) bool {
			return r == ' ' || r == ',' || r == '\n' || r == ';'
		})
		for _, u := range allowedURIs {
			if u == redirectURI || manage.DefaultValidateURI(u, redirectURI) == nil {
				return nil
			}
		}
		return manage.DefaultValidateURI(baseURI, redirectURI)
	})

	srv := server.NewDefaultServer(mgr)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(func(r *http.Request) (string, string, error) {
		if username, password, ok := r.BasicAuth(); ok && username != "" {
			return username, password, nil
		}
		if r.Form == nil {
			_ = r.ParseForm()
		}
		clientID := r.Form.Get("client_id")
		if clientID == "" && r.PostForm != nil {
			clientID = r.PostForm.Get("client_id")
		}
		if clientID == "" {
			return "", "", errors.ErrInvalidClient
		}
		clientSecret := r.Form.Get("client_secret")
		if clientSecret == "" && r.PostForm != nil {
			clientSecret = r.PostForm.Get("client_secret")
		}
		return clientID, clientSecret, nil
	})
	srv.SetResponseErrorHandler(func(ctx context.Context, re *errors.Response) {
		logger.Warn("oauth response error", "error", re.Error, "description", re.Description, "status", re.StatusCode)
	})

	s := &OAuthServer{
		manager:     mgr,
		server:      srv,
		clientStore: cs,
		googleAuth:  googleAuth,
		proxy:       proxy,
		publicURL:   publicURL,
		logger:      logger,
	}

	// Configure User Authorization Handler (Google Login Bridge)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) {
		if s.googleAuth != nil {
			if userEmail, ok := s.googleAuth.AuthenticateRequest(r); ok {
				if !s.googleAuth.isEmailAllowed(userEmail) {
					return "", errors.ErrAccessDenied
				}
				callerID := userEmail
				if s.proxy != nil {
					s.proxy.mu.RLock()
					for id, ident := range s.proxy.identities {
						if ident.MatchesEmail(id, userEmail) {
							callerID = id
							break
						}
					}
					s.proxy.mu.RUnlock()
				}
				return callerID, nil
			}
		}

		// If unauthenticated, redirect the user's browser to Google Sign-In
		returnTo := r.RequestURI
		if returnTo == "" {
			returnTo = r.URL.String()
		}
		loginURL := fmt.Sprintf("%s/auth/login?return_to=%s", s.publicURL, url.QueryEscape(returnTo))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return "", nil
	})

	return s, nil
}

// HandleAuthServerMetadata returns RFC 8414 OAuth 2.0 Authorization Server Metadata.
func (s *OAuthServer) HandleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	metadata := map[string]any{
		"issuer":                                s.publicURL,
		"authorization_endpoint":                fmt.Sprintf("%s/oauth/authorize", s.publicURL),
		"token_endpoint":                        fmt.Sprintf("%s/oauth/token", s.publicURL),
		"registration_endpoint":                 fmt.Sprintf("%s/oauth/register", s.publicURL),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"scopes_supported":                      []string{"openid", "email", "profile", "mcp:read", "mcp:write", "tools:read", "tools:call"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"service_documentation":                 s.publicURL,
	}

	_ = json.NewEncoder(w).Encode(metadata)
}

// HandleProtectedResourceMetadata returns RFC 9728 Protected Resource Metadata for the gateway.
func (s *OAuthServer) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	metadata := map[string]any{
		"resource":                 fmt.Sprintf("%s/mcp", s.publicURL),
		"authorization_servers":    []string{s.publicURL},
		"scopes_supported":         []string{"openid", "email", "profile", "mcp:read", "mcp:write", "tools:read", "tools:call"},
		"bearer_methods_supported": []string{"header"},
	}

	_ = json.NewEncoder(w).Encode(metadata)
}

// HandleRegister handles RFC 7591 Dynamic Client Registration.
func (s *OAuthServer) HandleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DynamicClientRegistrationRequest
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	if len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
	}

	// Generate Client ID and Client Secret
	clientIDBytes := make([]byte, 16)
	_, _ = rand.Read(clientIDBytes)
	clientID := "mcp_" + hex.EncodeToString(clientIDBytes)

	clientSecretBytes := make([]byte, 24)
	_, _ = rand.Read(clientSecretBytes)
	clientSecret := hex.EncodeToString(clientSecretBytes)

	redirectDomain := strings.Join(req.RedirectURIs, " ")
	if err := s.clientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: clientSecret,
		Domain: redirectDomain,
		UserID: req.ClientName,
	}); err != nil {
		s.logger.Error("failed to store dynamic oauth client", "client_id", clientID, "err", err)
		http.Error(w, "Failed to register client", http.StatusInternalServerError)
		return
	}

	s.logger.Info("registered dynamic oauth client", "client_id", clientID, "client_name", req.ClientName, "redirect_uris", req.RedirectURIs)

	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_post"
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	resp := DynamicClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleAuthorize handles the OAuth 2.1 authorization endpoint.
func (s *OAuthServer) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := s.server.HandleAuthorizeRequest(w, r); err != nil {
		s.logger.Warn("oauth authorize request failed", "err", err, "query", r.URL.RawQuery)
	}
}

// HandleToken handles the OAuth 2.1 token exchange and refresh endpoint.
func (s *OAuthServer) HandleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	_ = r.ParseForm()

	// Resilient fallback: parse JSON body if sent with application/json
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var jsonBody map[string]any
		data, err := io.ReadAll(r.Body)
		if err == nil && len(data) > 0 {
			if err := json.Unmarshal(data, &jsonBody); err == nil {
				if r.PostForm == nil {
					r.PostForm = make(url.Values)
				}
				if r.Form == nil {
					r.Form = make(url.Values)
				}
				for k, v := range jsonBody {
					if str, ok := v.(string); ok {
						r.PostForm.Set(k, str)
						r.Form.Set(k, str)
					}
				}
			}
		}
	}

	if err := s.server.HandleTokenRequest(w, r); err != nil {
		s.logger.Warn("oauth token request failed", "err", err, "form", r.Form)
	}
}

// ValidateAccessToken checks if the Authorization Bearer header contains a valid token issued by this OAuthServer.
func (s *OAuthServer) ValidateAccessToken(r *http.Request) (string, error) {
	tokenInfo, err := s.server.ValidationBearerToken(r)
	if err != nil {
		return "", err
	}
	return tokenInfo.GetUserID(), nil
}
