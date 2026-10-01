package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthServerLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	clientsPath := filepath.Join(tempDir, "oauth_clients.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// 1. Initialize OAuthServer
	publicURL := "https://mcp.test.example.com"
	srv, err := NewOAuthServer(publicURL, clientsPath, nil, nil, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)

	// 2. Test RFC 8414 Authorization Server Metadata Endpoint
	{
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		rec := httptest.NewRecorder()
		srv.HandleAuthServerMetadata(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var meta map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &meta)
		require.NoError(t, err)
		assert.Equal(t, publicURL, meta["issuer"])
		assert.Equal(t, publicURL+"/oauth/authorize", meta["authorization_endpoint"])
		assert.Equal(t, publicURL+"/oauth/token", meta["token_endpoint"])
		assert.Equal(t, publicURL+"/oauth/register", meta["registration_endpoint"])
		assert.Contains(t, meta["code_challenge_methods_supported"], "S256")
	}

	// 3. Test RFC 9728 Protected Resource Metadata Endpoint
	{
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()
		srv.HandleProtectedResourceMetadata(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var meta map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &meta)
		require.NoError(t, err)
		assert.Equal(t, publicURL+"/mcp", meta["resource"])
		assert.Contains(t, meta["authorization_servers"], publicURL)
	}

	// 4. Test RFC 7591 Dynamic Client Registration
	var clientID, clientSecret string
	redirectURI := "https://gemini.google.com/oauth/callback"
	{
		regPayload := DynamicClientRegistrationRequest{
			ClientName:              "Gemini Spark",
			RedirectURIs:            []string{redirectURI},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "client_secret_post",
		}
		data, _ := json.Marshal(regPayload)
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.HandleRegister(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
		var regResp DynamicClientRegistrationResponse
		err := json.Unmarshal(rec.Body.Bytes(), &regResp)
		require.NoError(t, err)
		assert.NotEmpty(t, regResp.ClientID)
		assert.NotEmpty(t, regResp.ClientSecret)
		assert.Equal(t, "Gemini Spark", regResp.ClientName)
		assert.Contains(t, regResp.RedirectURIs, redirectURI)

		clientID = regResp.ClientID
		clientSecret = regResp.ClientSecret
	}

	// Verify client is persisted on disk
	{
		_, err := os.Stat(clientsPath)
		assert.NoError(t, err)
	}

	// 5. Test PKCE Authorization Flow & Token Issuance
	// Configure mock Google auth handler for login
	gAuthCfg := &GoogleAuthConfig{
		ClientID:     "mock-google-client-id",
		ClientSecret: "mock-google-secret",
		AllowedUsers: []string{"testuser@example.com"},
	}
	gHandler, err := NewGoogleAuthHandler(gAuthCfg, NewSecretManager(5*time.Minute), publicURL, nil, logger)
	require.NoError(t, err)
	srv.googleAuth = gHandler

	// Mock active session for testuser@example.com
	sessionToken := "mock_session_12345"
	gHandler.sessionsMu.Lock()
	gHandler.sessions[sessionToken] = "testuser@example.com"
	gHandler.sessionsMu.Unlock()

	// Generate PKCE code verifier and challenge
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Request authorization code
	authQuery := url.Values{}
	authQuery.Set("response_type", "code")
	authQuery.Set("client_id", clientID)
	authQuery.Set("redirect_uri", redirectURI)
	authQuery.Set("scope", "mcp:read")
	authQuery.Set("state", "xyz123")
	authQuery.Set("code_challenge", codeChallenge)
	authQuery.Set("code_challenge_method", "S256")

	authReq := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authQuery.Encode(), nil)
	authReq.AddCookie(&http.Cookie{Name: "mcp_session", Value: sessionToken})
	authRec := httptest.NewRecorder()

	srv.HandleAuthorize(authRec, authReq)

	assert.Equal(t, http.StatusFound, authRec.Code)
	redirectLocation := authRec.Header().Get("Location")
	require.NotEmpty(t, redirectLocation)
	require.True(t, strings.HasPrefix(redirectLocation, redirectURI))

	locURL, err := url.Parse(redirectLocation)
	require.NoError(t, err)
	authCode := locURL.Query().Get("code")
	require.NotEmpty(t, authCode)
	assert.Equal(t, "xyz123", locURL.Query().Get("state"))

	// Exchange authorization code for access token at /oauth/token
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", clientID)
	tokenForm.Set("client_secret", clientSecret)
	tokenForm.Set("code", authCode)
	tokenForm.Set("redirect_uri", redirectURI)
	tokenForm.Set("code_verifier", codeVerifier)

	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()

	srv.HandleToken(tokenRec, tokenReq)

	t.Logf("Token response code: %d, body: %s", tokenRec.Code, tokenRec.Body.String())
	assert.Equal(t, http.StatusOK, tokenRec.Code)
	var tokResp map[string]any
	err = json.Unmarshal(tokenRec.Body.Bytes(), &tokResp)
	require.NoError(t, err)
	accessToken, ok := tokResp["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)
	refreshToken, ok := tokResp["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, refreshToken)

	// 6. Test ValidateAccessToken on protected request
	{
		mcpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		mcpReq.Header.Set("Authorization", "Bearer "+accessToken)
		userID, err := srv.ValidateAccessToken(mcpReq)
		require.NoError(t, err)
		assert.Equal(t, "testuser@example.com", userID)
	}

	// 7. Test Token Refresh Flow
	{
		refreshForm := url.Values{}
		refreshForm.Set("grant_type", "refresh_token")
		refreshForm.Set("client_id", clientID)
		refreshForm.Set("client_secret", clientSecret)
		refreshForm.Set("refresh_token", refreshToken)

		refreshReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
		refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		refreshRec := httptest.NewRecorder()

		srv.HandleToken(refreshRec, refreshReq)

		assert.Equal(t, http.StatusOK, refreshRec.Code)
		var refResp map[string]any
		err = json.Unmarshal(refreshRec.Body.Bytes(), &refResp)
		require.NoError(t, err)
		newAccessToken, ok := refResp["access_token"].(string)
		require.True(t, ok)
		require.NotEmpty(t, newAccessToken)

		// Verify new access token works
		mcpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		mcpReq.Header.Set("Authorization", "Bearer "+newAccessToken)
		userID, err := srv.ValidateAccessToken(mcpReq)
		require.NoError(t, err)
		assert.Equal(t, "testuser@example.com", userID)
	}

	// 8. Test Unauthenticated Authorize Request redirects to Google Login
	{
		unauthReq := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authQuery.Encode(), nil)
		unauthRec := httptest.NewRecorder()

		srv.HandleAuthorize(unauthRec, unauthReq)

		assert.Equal(t, http.StatusFound, unauthRec.Code)
		loginRedirect := unauthRec.Header().Get("Location")
		require.NotEmpty(t, loginRedirect)
		assert.Contains(t, loginRedirect, "/auth/login?return_to=")
	}

	// 9. Test ValidateAccessToken with invalid token
	{
		mcpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		mcpReq.Header.Set("Authorization", "Bearer invalid-token-xyz")
		userID, err := srv.ValidateAccessToken(mcpReq)
		assert.Error(t, err)
		assert.Empty(t, userID)
	}
}
