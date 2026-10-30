//go:build integration

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/proxy/auth"
)

type storeUserGetter struct {
	store store.Store
}

func (g storeUserGetter) GetUserByID(ctx context.Context, id string) (*types.User, error) {
	return g.store.GetUserByUserID(ctx, store.LockingStrengthNone, id)
}

type userInfoTestSetup struct {
	*testSetup
	router *mux.Router
	// sessionKey is the private key the test services sign session tokens with.
	sessionKey string
}

func setupUserInfoTest(t *testing.T) *userInfoTestSetup {
	t.Helper()

	setup := setupAuthCallbackTest(t)
	t.Cleanup(setup.cleanup)

	ctx := context.Background()

	user, err := setup.store.GetUserByUserID(ctx, store.LockingStrengthNone, "allowedUserId")
	require.NoError(t, err)
	user.Name = "Alice Example"
	user.Email = "alice@test.com"
	require.NoError(t, setup.store.SaveUser(ctx, user))

	svc, err := setup.store.GetServiceByDomain(ctx, "test-proxy.example.com")
	require.NoError(t, err)

	router := mux.NewRouter()
	NewUserInfoHandler(setup.proxyService, storeUserGetter{store: setup.store}, nil).RegisterEndpoints(router)

	return &userInfoTestSetup{testSetup: setup, router: router, sessionKey: svc.SessionPrivateKey}
}

func (s *userInfoTestSetup) signToken(t *testing.T, userID, domain string, method auth.Method, expiration time.Duration) string {
	t.Helper()
	token, err := sessionkey.SignToken(s.sessionKey, userID, "", domain, method, nil, nil, expiration)
	require.NoError(t, err)
	return token
}

func (s *userInfoTestSetup) get(authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, types.ProxyUserInfoEndpoint, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func TestUserInfo_ValidSession(t *testing.T) {
	setup := setupUserInfoTest(t)

	token := setup.signToken(t, "allowedUserId", "test-proxy.example.com", auth.MethodOIDC, time.Hour)
	rec := setup.get("Bearer " + token)

	require.Equal(t, http.StatusOK, rec.Code, "a valid OIDC session must resolve, body: %s", rec.Body.String())

	var got userInfoResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))

	assert.Equal(t, "allowedUserId", got.ID, "id must be the NetBird user id")
	assert.Equal(t, "alice@test.com", got.Email, "email must come from the stored user")
	assert.Equal(t, "Alice Example", got.Name, "name must come from the stored user")
	assert.Equal(t, string(types.UserRoleUser), got.Role, "role must be the NetBird role")
	assert.Equal(t, string(types.UserStatusActive), got.Status, "a validated user is active")
	assert.Equal(t, "testAccountId", got.AccountID, "account must be the user's account")
	assert.Equal(t, "test-proxy.example.com", got.Service, "service must be the token's domain")
	assert.Equal(t, []userInfoGroup{{ID: "allowedGroupId", Name: "Allowed Group"}}, got.Groups,
		"groups must pair ids with their current names")
}

func TestUserInfo_RejectsUntrustedTokens(t *testing.T) {
	setup := setupUserInfoTest(t)

	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	forged, err := sessionkey.SignToken(base64.StdEncoding.EncodeToString(otherKey), "allowedUserId", "",
		"test-proxy.example.com", auth.MethodOIDC, nil, nil, time.Hour)
	require.NoError(t, err)

	tests := []struct {
		name          string
		authorization string
	}{
		{name: "no authorization header", authorization: ""},
		{name: "not a bearer scheme", authorization: "Basic " + setup.signToken(t, "allowedUserId", "test-proxy.example.com", auth.MethodOIDC, time.Hour)},
		{name: "garbage token", authorization: "Bearer not-a-jwt"},
		{name: "signed with another key", authorization: "Bearer " + forged},
		{name: "expired", authorization: "Bearer " + setup.signToken(t, "allowedUserId", "test-proxy.example.com", auth.MethodOIDC, -time.Minute)},
		{name: "unknown service domain", authorization: "Bearer " + setup.signToken(t, "allowedUserId", "unknown.example.com", auth.MethodOIDC, time.Hour)},
		{name: "pin session", authorization: "Bearer " + setup.signToken(t, "pin-user", "test-proxy.example.com", auth.MethodPIN, time.Hour)},
		{name: "password session", authorization: "Bearer " + setup.signToken(t, "password-user", "test-proxy.example.com", auth.MethodPassword, time.Hour)},
		{name: "user of another account", authorization: "Bearer " + setup.signToken(t, "otherAccountUserId", "test-proxy.example.com", auth.MethodOIDC, time.Hour)},
		{name: "unknown user", authorization: "Bearer " + setup.signToken(t, "ghostUserId", "test-proxy.example.com", auth.MethodOIDC, time.Hour)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := setup.get(tt.authorization)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "an untrusted token must be refused, body: %s", rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "alice@test.com", "a refused token must not reveal identity")
		})
	}
}

func TestUserInfo_DeniesUsersWithoutAccess(t *testing.T) {
	setup := setupUserInfoTest(t)

	tests := []struct {
		name   string
		userID string
		domain string
	}{
		{name: "blocked user", userID: "blockedUserId", domain: "test-proxy.example.com"},
		{name: "user pending approval", userID: "pendingUserId", domain: "test-proxy.example.com"},
		{name: "user outside the service's groups", userID: "allowedUserId", domain: "restricted-proxy.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := setup.signToken(t, tt.userID, tt.domain, auth.MethodOIDC, time.Hour)
			rec := setup.get("Bearer " + token)
			assert.Equal(t, http.StatusForbidden, rec.Code, "a genuine token of a denied user must get 403, body: %s", rec.Body.String())
		})
	}
}
