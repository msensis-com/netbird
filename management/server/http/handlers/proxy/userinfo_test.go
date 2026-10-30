package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/proxy/auth"
)

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
		wantOK bool
	}{
		{name: "bearer token", header: "Bearer abc.def.ghi", want: "abc.def.ghi", wantOK: true},
		{name: "lower-case scheme", header: "bearer abc.def.ghi", want: "abc.def.ghi", wantOK: true},
		{name: "missing header", header: ""},
		{name: "other scheme", header: "Basic dXNlcjpwYXNz"},
		{name: "empty token", header: "Bearer   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			got, ok := bearerToken(req)
			assert.Equal(t, tt.wantOK, ok, "whether a token was found")
			assert.Equal(t, tt.want, got, "the extracted token")
		})
	}
}

func TestOIDCSessionDomain(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := base64.StdEncoding.EncodeToString(priv)

	sign := func(method auth.Method) string {
		token, err := sessionkey.SignToken(key, "user-1", "", "app.example.com", method, nil, nil, time.Hour)
		require.NoError(t, err)
		return token
	}

	domain, err := oidcSessionDomain(sign(auth.MethodOIDC))
	require.NoError(t, err)
	assert.Equal(t, "app.example.com", domain, "the domain is the token's single audience")

	_, err = oidcSessionDomain(sign(auth.MethodPIN))
	assert.Error(t, err, "a PIN session carries no user")

	_, err = oidcSessionDomain("not-a-jwt")
	assert.Error(t, err, "an unparseable token has no domain")

	multiAudience := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"aud":    []string{"a.example.com", "b.example.com"},
		"method": "oidc",
	})
	signed, err := multiAudience.SignedString(priv)
	require.NoError(t, err)
	_, err = oidcSessionDomain(signed)
	assert.Error(t, err, "a token naming several services is refused")
}

func TestPairUserInfoGroups(t *testing.T) {
	got := pairUserInfoGroups([]string{"g1", "g2"}, []string{"Engineering"})
	assert.Equal(t, []userInfoGroup{{ID: "g1", Name: "Engineering"}, {ID: "g2"}}, got,
		"a group without a resolved name keeps its id")

	assert.Equal(t, []userInfoGroup{}, pairUserInfoGroups(nil, nil),
		"no groups must encode as an empty list, not null")
}
