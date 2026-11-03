package dex

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/connector/oidc"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDexIssuer       = "http://dex.test/oauth2"
	testClientRedirect  = "http://client.test/callback"
	testEntraConnector  = "entra-test"
	testOktaConnector   = "okta-test"
	testAuthorizePath   = "/authorize"
	testConnectorSecret = "connector-secret"
)

// newFakeIssuer serves the OIDC discovery document Dex's connector reads when it opens.
func newFakeIssuer(t *testing.T) *httptest.Server {
	t.Helper()
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			issuer.URL, issuer.URL+testAuthorizePath, issuer.URL+"/token", issuer.URL+"/keys")
	}))
	t.Cleanup(issuer.Close)
	return issuer
}

func testConnectorConfig(issuer string) []byte {
	data, _ := json.Marshal(map[string]any{
		"issuer":       issuer,
		"clientID":     "connector-client",
		"clientSecret": testConnectorSecret,
		"redirectURI":  testDexIssuer + "/callback",
	})
	return data
}

// openRegisteredConnector opens a connector the way Dex does: through ConnectorsConfig.
func openRegisteredConnector(t *testing.T, issuer, id string) connector.Connector {
	t.Helper()
	config := server.ConnectorsConfig[oidcConnectorType]()
	require.NoError(t, json.Unmarshal(testConnectorConfig(issuer), config))
	conn, err := config.Open(id, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return conn
}

func loginQuery(t *testing.T, conn connector.Connector, scopes connector.Scopes) url.Values {
	t.Helper()
	callback, ok := conn.(connector.CallbackConnector)
	require.True(t, ok, "OIDC connector must support the callback flow")
	loginURL, _, err := callback.LoginURL(scopes, testDexIssuer+"/callback", "login-state")
	require.NoError(t, err)
	parsed, err := url.Parse(loginURL)
	require.NoError(t, err)
	assert.Equal(t, testAuthorizePath, parsed.Path, "login must still go to the issuer's authorize endpoint")
	return parsed.Query()
}

func TestAccountPicker_EntraLoginAsksForAccount(t *testing.T) {
	issuer := newFakeIssuer(t)

	query := loginQuery(t, openRegisteredConnector(t, issuer.URL, testEntraConnector), connector.Scopes{})

	assert.Equal(t, promptSelectAccount, query.Get(promptParam), "Entra logins must show the account picker")
	assert.Equal(t, "login-state", query.Get("state"), "the rest of the login request must survive")
	assert.Equal(t, "connector-client", query.Get("client_id"), "the rest of the login request must survive")
}

func TestAccountPicker_OtherProvidersUnchanged(t *testing.T) {
	issuer := newFakeIssuer(t)

	conn := openRegisteredConnector(t, issuer.URL, testOktaConnector)

	_, wrapped := conn.(accountPickerConnector)
	assert.False(t, wrapped, "only Entra connectors should be wrapped")
	assert.Empty(t, loginQuery(t, conn, connector.Scopes{}).Get(promptParam), "other providers must not get a prompt")
}

// Dex sends its own prompt on offline_access logins. OIDC prompt values chosen by Dex's
// configuration must win, so this flow behaves as it did before the wrapper existed.
func TestAccountPicker_KeepsDexPromptOnOfflineLogins(t *testing.T) {
	issuer := newFakeIssuer(t)

	query := loginQuery(t, openRegisteredConnector(t, issuer.URL, testEntraConnector), connector.Scopes{OfflineAccess: true})

	assert.Equal(t, "consent", query.Get(promptParam), "Dex's own prompt must be left alone")
}

// Dex decides what a connector can do by type-asserting it, so a capability the wrapper
// does not forward silently stops working. This fails when a Dex upgrade adds one.
func TestAccountPicker_ForwardsEveryConnectorCapability(t *testing.T) {
	issuer := newFakeIssuer(t)

	var config oidc.Config
	require.NoError(t, json.Unmarshal(testConnectorConfig(issuer.URL), &config))
	plain, err := config.Open(testEntraConnector, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	wrapped := openRegisteredConnector(t, issuer.URL, testEntraConnector)
	require.IsType(t, accountPickerConnector{}, wrapped, "Entra connectors must be wrapped")

	plainType, wrappedType := reflect.TypeOf(plain), reflect.TypeOf(wrapped)
	require.Positive(t, plainType.NumMethod(), "the plain connector must expose methods to compare")
	for i := range plainType.NumMethod() {
		name := plainType.Method(i).Name
		_, ok := wrappedType.MethodByName(name)
		assert.Truef(t, ok, "wrapper does not forward %s; add it to oidcConnectorCapabilities", name)
	}

	assert.Implements(t, (*connector.CallbackConnector)(nil), wrapped, "login must keep working")
	assert.Implements(t, (*connector.RefreshConnector)(nil), wrapped, "refresh must keep working")
	assert.Implements(t, (*connector.TokenIdentityConnector)(nil), wrapped, "token exchange must keep working")
	assert.Implements(t, (*connector.LogoutCallbackConnector)(nil), wrapped, "logout must keep working")
	assert.Implements(t, (*io.Closer)(nil), wrapped, "shutdown must keep working")
}

// newAccountPickerServer runs a real Dex with an Entra connector and a NetBird-like client.
func newAccountPickerServer(t *testing.T, issuer string) *httptest.Server {
	t.Helper()
	t.Setenv("DEX_SESSIONS_ENABLED", "true")
	ctx := context.Background()

	yamlConfig := &YAMLConfig{
		Issuer:  testDexIssuer,
		Storage: Storage{Type: "sqlite3", Config: map[string]any{"file": filepath.Join(t.TempDir(), "dex.db")}},
		Web:     Web{HTTP: "127.0.0.1:0"},
		OAuth2:  OAuth2{SkipApprovalScreen: true},
		Sessions: &Sessions{
			CookieName:           "netbird-session",
			AbsoluteLifetime:     "24h",
			ValidIfNotUsedFor:    "1h",
			SSOSharedWithDefault: "all",
		},
		StaticClients: []storage.Client{{
			ID: "netbird-dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{testClientRedirect},
		}},
		StaticConnectors: []Connector{{
			Type: "entra", Name: "Microsoft Entra", ID: testEntraConnector,
			Config: map[string]any{
				"issuer": issuer, "clientID": "connector-client", "clientSecret": testConnectorSecret,
				"redirectURI": testDexIssuer + "/callback",
			},
		}},
	}
	provider, err := NewProviderFromYAML(ctx, yamlConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.storage.Close() })

	dexServer := httptest.NewServer(provider.Handler())
	t.Cleanup(dexServer.Close)
	return dexServer
}

// followToIssuer walks Dex's redirects for an authorization request and returns the
// first redirect that leaves Dex: the login page, or back to the client on an error.
func followToIssuer(t *testing.T, dexServer *httptest.Server, params url.Values) *url.URL {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	next := dexServer.URL + "/oauth2/auth?" + params.Encode()
	dexBase, err := url.Parse(testDexIssuer)
	require.NoError(t, err)

	for range 5 {
		resp, err := client.Get(next)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.GreaterOrEqual(t, resp.StatusCode, 300, "Dex must redirect, got %d for %s", resp.StatusCode, next)
		require.Less(t, resp.StatusCode, 400, "Dex must redirect, got %d for %s", resp.StatusCode, next)

		location, err := resp.Location()
		require.NoError(t, err)
		if location.Host != "" && location.Host != dexBase.Host && location.Host != resp.Request.URL.Host {
			return location
		}
		next = dexServer.URL + location.RequestURI()
	}
	require.FailNow(t, "too many redirects inside Dex")
	return nil
}

func authorizationParams() url.Values {
	return url.Values{
		"client_id":     {"netbird-dashboard"},
		"redirect_uri":  {testClientRedirect},
		"response_type": {"code"},
		"scope":         {"openid profile email groups"},
		"state":         {"client-state"},
	}
}

// The scopes here are the ones NetBird's proxy and dashboard really request: no
// offline_access. This proves the picker reaches Microsoft through Dex's real handlers.
func TestAccountPicker_RealLoginRequestReachesEntraWithPrompt(t *testing.T) {
	issuer := newFakeIssuer(t)
	dexServer := newAccountPickerServer(t, issuer.URL)

	location := followToIssuer(t, dexServer, authorizationParams())

	assert.Equal(t, testAuthorizePath, location.Path, "the login must end at Microsoft's authorize endpoint")
	assert.Equal(t, promptSelectAccount, location.Query().Get(promptParam), "Microsoft must be asked to show the picker")
}

// The dashboard renews tokens silently with prompt=none. That must fail back to the
// client, never reach a login page it cannot display in its hidden frame.
func TestAccountPicker_SilentRenewalNeverReachesEntra(t *testing.T) {
	issuer := newFakeIssuer(t)
	dexServer := newAccountPickerServer(t, issuer.URL)

	params := authorizationParams()
	params.Set(promptParam, "none")
	location := followToIssuer(t, dexServer, params)

	assert.NotEqual(t, testAuthorizePath, location.Path, "silent renewal must not be sent to Microsoft")
	assert.Equal(t, "login_required", location.Query().Get("error"), "with no session, silent renewal must report login_required")
}
