package dex

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/connector/oidc"
	"github.com/dexidp/dex/server"
)

const (
	oidcConnectorType = "oidc"
	entraProviderType = "entra"

	promptParam         = "prompt"
	promptSelectAccount = "select_account"
)

func init() {
	server.ConnectorsConfig[oidcConnectorType] = func() server.ConnectorConfig {
		return new(accountPickerConfig)
	}
}

// accountPickerConfig opens Dex's OIDC connector and adds Microsoft's account picker
// to Entra logins. Without it Microsoft can silently reuse an account the browser is
// signed in to. Dex only sends a prompt for offline_access logins, which would also
// create refresh tokens nothing uses.
type accountPickerConfig struct {
	oidc.Config
}

// Open implements server.ConnectorConfig.
func (c *accountPickerConfig) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	conn, err := c.Config.Open(id, logger)
	if err != nil {
		return nil, err
	}
	if inferOIDCProviderType(id) != entraProviderType {
		return conn, nil
	}

	capable, ok := conn.(oidcConnectorCapabilities)
	if !ok {
		// The picker is a convenience, not a security check, so logins keep working without it.
		logger.Warn("OIDC connector cannot be wrapped, account picker disabled", "connector", id)
		return conn, nil
	}
	return accountPickerConnector{oidcConnectorCapabilities: capable}, nil
}

// oidcConnectorCapabilities lists what Dex's OIDC connector can do. Dex checks these
// with type assertions, so a capability missing here would silently switch off.
type oidcConnectorCapabilities interface {
	connector.CallbackConnector
	connector.RefreshConnector
	connector.TokenIdentityConnector
	connector.LogoutCallbackConnector
	io.Closer
}

// accountPickerConnector forwards everything to Dex's OIDC connector except the login URL.
type accountPickerConnector struct {
	oidcConnectorCapabilities
}

// LoginURL implements connector.CallbackConnector.
func (c accountPickerConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, []byte, error) {
	loginURL, connData, err := c.oidcConnectorCapabilities.LoginURL(s, callbackURL, state)
	if err != nil {
		return "", nil, err
	}
	loginURL, err = addAccountPrompt(loginURL)
	if err != nil {
		return "", nil, err
	}
	return loginURL, connData, nil
}

func addAccountPrompt(loginURL string) (string, error) {
	parsed, err := url.Parse(loginURL)
	if err != nil {
		return "", fmt.Errorf("parse login URL: %w", err)
	}
	query := parsed.Query()
	// Dex sets its own prompt on offline_access logins, and the two cannot be combined.
	if query.Has(promptParam) {
		return loginURL, nil
	}
	query.Set(promptParam, promptSelectAccount)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
