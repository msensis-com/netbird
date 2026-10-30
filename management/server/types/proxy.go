package types

// ProxyCallbackEndpoint holds the proxy callback endpoint
const ProxyCallbackEndpoint = "/reverse-proxy/callback"

// ProxyCallbackEndpointFull holds the proxy callback endpoint with api suffix
const ProxyCallbackEndpointFull = "/api" + ProxyCallbackEndpoint

// ProxyUserInfoEndpoint holds the endpoint a proxied backend calls with the
// session token the proxy forwarded, to learn who the caller is
const ProxyUserInfoEndpoint = "/reverse-proxy/userinfo"

// ProxyUserInfoEndpointFull holds the proxy userinfo endpoint with api suffix
const ProxyUserInfoEndpointFull = "/api" + ProxyUserInfoEndpoint
