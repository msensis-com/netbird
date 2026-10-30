package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/ratelimit"
)

// UserGetter loads a NetBird user by ID.
type UserGetter interface {
	GetUserByID(ctx context.Context, id string) (*types.User, error)
}

// UserInfoHandler tells a proxied backend who sent a request. The proxy
// forwards the caller's session token as X-NetBird-AuthToken, and the backend
// presents it here instead of trusting the plain identity headers, which any
// client that reaches the backend directly could set.
type UserInfoHandler struct {
	proxyService   *nbgrpc.ProxyServiceServer
	users          UserGetter
	rateLimiter    *ratelimit.APIRateLimiter
	trustedProxies []netip.Prefix
}

type userInfoGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userInfoResponse struct {
	ID        string          `json:"id"`
	Email     string          `json:"email"`
	Name      string          `json:"name"`
	Role      string          `json:"role"`
	Status    string          `json:"status"`
	LastLogin *time.Time      `json:"last_login,omitempty"`
	AccountID string          `json:"account_id"`
	Service   string          `json:"service"`
	Groups    []userInfoGroup `json:"groups"`
}

// NewUserInfoHandler creates the handler for the proxy userinfo endpoint.
func NewUserInfoHandler(proxyService *nbgrpc.ProxyServiceServer, users UserGetter, trustedProxies []netip.Prefix) *UserInfoHandler {
	// A backend asks once per user per cache period, so the limit only has to
	// stop token guessing, not normal traffic from a busy backend.
	rateLimiterConfig := &ratelimit.RateLimiterConfig{
		RequestsPerMinute: 600,
		Burst:             100,
		CleanupInterval:   5 * time.Minute,
		LimiterTTL:        10 * time.Minute,
	}

	return &UserInfoHandler{
		proxyService:   proxyService,
		users:          users,
		rateLimiter:    ratelimit.NewAPIRateLimiter(rateLimiterConfig),
		trustedProxies: trustedProxies,
	}
}

// RegisterEndpoints registers the userinfo endpoint.
func (h *UserInfoHandler) RegisterEndpoints(router *mux.Router) {
	router.HandleFunc(types.ProxyUserInfoEndpoint, h.handleUserInfo).Methods(http.MethodGet)
}

func (h *UserInfoHandler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	clientIP := resolveClientIP(r, h.trustedProxies)
	if !h.rateLimiter.Allow(clientIP) {
		log.WithField("client_ip", clientIP).Warn("proxy userinfo rate limit exceeded")
		util.WriteErrorResponse("too many requests", http.StatusTooManyRequests, w)
		return
	}

	token, ok := bearerToken(r)
	if !ok {
		writeUnauthorized(w)
		return
	}

	domain, err := oidcSessionDomain(token)
	if err != nil {
		log.WithError(err).Debug("proxy userinfo: unusable session token")
		writeUnauthorized(w)
		return
	}

	resp, err := h.proxyService.ValidateSessionToken(r.Context(), domain, token)
	if err != nil {
		log.WithContext(r.Context()).WithError(err).Error("proxy userinfo: validate session token")
		util.WriteErrorResponse("session validation failed", http.StatusInternalServerError, w)
		return
	}

	if !resp.GetValid() {
		h.writeDenied(w, domain, resp.GetUserId(), resp.GetDeniedReason())
		return
	}

	user, err := h.users.GetUserByID(r.Context(), resp.GetUserId())
	if err != nil {
		log.WithContext(r.Context()).WithError(err).Error("proxy userinfo: load user")
		util.WriteErrorResponse("user lookup failed", http.StatusInternalServerError, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, &userInfoResponse{
		ID:        user.Id,
		Email:     resp.GetUserEmail(),
		Name:      user.Name,
		Role:      string(user.Role),
		Status:    string(types.UserStatusActive),
		LastLogin: user.LastLogin,
		AccountID: user.AccountID,
		Service:   domain,
		Groups:    pairUserInfoGroups(resp.GetPeerGroupIds(), resp.GetPeerGroupNames()),
	})
}

// writeDenied answers a token that failed validation. A denial without a user
// means the token itself is not trusted; with a user, the token is genuine but
// the user may not use the service (blocked, pending approval, not in its groups).
func (h *UserInfoHandler) writeDenied(w http.ResponseWriter, domain, userID, reason string) {
	log.WithFields(log.Fields{
		"domain":  domain,
		"user_id": userID,
		"reason":  reason,
	}).Debug("proxy userinfo: session denied")

	if userID == "" {
		writeUnauthorized(w)
		return
	}
	util.WriteErrorResponse(reason, http.StatusForbidden, w)
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	util.WriteErrorResponse("invalid session token", http.StatusUnauthorized, w)
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// oidcSessionDomain reads the service domain and auth method from a session
// token without verifying it. The domain only picks which service key
// ValidateSessionToken verifies the same token with, and that check also
// requires the audience to equal the domain, so both claims are trusted only
// once the token passes it.
func oidcSessionDomain(token string) (string, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return "", fmt.Errorf("parse session token: %w", err)
	}

	audience, err := claims.GetAudience()
	if err != nil {
		return "", fmt.Errorf("read audience: %w", err)
	}
	if len(audience) != 1 || audience[0] == "" {
		return "", errors.New("session token must name exactly one service")
	}

	// PIN and password sessions are minted for synthetic subjects, not users.
	if method, _ := claims["method"].(string); method != auth.MethodOIDC.String() {
		return "", fmt.Errorf("session method %q carries no user", method)
	}

	return audience[0], nil
}

func pairUserInfoGroups(ids, names []string) []userInfoGroup {
	groups := make([]userInfoGroup, 0, len(ids))
	for i, id := range ids {
		group := userInfoGroup{ID: id}
		if i < len(names) {
			group.Name = names[i]
		}
		groups = append(groups, group)
	}
	return groups
}
