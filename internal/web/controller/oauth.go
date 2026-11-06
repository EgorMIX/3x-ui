package controller

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/sub"
	"github.com/mhsanaei/3x-ui/v3/internal/util/oauth"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/tgbot"
	"github.com/mhsanaei/3x-ui/v3/internal/web/session"
)

const oauthDiscoveryTimeout = 15 * time.Second

// getOAuthEnable reports whether OIDC login is active (env or stored settings),
// so the login page can show the SSO button.
func (a *IndexController) getOAuthEnable(c *gin.Context) {
	jsonObj(c, a.settingService.OAuthEnabledEffective(), nil)
}

// oauthLogin starts the OIDC Authorization-Code + PKCE flow: it mints per-login
// state/nonce/verifier, stores them on the session, and redirects to the IdP.
func (a *IndexController) oauthLogin(c *gin.Context) {
	if !a.settingService.OAuthEnabledEffective() {
		c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
		return
	}
	provider, err := a.oauthProviderFor(c)
	if err != nil {
		logger.Warning("oauth: provider init failed:", err)
		a.redirectLoginError(c)
		return
	}
	fs, err := oauth.NewFlowState()
	if err != nil {
		logger.Warning("oauth: flow state failed:", err)
		a.redirectLoginError(c)
		return
	}
	if err := session.SetOAuthFlow(c, fs.State, fs.Nonce, fs.Verifier); err != nil {
		logger.Warning("oauth: unable to store flow state:", err)
		a.redirectLoginError(c)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusTemporaryRedirect, provider.AuthCodeURL(fs))
}

// oauthCallback completes the flow: it validates state, exchanges the code,
// verifies the ID token, maps the caller to a role, and opens a session.
func (a *IndexController) oauthCallback(c *gin.Context) {
	if !a.settingService.OAuthEnabledEffective() {
		c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
		return
	}
	wantState, nonce, verifier := session.GetOAuthFlow(c)
	_ = session.ClearOAuthFlow(c)

	if errParam := c.Query("error"); errParam != "" {
		logger.Warningf("oauth: provider returned error=%q", errParam)
		a.redirectLoginError(c)
		return
	}
	gotState := c.Query("state")
	if wantState == "" || gotState == "" ||
		subtle.ConstantTimeCompare([]byte(wantState), []byte(gotState)) != 1 {
		logger.Warning("oauth: state mismatch on callback")
		a.redirectLoginError(c)
		return
	}
	code := c.Query("code")
	if code == "" {
		logger.Warning("oauth: callback missing code")
		a.redirectLoginError(c)
		return
	}

	provider, err := a.oauthProviderFor(c)
	if err != nil {
		logger.Warning("oauth: provider init failed:", err)
		a.redirectLoginError(c)
		return
	}
	identity, err := provider.Exchange(c.Request.Context(), code, verifier, nonce)
	if err != nil {
		logger.Warning("oauth: exchange failed:", err)
		a.redirectLoginError(c)
		return
	}

	cfg := a.settingService.GetEffectiveOAuthConfig()
	role := resolveRole(identity, cfg)
	remoteIP := getRemoteIp(c)
	timeStr := time.Now().Format("2006-01-02 15:04:05")

	switch role {
	case session.RoleAdmin:
		a.oauthLoginAdmin(c, identity, cfg, remoteIP, timeStr)
	case session.RoleUser:
		a.oauthLoginUser(c, identity, cfg, remoteIP, timeStr)
	default:
		logger.Warningf("oauth: user %q (groups=%v) is in no permitted group", identity.Username, identity.Groups)
		attempt := oauthLoginAttempt(identity, remoteIP, timeStr, tgbot.LoginFail)
		attempt.Reason = "oauth: no permitted group"
		a.tgbot.UserLoginNotify(attempt)
		a.redirectLoginError(c)
	}
}

// oauthLoginAttempt builds the login notification. The username comes from the
// provider and notifications are rendered as HTML, so it is escaped the same way
// as the name typed into the password form.
func oauthLoginAttempt(id *oauth.Identity, remoteIP, timeStr string, status tgbot.LoginStatus) tgbot.LoginAttempt {
	return tgbot.LoginAttempt{
		Username: template.HTMLEscapeString(id.Username),
		IP:       remoteIP,
		Time:     timeStr,
		Status:   status,
	}
}

// oauthLoginAdmin binds the session to the panel's admin account. Every admin
// identity maps to the single first user — the panel has no per-admin data — and
// an admin is also provisioned a client so they get their own connection.
func (a *IndexController) oauthLoginAdmin(c *gin.Context, id *oauth.Identity, cfg config.OAuthConfig, remoteIP, timeStr string) {
	user, err := a.userService.GetFirstUser()
	if err != nil || user == nil {
		logger.Warning("oauth: unable to load admin user:", err)
		a.redirectLoginError(c)
		return
	}
	if err := session.SetLoginUser(c, user); err != nil {
		logger.Warning("oauth: unable to save session:", err)
		a.redirectLoginError(c)
		return
	}
	if err := session.SetLoginRole(c, session.RoleAdmin); err != nil {
		logger.Warning("oauth: unable to save role:", err)
	}
	// Best-effort: provision the admin's own client but never block panel access.
	if len(cfg.UserInboundRemarks) > 0 {
		if _, needRestart, provErr := a.provisionOauthClient(cfg, id); provErr != nil {
			logger.Warning("oauth: admin client provisioning skipped:", provErr)
		} else if needRestart {
			a.xrayService.SetToNeedRestart()
		}
	}
	logger.Infof("oauth admin %q logged in, IP: %s", id.Username, remoteIP)
	a.tgbot.UserLoginNotify(oauthLoginAttempt(id, remoteIP, timeStr, tgbot.LoginSuccess))
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"panel/")
}

// cabinet serves the self-service cabinet SPA shell. The page is a thin client;
// its /cabinet/data feed is what enforces the user-tier session.
func (a *IndexController) cabinet(c *gin.Context) {
	serveDistPage(c, "cabinet.html")
}

// cabinetData returns the self-service caller's connection: their share links
// and traffic, keyed by the subId bound to the session. User-tier only.
func (a *IndexController) cabinetData(c *gin.Context) {
	subID := session.GetLoginClientSubID(c)
	if subID == "" {
		pureJsonMsg(c, http.StatusUnauthorized, false, I18nWeb(c, "pages.login.loginAgain"))
		return
	}
	remark, _ := a.settingService.GetRemarkTemplate()
	svc := sub.NewSubService(remark)
	// Use the sub server's own host resolution: the raw Host header carries the
	// panel port, which would turn a wildcard inbound address into a malformed
	// "[host:port]:443" link that clients (and new URL()) reject.
	_, host, _, _ := svc.ResolveRequest(c)
	links, _, _, traffic, err := svc.GetSubs(subID, host)
	if err != nil {
		jsonMsg(c, "", err)
		return
	}
	// The links are credentials: keep them out of browser and proxy caches.
	c.Header("Cache-Control", "no-store")
	jsonObj(c, gin.H{
		"subId":      subID,
		"subUrl":     a.buildSubURL(host, subID),
		"links":      links,
		"up":         traffic.Up,
		"down":       traffic.Down,
		"total":      traffic.Total,
		"expiryTime": traffic.ExpiryTime,
		"enable":     traffic.Enable,
	}, nil)
}

// buildSubURL assembles the caller's subscription URL the same way the sub
// server does: a configured subURI wins, else the request-derived base + path.
func (a *IndexController) buildSubURL(host, subID string) string {
	base := a.settingService.BuildSubURIBase(host)
	subPath, _ := a.settingService.GetSubPath()
	configuredURI, _ := a.settingService.GetSubURI()
	prefix := configuredURI
	if prefix == "" {
		prefix = base + subPath
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix + subID
}

// oauthLoginUser provisions the caller's self-service client on first login and
// binds the session to its subId, then sends them to their cabinet.
func (a *IndexController) oauthLoginUser(c *gin.Context, id *oauth.Identity, cfg config.OAuthConfig, remoteIP, timeStr string) {
	subID, needRestart, err := a.provisionOauthClient(cfg, id)
	if err != nil {
		logger.Warning("oauth: user provisioning failed:", err)
		a.redirectLoginError(c)
		return
	}
	if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	if err := session.SetLoginClient(c, subID); err != nil {
		logger.Warning("oauth: unable to save session:", err)
		a.redirectLoginError(c)
		return
	}
	logger.Infof("oauth user %q logged in, IP: %s", id.Username, remoteIP)
	a.tgbot.UserLoginNotify(oauthLoginAttempt(id, remoteIP, timeStr, tgbot.LoginSuccess))
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"cabinet/")
}

// provisionOauthClient ensures the caller has a client on the configured
// inbound(s), keyed by their email (falling back to username), and returns its subId.
func (a *IndexController) provisionOauthClient(cfg config.OAuthConfig, id *oauth.Identity) (string, bool, error) {
	email := id.Email
	if email == "" {
		email = id.Username
	}
	var inboundSvc service.InboundService
	var clientSvc service.ClientService
	var prov service.OAuthProvisionService
	return prov.EnsureUserClient(&inboundSvc, &clientSvc, cfg, id.Subject, email)
}

// resolveRole maps a verified identity to a login tier via its group claims.
// An unmatched identity is denied.
func resolveRole(id *oauth.Identity, cfg config.OAuthConfig) string {
	if cfg.AdminGroup != "" && id.InGroup(cfg.AdminGroup) {
		return session.RoleAdmin
	}
	if len(cfg.UserGroups) > 0 && id.InAnyGroup(cfg.UserGroups) {
		return session.RoleUser
	}
	return ""
}

// oauthProviderFor returns the OIDC provider for the effective config, running
// discovery only when the identity-provider settings change, so editing them in
// the UI takes effect without a restart. The redirect URL stays out of the cache
// key: when it is derived from the request, a client sending made-up Host headers
// could otherwise force a discovery round-trip per request. Discovery also runs
// outside the lock, so a stalled provider cannot queue up every other login.
func (a *IndexController) oauthProviderFor(c *gin.Context) (*oauth.Provider, error) {
	cfg := a.settingService.GetEffectiveOAuthConfig()
	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		redirectURL = deriveRedirectURL(c)
	}
	sig := strings.Join([]string{
		cfg.Issuer, cfg.ClientID, cfg.ClientSecret, strings.Join(cfg.Scopes, ","), cfg.UsernameClaim, cfg.GroupsClaim,
	}, "\x00")

	a.oauthMu.Lock()
	provider := a.oauthProvider
	cached := provider != nil && a.oauthSig == sig
	a.oauthMu.Unlock()
	if cached {
		return provider.WithRedirectURL(redirectURL), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), oauthDiscoveryTimeout)
	defer cancel()
	provider, err := oauth.NewProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	a.oauthMu.Lock()
	a.oauthProvider = provider
	a.oauthSig = sig
	a.oauthMu.Unlock()
	return provider.WithRedirectURL(redirectURL), nil
}

func deriveRedirectURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	base := c.GetString("base_path")
	return scheme + "://" + c.Request.Host + base + "oauth/callback"
}

func (a *IndexController) redirectLoginError(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"?oauth_error=1")
}
