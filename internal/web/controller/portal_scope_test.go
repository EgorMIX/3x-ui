package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/crypto"
)

const portalTestToken = "portal-token"

// portalRoutes is written out here on purpose, so a change to portalScopeAllow
// has to be repeated by hand instead of passing unnoticed.
var portalRoutes = []struct{ method, pattern, path string }{
	{http.MethodGet, "/inbounds/options", "/inbounds/options"},
	{http.MethodGet, "/clients/list/paged", "/clients/list/paged"},
	{http.MethodGet, "/clients/get/:email", "/clients/get/a@example.com"},
	{http.MethodGet, "/clients/get/subId/:subId", "/clients/get/subId/sub1"},
	{http.MethodGet, "/clients/traffic/:email", "/clients/traffic/a@example.com"},
	{http.MethodGet, "/clients/subLinks/:subId", "/clients/subLinks/sub1"},
	{http.MethodPost, "/clients/add", "/clients/add"},
	{http.MethodPost, "/clients/update/:email", "/clients/update/a@example.com"},
	{http.MethodPost, "/clients/:email/attach", "/clients/a@example.com/attach"},
	{http.MethodPost, "/clients/:email/detach", "/clients/a@example.com/detach"},
	{http.MethodPost, "/clients/hwids/:email", "/clients/hwids/a@example.com"},
	{http.MethodDelete, "/clients/hwids/:email/:id", "/clients/hwids/a@example.com/1"},
}

// newPortalScopeEngine registers the real client and inbound routes behind the
// real scope check. The handlers never run: a sentinel stops every request that
// passes the check. Routes outside those two controllers use stubs, because the
// scope check only reads the route pattern.
func newPortalScopeEngine(t *testing.T) *gin.Engine {
	t.Helper()
	engine, a := newAPIAuthTestEngine(t)
	row := &model.ApiToken{Name: "portal", Token: crypto.HashTokenSHA256(portalTestToken), Enabled: true, Scope: model.ApiScopePortal}
	if err := database.GetDB().Create(row).Error; err != nil {
		t.Fatalf("seed portal token: %v", err)
	}
	api := engine.Group("/base/panel/api", a.checkAPIAuth, a.enforceTokenScope, func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusOK, gin.H{"reached": true})
	})
	NewClientController(api.Group("/clients"))
	NewInboundController(api.Group("/inbounds"))
	stub := func(c *gin.Context) {}
	api.POST("/setting/all", stub)
	api.POST("/server/restartXrayService", stub)
	api.GET("/xray/", stub)
	api.GET("/nodes/list", stub)
	return engine
}

func portalRequest(engine *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/base/panel/api"+path, nil)
	req.Header.Set("Authorization", "Bearer "+portalTestToken)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func TestPortalScopeAllowsItsRoutes(t *testing.T) {
	engine := newPortalScopeEngine(t)
	for _, r := range portalRoutes {
		t.Run(r.method+" "+r.pattern, func(t *testing.T) {
			if w := portalRequest(engine, r.method, r.path); w.Code != http.StatusOK || w.Body.String() != `{"reached":true}` {
				t.Fatalf("response = %d %s, want the request to pass the scope check", w.Code, w.Body.String())
			}
		})
	}
}

func TestPortalScopeRoutesExist(t *testing.T) {
	engine := newPortalScopeEngine(t)
	registered := map[string]bool{}
	for _, route := range engine.Routes() {
		registered[route.Method+" "+route.Path] = true
	}
	allowed := 0
	for _, r := range portalRoutes {
		if !registered[r.method+" /base/panel/api"+r.pattern] {
			t.Errorf("%s %s is allowed for portal tokens but no longer registered", r.method, r.pattern)
		}
		if !scopeAllows(portalScopeAllow, r.pattern, r.method) {
			t.Errorf("%s %s is missing from portalScopeAllow", r.method, r.pattern)
		}
	}
	for _, methods := range portalScopeAllow {
		allowed += len(methods)
	}
	if allowed != len(portalRoutes) {
		t.Fatalf("portalScopeAllow has %d route/method pairs, want %d", allowed, len(portalRoutes))
	}
}

func TestPortalScopeRefusesOtherMethods(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, r := range portalRoutes {
		for _, method := range methods {
			if method != r.method && scopeAllows(portalScopeAllow, r.pattern, method) {
				t.Errorf("%s %s must be refused", method, r.pattern)
			}
		}
	}
	// DELETE on the device list clears every device; the portal removes one at a time.
	if w := portalRequest(newPortalScopeEngine(t), http.MethodDelete, "/clients/hwids/a@example.com"); w.Code != http.StatusForbidden {
		t.Fatalf("clear all devices = %d, want 403", w.Code)
	}
}

func TestPortalScopeRefusesEverythingElse(t *testing.T) {
	engine := newPortalScopeEngine(t)
	for _, r := range []struct{ method, path string }{
		{http.MethodPost, "/clients/del/a@example.com"},
		{http.MethodPost, "/clients/delOrphans"},
		{http.MethodPost, "/clients/delDepleted"},
		{http.MethodPost, "/clients/resetAllTraffics"},
		{http.MethodPost, "/clients/bulkDel"},
		{http.MethodPost, "/clients/bulkCreate"},
		{http.MethodPost, "/clients/bulkAttach"},
		{http.MethodPost, "/clients/import"},
		{http.MethodGet, "/clients/export"},
		{http.MethodGet, "/clients/list"},
		{http.MethodGet, "/clients/links/a@example.com"},
		{http.MethodGet, "/clients/get/tgId/1"},
		{http.MethodPost, "/inbounds/add"},
		{http.MethodPost, "/inbounds/del/1"},
		{http.MethodPost, "/inbounds/update/1"},
		{http.MethodPost, "/inbounds/1/delAllClients"},
		{http.MethodGet, "/inbounds/list"},
		{http.MethodPost, "/setting/all"},
		{http.MethodPost, "/server/restartXrayService"},
		{http.MethodGet, "/xray/"},
		{http.MethodGet, "/nodes/list"},
	} {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			if w := portalRequest(engine, r.method, r.path); w.Code != http.StatusForbidden {
				t.Fatalf("response = %d %s, want 403", w.Code, w.Body.String())
			}
		})
	}
}

// getInboundOptions reads the user from the session, and API tokens have none
// until checkAPIAuth attaches the first user. Run the real handler to cover that.
func TestPortalScopeReadsInboundOptions(t *testing.T) {
	engine, a := newAPIAuthTestEngine(t)
	row := &model.ApiToken{Name: "portal", Token: crypto.HashTokenSHA256(portalTestToken), Enabled: true, Scope: model.ApiScopePortal}
	if err := database.GetDB().Create(row).Error; err != nil {
		t.Fatalf("seed portal token: %v", err)
	}
	NewInboundController(engine.Group("/base/panel/api/inbounds", a.checkAPIAuth, a.enforceTokenScope))
	w := portalRequest(engine, http.MethodGet, "/inbounds/options")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("response = %d %s, want a successful options list", w.Code, w.Body.String())
	}
}

func TestPortalScopeIsNotANodeIdentity(t *testing.T) {
	if model.IsNodeSyncApiScope(model.ApiScopePortal) {
		t.Fatal("portal tokens must keep ordinary inbound validation")
	}
	if !model.IsKnownApiScope(model.ApiScopePortal) {
		t.Fatal("portal must be a known scope")
	}
}

func TestPortalClientFieldError(t *testing.T) {
	stored := &model.ClientRecord{ForwardedPorts: "5000", Reverse: `{"tag":"own"}`}
	for _, tt := range []struct {
		name    string
		current *model.ClientRecord
		client  model.Client
		wantErr string
	}{
		{name: "plain new client"},
		{name: "new client opening ports", client: model.Client{ForwardedPorts: "8080"}, wantErr: "forwardedPorts"},
		{name: "new client naming an outbound", client: model.Client{Reverse: &model.ClientReverse{Tag: "direct"}}, wantErr: "reverse"},
		{name: "stored values sent back", current: stored, client: model.Client{ForwardedPorts: " 5000 ", Reverse: &model.ClientReverse{Tag: "own"}}},
		{name: "omitted values", current: stored},
		{name: "changed ports", current: stored, client: model.Client{ForwardedPorts: "5000,5001"}, wantErr: "forwardedPorts"},
		{name: "changed reverse", current: stored, client: model.Client{Reverse: &model.ClientReverse{Tag: "direct"}}, wantErr: "reverse"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := portalClientFieldError(tt.current, tt.client)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected refusal: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want a refusal naming %s", err, tt.wantErr)
			}
		})
	}
}

func TestPortalTokenCannotSetHostFields(t *testing.T) {
	engine, a := newAPIAuthTestEngine(t)
	for name, scope := range map[string]string{portalTestToken: model.ApiScopePortal, "admin-token": model.ApiScopeAdmin} {
		row := &model.ApiToken{Name: name, Token: crypto.HashTokenSHA256(name), Enabled: true, Scope: scope}
		if err := database.GetDB().Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if err := database.GetDB().Create(&model.ClientRecord{Email: "a@example.com", SubID: "sub1", UUID: "uuid-1"}).Error; err != nil {
		t.Fatalf("seed client: %v", err)
	}
	NewClientController(engine.Group("/base/panel/api/clients", a.checkAPIAuth, a.enforceTokenScope))
	post := func(token, path, body string) string {
		req := httptest.NewRequest(http.MethodPost, "/base/panel/api"+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w.Body.String()
	}
	const update = `{"email":"a@example.com","forwardedPorts":"8080"}`
	const updateReverse = `{"email":"a@example.com","reverse":{"tag":"direct"}}`
	const add = `{"client":{"email":"b@example.com","forwardedPorts":"8080"},"inboundIds":[1]}`
	for _, tt := range []struct{ path, body, want string }{
		{"/clients/update/a@example.com", update, "forwardedPorts"},
		{"/clients/update/a@example.com", updateReverse, "reverse"},
		{"/clients/add", add, "forwardedPorts"},
	} {
		if got := post(portalTestToken, tt.path, tt.body); !strings.Contains(got, "portal tokens cannot change "+tt.want) {
			t.Errorf("portal %s = %s, want a refusal", tt.path, got)
		}
		if got := post("admin-token", tt.path, tt.body); strings.Contains(got, "portal tokens cannot") {
			t.Errorf("admin %s = %s, must not be refused by the portal check", tt.path, got)
		}
	}
}
