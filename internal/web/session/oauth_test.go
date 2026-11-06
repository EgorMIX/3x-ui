package session

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func newSessionRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sessions.Sessions(sessionCookieName, cookie.NewStore([]byte("01234567890123456789012345678901"))))
	return r
}

func TestGetLoginRoleDefaultsToAdmin(t *testing.T) {
	r := newSessionRouter()
	r.GET("/", func(c *gin.Context) {
		if got := GetLoginRole(c); got != RoleAdmin {
			t.Fatalf("GetLoginRole with nothing set = %q, want %q", got, RoleAdmin)
		}
		c.Status(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSetGetLoginRole(t *testing.T) {
	r := newSessionRouter()
	r.GET("/", func(c *gin.Context) {
		if err := SetLoginRole(c, RoleUser); err != nil {
			t.Fatal(err)
		}
		if got := GetLoginRole(c); got != RoleUser {
			t.Fatalf("GetLoginRole = %q, want %q", got, RoleUser)
		}
		c.Status(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestOAuthFlowRoundTripAndClear(t *testing.T) {
	r := newSessionRouter()
	r.GET("/", func(c *gin.Context) {
		if err := SetOAuthFlow(c, "st", "no", "vf"); err != nil {
			t.Fatal(err)
		}
		s, n, v := GetOAuthFlow(c)
		if s != "st" || n != "no" || v != "vf" {
			t.Fatalf("GetOAuthFlow = %q/%q/%q, want st/no/vf", s, n, v)
		}
		if err := ClearOAuthFlow(c); err != nil {
			t.Fatal(err)
		}
		s, n, v = GetOAuthFlow(c)
		if s != "" || n != "" || v != "" {
			t.Fatalf("after clear GetOAuthFlow = %q/%q/%q, want empty", s, n, v)
		}
		c.Status(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSetLoginClientDropsPriorSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sessions.Sessions("3x-ui", cookie.NewStore([]byte("test-secret"))))
	r.GET("/", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(loginUserKey, 1)
		s.Set("leftover", "x")
		if err := SetLoginClient(c, "sub-1"); err != nil {
			t.Fatalf("SetLoginClient: %v", err)
		}
		if s.Get(loginUserKey) != nil || s.Get("leftover") != nil {
			t.Fatal("a self-service login must not keep the previous session")
		}
		if got := GetLoginClientSubID(c); got != "sub-1" {
			t.Fatalf("subId = %q", got)
		}
		if got := GetLoginRole(c); got != RoleUser {
			t.Fatalf("role = %q", got)
		}
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}
