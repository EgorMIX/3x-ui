package service

import (
	"fmt"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func seedInbound(t *testing.T, remark string, port int) *model.Inbound {
	t.Helper()
	ib := &model.Inbound{
		Tag:      fmt.Sprintf("%s-%d-tag", remark, port),
		Remark:   remark,
		Enable:   true,
		Port:     port,
		Protocol: model.VLESS,
		Settings: `{"clients":[]}`,
	}
	if err := database.GetDB().Create(ib).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	return ib
}

func reloadClients(t *testing.T, inboundID int) []model.Client {
	t.Helper()
	var ib model.Inbound
	if err := database.GetDB().First(&ib, inboundID).Error; err != nil {
		t.Fatalf("reload inbound: %v", err)
	}
	clients, err := (&InboundService{}).GetClients(&ib)
	if err != nil {
		t.Fatalf("GetClients: %v", err)
	}
	return clients
}

func TestEnsureUserClient_CreatesThenReuses(t *testing.T) {
	setupBulkDB(t)
	ib := seedInbound(t, "oauth-users", 24101)
	prov := &OAuthProvisionService{}
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"oauth-users"}, UserTotalGB: 10, UserExpiryDays: 30, UserLimitIP: 2}

	sub1, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "sub-alice@corp", "alice@corp")
	if err != nil {
		t.Fatalf("first EnsureUserClient: %v", err)
	}
	if sub1 == "" {
		t.Fatal("first login returned empty subId")
	}

	clients := reloadClients(t, ib.Id)
	if len(clients) != 1 {
		t.Fatalf("client count after first login = %d, want 1", len(clients))
	}
	got := clients[0]
	if got.Email != "alice@corp" || got.SubID != sub1 {
		t.Fatalf("client = %s/%s, want alice@corp/%s", got.Email, got.SubID, sub1)
	}
	if got.TotalGB != 10*1024*1024*1024 {
		t.Errorf("TotalGB = %d, want 10GiB", got.TotalGB)
	}
	if got.LimitIP != 2 {
		t.Errorf("LimitIP = %d, want 2", got.LimitIP)
	}
	if got.ExpiryTime == 0 {
		t.Error("ExpiryTime = 0, want a future expiry from 30 days")
	}
	if !got.Enable {
		t.Error("client is not enabled")
	}

	sub2, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "sub-alice@corp", "alice@corp")
	if err != nil {
		t.Fatalf("second EnsureUserClient: %v", err)
	}
	if sub2 != sub1 {
		t.Fatalf("second login subId = %q, want stable %q", sub2, sub1)
	}
	if clients := reloadClients(t, ib.Id); len(clients) != 1 {
		t.Fatalf("client count after second login = %d, want 1 (idempotent)", len(clients))
	}
}

func TestEnsureUserClient_AttachesToEveryMatchingRemark(t *testing.T) {
	setupBulkDB(t)
	ib1 := seedInbound(t, "vpn", 24201)
	ib2 := seedInbound(t, "vpn", 24202)
	seedInbound(t, "other", 24203)
	prov := &OAuthProvisionService{}
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"vpn"}}

	sub, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "sub-bob@corp", "bob@corp")
	if err != nil {
		t.Fatalf("EnsureUserClient: %v", err)
	}
	for _, ib := range []*model.Inbound{ib1, ib2} {
		clients := reloadClients(t, ib.Id)
		if len(clients) != 1 || clients[0].Email != "bob@corp" || clients[0].SubID != sub {
			t.Fatalf("inbound %q clients = %+v, want bob@corp/%s", ib.Remark, clients, sub)
		}
	}
}

func TestEnsureUserClient_AttachesToInboundAddedLater(t *testing.T) {
	setupBulkDB(t)
	ib1 := seedInbound(t, "vpn", 24301)
	prov := &OAuthProvisionService{}
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"vpn"}}

	sub1, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "sub-carol@corp", "carol@corp")
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	if c := reloadClients(t, ib1.Id); len(c) != 1 {
		t.Fatalf("inbound1 clients after first login = %d, want 1", len(c))
	}

	ib2 := seedInbound(t, "vpn", 24302)
	sub2, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "sub-carol@corp", "carol@corp")
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if sub2 != sub1 {
		t.Fatalf("subId changed on re-login: %q -> %q", sub1, sub2)
	}
	c1 := reloadClients(t, ib1.Id)
	c2 := reloadClients(t, ib2.Id)
	if len(c1) != 1 {
		t.Fatalf("inbound1 clients = %d, want 1 (no duplicate)", len(c1))
	}
	if len(c2) != 1 || c2[0].Email != "carol@corp" || c2[0].SubID != sub1 {
		t.Fatalf("newly added inbound2 should carry the same client: %+v", c2)
	}
}

func TestReconcileAll_AttachesToMissingInboundsIdempotently(t *testing.T) {
	setupBulkDB(t)
	ib1 := seedInbound(t, "vpn", 24401)
	ibOther := seedInbound(t, "other", 24402)
	prov := &OAuthProvisionService{}
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"vpn"}}

	sub, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "sub-dave@corp", "dave@corp")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	ib2 := seedInbound(t, "vpn", 24403)

	attached, _, err := prov.ReconcileAll(inboundSvc, clientSvc, cfg)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if attached != 1 {
		t.Fatalf("attached = %d, want 1", attached)
	}
	if c := reloadClients(t, ib2.Id); len(c) != 1 || c[0].Email != "dave@corp" || c[0].SubID != sub {
		t.Fatalf("new inbound should carry the client: %+v", c)
	}
	if c := reloadClients(t, ib1.Id); len(c) != 1 {
		t.Fatalf("original inbound clients = %d, want 1 (no duplicate)", len(c))
	}
	if c := reloadClients(t, ibOther.Id); len(c) != 0 {
		t.Fatalf("non-target inbound must stay untouched, got %+v", c)
	}

	attached2, _, err := prov.ReconcileAll(inboundSvc, clientSvc, cfg)
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if attached2 != 0 {
		t.Fatalf("steady-state reconcile attached = %d, want 0", attached2)
	}
}

func TestReconcileAll_RestoresAfterOnlyInboundReadded(t *testing.T) {
	setupBulkDB(t)
	a := seedInbound(t, "vpn", 25301)
	prov := &OAuthProvisionService{}
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"vpn"}}

	sub, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "sub-solo@corp", "solo@corp")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	var rec model.ClientRecord
	if err := database.GetDB().Where("email = ?", "solo@corp").First(&rec).Error; err != nil {
		t.Fatalf("load record: %v", err)
	}
	if !rec.OauthManaged {
		t.Fatal("provisioned client should be flagged oauth_managed")
	}

	if _, err := inboundSvc.DelInbound(a.Id); err != nil {
		t.Fatalf("del inbound: %v", err)
	}

	a2 := seedInbound(t, "vpn", 25302)
	attached, _, err := prov.ReconcileAll(inboundSvc, clientSvc, cfg)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if attached != 1 {
		t.Fatalf("attached = %d, want 1 (roster restored from the persisted record)", attached)
	}
	clients := reloadClients(t, a2.Id)
	if len(clients) != 1 || clients[0].Email != "solo@corp" || clients[0].SubID != sub {
		t.Fatalf("re-added inbound should carry the same client: %+v", clients)
	}
}

func TestEnsureUserClient_AppliesFlow(t *testing.T) {
	setupBulkDB(t)
	reality := `{"network":"tcp","security":"reality","realitySettings":{"serverNames":["r.example.com"],"shortIds":["ab"],"settings":{"publicKey":"PBK","fingerprint":"chrome"}}}`
	ib := &model.Inbound{
		Tag: "vpn-tag", Remark: "vpn", Enable: true, Port: 24701, Protocol: model.VLESS,
		Settings: `{"clients":[],"decryption":"none"}`, StreamSettings: reality,
	}
	if err := database.GetDB().Create(ib).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	prov := &OAuthProvisionService{}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"vpn"}, UserFlow: "xtls-rprx-vision"}

	if _, _, err := prov.EnsureUserClient(&InboundService{}, &ClientService{}, cfg, "sub-flow@corp", "flow@corp"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	clients := reloadClients(t, ib.Id)
	if len(clients) != 1 || clients[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("client flow = %+v, want xtls-rprx-vision", clients)
	}
}

func TestEnsureUserClient_Errors(t *testing.T) {
	setupBulkDB(t)
	seedInbound(t, "oauth-users", 24101)
	prov := &OAuthProvisionService{}
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}

	t.Run("empty email", func(t *testing.T) {
		if _, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, config.OAuthConfig{UserInboundRemarks: []string{"oauth-users"}}, "subject", ""); err == nil {
			t.Fatal("want error for empty email")
		}
	})
	t.Run("no inbound remark configured", func(t *testing.T) {
		if _, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, config.OAuthConfig{}, "sub-a@b", "a@b"); err == nil {
			t.Fatal("want error for missing inbound remark")
		}
	})
	t.Run("inbound remark not found", func(t *testing.T) {
		if _, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, config.OAuthConfig{UserInboundRemarks: []string{"nope"}}, "sub-a@b", "a@b"); err == nil {
			t.Fatal("want error for unknown inbound remark")
		}
	})
}

func TestEnsureUserClient_EmailChangeKeepsClient(t *testing.T) {
	setupBulkDB(t)
	ib := seedInbound(t, "oauth-users", 24201)
	prov := &OAuthProvisionService{}
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"oauth-users"}}

	sub1, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "subject-1", "old@corp")
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	sub2, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "subject-1", "new@corp")
	if err != nil {
		t.Fatalf("login after email change: %v", err)
	}
	if sub1 != sub2 {
		t.Fatalf("email change must keep the client: %q != %q", sub1, sub2)
	}
	if got := len(reloadClients(t, ib.Id)); got != 1 {
		t.Fatalf("email change must not add a client, got %d", got)
	}
}

func TestEnsureUserClient_EmailCannotHijackClient(t *testing.T) {
	setupBulkDB(t)
	seedInbound(t, "oauth-users", 24202)
	prov := &OAuthProvisionService{}
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"oauth-users"}}

	if _, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "victim", "victim@corp"); err != nil {
		t.Fatalf("victim login: %v", err)
	}
	subID, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "attacker", "victim@corp")
	if err == nil {
		t.Fatalf("another subject claiming the email must be refused, got subId %q", subID)
	}
}

func TestEnsureUserClient_RefusesManuallyCreatedClient(t *testing.T) {
	setupBulkDB(t)
	ib := seedInbound(t, "oauth-users", 24203)
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}
	if _, err := clientSvc.Create(inboundSvc, &ClientCreatePayload{
		Client:     model.Client{Email: "manual@corp", Enable: true, SubID: "manual-sub"},
		InboundIds: []int{ib.Id},
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"oauth-users"}}
	subID, _, err := (&OAuthProvisionService{}).EnsureUserClient(inboundSvc, clientSvc, cfg, "someone", "manual@corp")
	if err == nil {
		t.Fatalf("a client outside the SSO pool must not be adopted, got subId %q", subID)
	}
}

func TestReconcileAll_PreservesClientFields(t *testing.T) {
	setupBulkDB(t)
	first := seedInbound(t, "oauth-users", 24204)
	prov := &OAuthProvisionService{}
	inboundSvc := &InboundService{}
	clientSvc := &ClientService{}
	cfg := config.OAuthConfig{UserInboundRemarks: []string{"oauth-users"}}

	if _, _, err := prov.EnsureUserClient(inboundSvc, clientSvc, cfg, "subject-2", "keep@corp"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := database.GetDB().Model(&model.ClientRecord{}).Where("email = ?", "keep@corp").
		Updates(map[string]any{"limit_hwid": 3, "comment": "vip"}).Error; err != nil {
		t.Fatalf("seed fields: %v", err)
	}
	second := seedInbound(t, "oauth-users", 24205)
	attached, _, err := prov.ReconcileAll(inboundSvc, clientSvc, cfg)
	if err != nil || attached != 1 {
		t.Fatalf("reconcile: attached=%d err=%v", attached, err)
	}
	if got := len(reloadClients(t, second.Id)); got != 1 {
		t.Fatalf("client not attached to inbound %d (first=%d): %d", second.Id, first.Id, got)
	}
	var rec model.ClientRecord
	if err := database.GetDB().Where("email = ?", "keep@corp").First(&rec).Error; err != nil {
		t.Fatalf("reload record: %v", err)
	}
	if rec.LimitHwid != 3 || rec.Comment != "vip" {
		t.Fatalf("reconcile must not reset the client, got limitHwid=%d comment=%q", rec.LimitHwid, rec.Comment)
	}
	if !rec.OauthManaged || rec.OauthSubject != "subject-2" {
		t.Fatalf("binding lost: managed=%v subject=%q", rec.OauthManaged, rec.OauthSubject)
	}
}

func TestBindCreatedOauthRecordSkipsAnotherClient(t *testing.T) {
	setupBulkDB(t)
	other := &model.ClientRecord{Email: "shared@corp", SubID: "other-sub", OauthSubject: "owner"}
	if err := database.GetDB().Create(other).Error; err != nil {
		t.Fatalf("seed client: %v", err)
	}
	if err := bindCreatedOauthRecord("shared@corp", "lost-race-sub", "intruder"); err == nil {
		t.Fatal("a create that lost the race must not report a bound client")
	}
	var got model.ClientRecord
	if err := database.GetDB().First(&got, other.Id).Error; err != nil {
		t.Fatalf("reload client: %v", err)
	}
	if got.OauthSubject != "owner" || got.OauthManaged {
		t.Fatalf("client changed: subject=%q managed=%v", got.OauthSubject, got.OauthManaged)
	}
}

func TestClaimOauthRecordHasOneWinner(t *testing.T) {
	setupBulkDB(t)
	rec := &model.ClientRecord{Email: "legacy@corp", SubID: "legacy-sub", OauthManaged: true}
	if err := database.GetDB().Create(rec).Error; err != nil {
		t.Fatalf("seed client: %v", err)
	}
	if err := claimOauthRecord("legacy@corp", "first"); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := claimOauthRecord("legacy@corp", "second"); err == nil {
		t.Fatal("a claimed client must not move to a second subject")
	}
	var got model.ClientRecord
	if err := database.GetDB().First(&got, rec.Id).Error; err != nil {
		t.Fatalf("reload client: %v", err)
	}
	if got.OauthSubject != "first" {
		t.Fatalf("subject = %q, want first", got.OauthSubject)
	}
}
