package service

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/common"
)

// OAuthProvisionService turns a verified OIDC identity into a usable VPN
// connection: it guarantees a Client exists on every inbound whose remark is
// listed in the OIDC settings.
type OAuthProvisionService struct{}

// EnsureUserClient returns the subId of the caller's client, guaranteeing it is
// attached to every matching inbound.
//
// The client is owned by the immutable OIDC subject, never by the email: the
// email is user-editable on most providers, so trusting it alone would let
// someone rename themselves into another person's connection. A subject keeps
// its client across email changes, and a client the panel did not provision
// for SSO is never adopted, even when its email matches.
func (s *OAuthProvisionService) EnsureUserClient(inboundSvc *InboundService, clientSvc *ClientService, cfg config.OAuthConfig, subject, email string) (string, bool, error) {
	if subject == "" {
		return "", false, common.NewError("oauth: cannot provision client without a subject")
	}
	if email == "" {
		return "", false, common.NewError("oauth: cannot provision client without an email")
	}
	if len(cfg.UserInboundRemarks) == 0 {
		return "", false, common.NewError("oauth: user inbound remark is not configured")
	}
	rec, err := resolveOauthRecord(subject, email)
	if err != nil {
		return "", false, err
	}
	targets, err := oauthTargetIDs(inboundSvc, cfg.UserInboundRemarks)
	if err != nil {
		return "", false, err
	}

	if rec == nil {
		if len(targets) == 0 {
			return "", false, common.NewError("oauth: no inbound matches remark(s):", strings.Join(cfg.UserInboundRemarks, ", "))
		}
		client := buildOAuthClient(email, cfg)
		needRestart, createErr := clientSvc.Create(inboundSvc, &ClientCreatePayload{Client: client, InboundIds: targets})
		// A partial failure can leave the record behind; bind it anyway so the
		// next login finishes the attach instead of refusing it as foreign.
		bindErr := bindCreatedOauthRecord(email, client.SubID, subject)
		if createErr != nil {
			return "", needRestart, createErr
		}
		if bindErr != nil {
			return "", needRestart, bindErr
		}
		return client.SubID, needRestart, nil
	}

	missing, err := missingOauthTargets(clientSvc, rec, targets)
	if err != nil {
		return "", false, err
	}
	if len(missing) == 0 {
		return rec.SubID, false, nil
	}
	needRestart, err := clientSvc.Attach(inboundSvc, rec.Id, missing)
	if err != nil {
		// The client still works on the inbounds it already has: keep the login
		// and let the periodic job retry the attach.
		logger.Warningf("oauth: attach %s to %d inbound(s) failed: %v", rec.Email, len(missing), err)
	}
	return rec.SubID, needRestart, nil
}

// ReconcileAll re-attaches every OIDC-managed client (persisted in the clients
// table) to all inbounds matching the configured remarks. Because the roster
// comes from the DB rather than the current inbound membership, an inbound
// deleted and re-added, even the only one a user was on, gets the users back. It
// only attaches (never deletes/disables); Attach reuses the stored identity, so
// subId, credentials, limits and traffic are preserved. Returns how many clients
// were attached and whether xray needs a restart.
func (s *OAuthProvisionService) ReconcileAll(inboundSvc *InboundService, clientSvc *ClientService, cfg config.OAuthConfig) (int, bool, error) {
	if len(cfg.UserInboundRemarks) == 0 {
		return 0, false, nil
	}
	targets, err := oauthTargetIDs(inboundSvc, cfg.UserInboundRemarks)
	if err != nil {
		return 0, false, err
	}
	if len(targets) == 0 {
		return 0, false, nil
	}

	var records []model.ClientRecord
	if err := database.GetDB().Where("oauth_managed = ?", true).Find(&records).Error; err != nil {
		return 0, false, err
	}

	attached := 0
	needRestart := false
	for i := range records {
		rec := &records[i]
		missing, err := missingOauthTargets(clientSvc, rec, targets)
		if err != nil {
			logger.Warningf("oauth sync: read inbounds of %s failed: %v", rec.Email, err)
			continue
		}
		if len(missing) == 0 {
			continue
		}
		nr, err := clientSvc.Attach(inboundSvc, rec.Id, missing)
		if err != nil {
			logger.Warningf("oauth sync: attach %s to %d inbound(s) failed: %v", rec.Email, len(missing), err)
			continue
		}
		attached++
		needRestart = needRestart || nr
	}
	return attached, needRestart, nil
}

// resolveOauthRecord finds the client owned by subject. A nil record with a nil
// error means the identity has no client yet. An email already held by a client
// outside the SSO pool, or bound to another subject, is refused.
func resolveOauthRecord(subject, email string) (*model.ClientRecord, error) {
	db := database.GetDB()
	rec := &model.ClientRecord{}
	err := db.Where("oauth_subject = ?", subject).First(rec).Error
	if err == nil {
		return rec, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	rec = &model.ClientRecord{}
	err = db.Where("email = ?", email).First(rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !rec.OauthManaged || rec.OauthSubject != "" {
		return nil, common.NewError("oauth: refusing to take over existing client", email)
	}
	// Provisioned before subjects were recorded: the first login claims it.
	if err := claimOauthRecord(email, subject); err != nil {
		return nil, err
	}
	rec.OauthSubject = subject
	return rec, nil
}

// bindCreatedOauthRecord adds the client this login just created to the OIDC pool
// and records its owner. Matching the freshly minted subId as well as the email
// keeps a create that lost a race from binding the other caller's client. The
// reconcile job relies on the flag to restore clients onto re-added inbounds.
func bindCreatedOauthRecord(email, subID, subject string) error {
	return requireOauthBind(email, database.GetDB().Model(&model.ClientRecord{}).
		Where("email = ? AND sub_id = ?", email, subID).
		Updates(map[string]any{"oauth_managed": true, "oauth_subject": subject}))
}

// claimOauthRecord gives an unowned SSO client to its first subject. Two logins
// racing for the same record cannot both win it.
func claimOauthRecord(email, subject string) error {
	return requireOauthBind(email, database.GetDB().Model(&model.ClientRecord{}).
		Where("email = ? AND oauth_managed = ? AND oauth_subject = ?", email, true, "").
		Update("oauth_subject", subject))
}

func requireOauthBind(email string, res *gorm.DB) error {
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return common.NewError("oauth: client was not bound:", email)
	}
	return nil
}

// oauthTargetIDs lists the inbounds whose remark is one of remarks.
func oauthTargetIDs(inboundSvc *InboundService, remarks []string) ([]int, error) {
	inbounds, err := inboundSvc.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	wanted := make(map[string]struct{}, len(remarks))
	for _, r := range remarks {
		wanted[r] = struct{}{}
	}
	var ids []int
	for _, ib := range inbounds {
		if _, ok := wanted[ib.Remark]; ok {
			ids = append(ids, ib.Id)
		}
	}
	return ids, nil
}

// missingOauthTargets returns the targets rec is not attached to yet.
func missingOauthTargets(clientSvc *ClientService, rec *model.ClientRecord, targets []int) ([]int, error) {
	current, err := clientSvc.GetInboundIdsForRecord(rec.Id)
	if err != nil {
		return nil, err
	}
	have := make(map[int]struct{}, len(current))
	for _, id := range current {
		have[id] = struct{}{}
	}
	var missing []int
	for _, id := range targets {
		if _, ok := have[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing, nil
}

// buildOAuthClient mints the client with a known subId so the caller can hand it
// straight to the cabinet; ClientService.Create fills per-protocol credentials.
func buildOAuthClient(email string, cfg config.OAuthConfig) model.Client {
	c := model.Client{
		Email:   email,
		Enable:  true,
		Flow:    cfg.UserFlow,
		LimitIP: cfg.UserLimitIP,
		TotalGB: cfg.UserTotalGB * 1024 * 1024 * 1024,
		SubID:   uuid.NewString(),
	}
	if cfg.UserExpiryDays > 0 {
		c.ExpiryTime = time.Now().Add(time.Duration(cfg.UserExpiryDays) * 24 * time.Hour).UnixMilli()
	}
	return c
}
