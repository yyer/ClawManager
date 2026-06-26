package services

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/secplane/policy"
)

// collabPolicyCacheTTL bounds how long a cached collab policy is reused
// before re-reading from the DB. DispatchTask can fire in hot loops (quota
// check, leader bootstrap) so a 10s cache avoids per-call DB hits.
const collabPolicyCacheTTL = 10 * time.Second

// collabPolicyEntry caches the parsed collab policy. teamService holds one
// entry; the cache is guarded by collabCacheMu.
type collabPolicyEntry struct {
	payload   policy.CollabPolicyPayload
	fetchedAt time.Time
}

// CollabViolationError is returned by DispatchTask when a collab rule fires
// in enforce mode. team_handler maps it to HTTP 403 with rule_id/severity.
type CollabViolationError struct {
	RuleID   string // collab_identity_breach | collab_schema_violation | collab_quota_throttle | collab_approval_required
	Reason   string
	Severity string // medium | high
	Mode     string // enforce | observe
}

func (e *CollabViolationError) Error() string {
	return fmt.Sprintf("collab policy blocked: %s (%s)", e.RuleID, e.Reason)
}

// checkCollabTask runs the 4 collab rules against a DispatchTask envelope.
// Returns the first enforce-mode violation (caller blocks XAdd) or nil.
// Observe-mode violations are recorded as alerts but do not block.
// If collabSvc is nil (back-compat) or policy load fails, returns nil (fail open).
func (s *teamService) checkCollabTask(team *models.Team, member *models.TeamMember, envelope map[string]interface{}, envelopeJSON string) *CollabViolationError {
	if s.collabSvc == nil {
		return nil
	}

	p, err := s.loadCollabPolicy()
	if err != nil || p == nil {
		return nil
	}

	if !collabPolicyEnabled(p) {
		return nil
	}

	// teamId mismatch → clear. dispatchInitialLeaderTask fires for every new
	// team; collab policy teamId default "12" won't match a real team id, so
	// bootstrap tasks pass through unchecked until the operator sets teamId.
	if p.TeamId != "" && p.TeamId != strconv.Itoa(team.ID) {
		return nil
	}

	violations := s.evalCollabRules(p, team, member, envelope)

	for i := range violations {
		s.recordCollabAlert(&violations[i], team, member, envelopeJSON)
	}

	for i := range violations {
		if violations[i].Mode == "enforce" {
			v := violations[i]
			return &v
		}
	}
	return nil
}

// loadCollabPolicy returns the cached policy if fresh, else re-reads from DB.
// On DB error returns default policy (fail open). default policy is also used
// when no row exists yet.
func (s *teamService) loadCollabPolicy() (*policy.CollabPolicyPayload, error) {
	s.collabCacheMu.Lock()
	defer s.collabCacheMu.Unlock()
	if s.collabPolicyCache != nil && time.Since(s.collabPolicyCache.fetchedAt) < collabPolicyCacheTTL {
		p := s.collabPolicyCache.payload
		return &p, nil
	}
	rule, err := s.collabSvc.GetByRuleID(policy.CollabPolicyRuleID)
	if err != nil {
		return nil, err
	}
	if rule == nil || strings.TrimSpace(rule.Pattern) == "" {
		p := defaultCollabPolicy()
		s.collabPolicyCache = &collabPolicyEntry{payload: *p, fetchedAt: time.Now()}
		return p, nil
	}
	var payload policy.CollabPolicyPayload
	if err := json.Unmarshal([]byte(rule.Pattern), &payload); err != nil {
		p := defaultCollabPolicy()
		s.collabPolicyCache = &collabPolicyEntry{payload: *p, fetchedAt: time.Now()}
		return p, nil
	}
	s.collabPolicyCache = &collabPolicyEntry{payload: payload, fetchedAt: time.Now()}
	return &payload, nil
}

// evalCollabRules evaluates the 4 sub-rules against the envelope.
// envelope fields (set by team_service.DispatchTask):
//   from=clawmanager, to=member.MemberKey, messageId, teamId, intent,
//   taskId, title, prompt, contextRefs, metadata, createdAt
func (s *teamService) evalCollabRules(p *policy.CollabPolicyPayload, team *models.Team, member *models.TeamMember, env map[string]interface{}) []CollabViolationError {
	var out []CollabViolationError

	// 1. identity — from must be "clawmanager" or the target member's key.
	//    team_service always sets from="clawmanager" today, so this rule is
	//    defense-in-depth for future envelope variants.
	if p.IdentityMode != "off" {
		from, _ := env["from"].(string)
		if from != "" && from != "clawmanager" && from != member.MemberKey {
			out = append(out, CollabViolationError{
				RuleID:   "collab_identity_breach",
				Reason:   fmt.Sprintf("sender '%s' is not clawmanager or target member '%s'", from, member.MemberKey),
				Severity: "high",
				Mode:     p.IdentityMode,
			})
		}
	}

	// 2. schema — required fields messageId/teamId/to/prompt must be present
	//    and non-empty.
	if p.SchemaMode != "off" {
		var missing []string
		for _, k := range []string{"messageId", "teamId", "to", "prompt"} {
			v, _ := env[k].(string)
			if strings.TrimSpace(v) == "" {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			out = append(out, CollabViolationError{
				RuleID:   "collab_schema_violation",
				Reason:   "missing required fields: " + strings.Join(missing, ", "),
				Severity: "medium",
				Mode:     p.SchemaMode,
			})
		}
	}

	// 3. quota — sliding window per (teamId:memberKey), limit = XaddRps
	// within XaddWindowSeconds (default 1s). Window size is configurable so
	// operators can test with e.g. "2 XADD in 5s" instead of needing to fire
	// 21 requests within a single second.
	if p.QuotaMode != "off" && p.XaddRps > 0 {
		windowSecs := p.XaddWindowSeconds
		if windowSecs <= 0 {
			windowSecs = 1
		}
		windowMillis := int64(windowSecs) * 1000
		key := fmt.Sprintf("%d:%s", team.ID, member.MemberKey)
		now := time.Now().UnixMilli()
		s.collabQuotaMu.Lock()
		window := s.collabQuotaWindows[key]
		pruned := window[:0]
		for _, ts := range window {
			if now-ts < windowMillis {
				pruned = append(pruned, ts)
			}
		}
		pruned = append(pruned, now)
		s.collabQuotaWindows[key] = pruned
		s.collabQuotaMu.Unlock()
		if len(pruned) > p.XaddRps {
			out = append(out, CollabViolationError{
				RuleID:   "collab_quota_throttle",
				Reason:   fmt.Sprintf("XADD rate %d in %ds exceeds limit %d", len(pruned), windowSecs, p.XaddRps),
				Severity: "medium",
				Mode:     p.QuotaMode,
			})
		}
	}

	// 4. approval — DispatchTask is always clawmanager→single-member (not
	//    broadcast). to!=member is impossible here because teamInboxKey is
	//    derived from member.MemberKey, but check anyway as defense-in-depth.
	if p.ApprovalMode != "off" {
		to, _ := env["to"].(string)
		if to != "" && to != member.MemberKey {
			out = append(out, CollabViolationError{
				RuleID:   "collab_approval_required",
				Reason:   fmt.Sprintf("to '%s' does not match target member '%s'", to, member.MemberKey),
				Severity: "high",
				Mode:     p.ApprovalMode,
			})
		}
	}

	return out
}

// recordCollabAlert writes a secplane_alert row for a violation. Failures are
// logged but do not block the dispatch path.
func (s *teamService) recordCollabAlert(v *CollabViolationError, team *models.Team, member *models.TeamMember, envelopeJSON string) {
	if s.collabSvc == nil {
		return
	}
	ruleID := v.RuleID
	ruleName := map[string]string{
		"collab_identity_breach":  "协同治理-身份违规",
		"collab_schema_violation": "协同治理-Schema违规",
		"collab_quota_throttle":   "协同治理-配额限流",
		"collab_approval_required": "协同治理-审批缺失",
	}[v.RuleID]
	if ruleName == "" {
		ruleName = "协同治理-" + v.RuleID
	}
	action := "observed"
	if v.Mode == "enforce" {
		action = "blocked"
	}
	subject := fmt.Sprintf("team:%d:member:%s", team.ID, member.MemberKey)
	alert := &policy.Alert{
		Source:     "collab_governance",
		RuleID:     &ruleID,
		RuleName:   &ruleName,
		Severity:   v.Severity,
		Action:     action,
		Subject:    &subject,
		Evidence:   &v.Reason,
		RawPayload: &envelopeJSON,
	}
	if err := s.collabSvc.RecordExternalAlert(alert); err != nil {
		fmt.Printf("Warning: failed to record collab alert: %v\n", err)
	}
}

// collabPolicyEnabled returns false when all 4 sub-modes are off (effectively
// a master switch).
func collabPolicyEnabled(p *policy.CollabPolicyPayload) bool {
	return p.IdentityMode != "off" || p.SchemaMode != "off" || p.QuotaMode != "off" || p.ApprovalMode != "off"
}

// defaultCollabPolicy mirrors policy/handler.go defaultCollabPolicy. Kept in
// sync so a fresh install with no collab.policy row still has safe defaults.
func defaultCollabPolicy() *policy.CollabPolicyPayload {
	return &policy.CollabPolicyPayload{
		TeamId:            "12",
		CommunicationMode: "leader_mediated",
		RedisAclMode:      "per_member",
		RelayRequired:     true,
		IdentityMode:      "enforce",
		SchemaMode:        "observe",
		QuotaMode:         "enforce",
		ApprovalMode:      "observe",
		MuteOnAnomaly:     true,
		AuditReplay:       true,
		XaddRps:           20,
		XaddWindowSeconds: 1,
		StreamMaxLen:      5000,
		ApprovalThreshold: 85,
	}
}
