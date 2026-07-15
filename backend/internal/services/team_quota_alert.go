package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/secplane/policy"
)

// checkStreamLimits inspects the team's events stream and each member's
// inbox stream for length over policy.StreamMaxLen. Over-limit streams
// are XTRIMmed to ~StreamMaxLen and a medium-severity alert is recorded.
//
// Best-effort: XLEN/XTRIM failures are logged and do not abort the sweep.
// Skipped entirely when policy.StreamMaxLen <= 0 (dead config).
func (s *teamService) checkStreamLimits(ctx context.Context, team *models.Team, bus *redisBus, p *policy.CollabPolicyPayload) {
	if p == nil || p.StreamMaxLen <= 0 {
		return
	}
	eventsLen, err := bus.XLen(ctx, teamEventsKey(team.ID))
	if err != nil {
		fmt.Printf("Warning: Team %d stream limit check XLEN events failed: %v\n", team.ID, err)
		return
	}
	if eventsLen > p.StreamMaxLen {
		trimmed, err := bus.XTrim(ctx, teamEventsKey(team.ID), p.StreamMaxLen)
		if err != nil {
			fmt.Printf("Warning: Team %d stream limit XTRIM events failed: %v\n", team.ID, err)
		}
		s.recordQuotaAlert(team.ID, "stream_limit_exceeded", "medium",
			fmt.Sprintf("events stream length %d exceeds limit %d (trimmed %d)", eventsLen, p.StreamMaxLen, trimmed))
	}

	members, err := s.repo.ListMembersByTeamID(team.ID)
	if err != nil {
		fmt.Printf("Warning: Team %d stream limit check list members failed: %v\n", team.ID, err)
		return
	}
	for idx := range members {
		member := &members[idx]
		if member.Status == models.TeamMemberStatusDeleted {
			continue
		}
		inboxLen, err := bus.XLen(ctx, teamInboxKey(team.ID, member.MemberKey))
		if err != nil {
			fmt.Printf("Warning: Team %d member %s inbox XLEN failed: %v\n", team.ID, member.MemberKey, err)
			continue
		}
		if inboxLen > p.StreamMaxLen {
			trimmed, err := bus.XTrim(ctx, teamInboxKey(team.ID, member.MemberKey), p.StreamMaxLen)
			if err != nil {
				fmt.Printf("Warning: Team %d member %s inbox XTRIM failed: %v\n", team.ID, member.MemberKey, err)
			}
			s.recordQuotaAlert(team.ID, "stream_limit_exceeded", "medium",
				fmt.Sprintf("member %s inbox length %d exceeds limit %d (trimmed %d)", member.MemberKey, inboxLen, p.StreamMaxLen, trimmed))
		}
	}
}

// recordMemberRate logs an XADD timestamp for the given member's events
// stream activity and emits a medium-severity alert when the count in the
// sliding window exceeds policy.XaddRps. The window is cleared after an
// alert fires to avoid duplicate alerts for the same burst.
//
// Skipped when policy.XaddRps <= 0 (rate limiting disabled).
func (s *teamService) recordMemberRate(teamID int, memberKey string, p *policy.CollabPolicyPayload) {
	if p == nil || p.XaddRps <= 0 || strings.TrimSpace(memberKey) == "" {
		return
	}
	windowSecs := p.XaddWindowSeconds
	if windowSecs <= 0 {
		windowSecs = 1
	}
	windowMillis := int64(windowSecs) * 1000
	now := time.Now().UnixMilli()

	s.eventsRateMu.Lock()
	defer s.eventsRateMu.Unlock()
	if s.eventsRateWindows == nil {
		s.eventsRateWindows = map[int]map[string][]int64{}
	}
	teamWindows, ok := s.eventsRateWindows[teamID]
	if !ok {
		teamWindows = map[string][]int64{}
		s.eventsRateWindows[teamID] = teamWindows
	}
	window := teamWindows[memberKey]
	pruned := window[:0]
	for _, ts := range window {
		if now-ts < windowMillis {
			pruned = append(pruned, ts)
		}
	}
	pruned = append(pruned, now)
	teamWindows[memberKey] = pruned

	if len(pruned) > p.XaddRps {
		teamWindows[memberKey] = pruned[:0]
		s.recordQuotaAlert(teamID, "rate_limit_exceeded", "medium",
			fmt.Sprintf("member %s events rate %d in %ds exceeds limit %d", memberKey, len(pruned), windowSecs, p.XaddRps))
	}
}

// recordQuotaAlert writes a secplane_alert row for a runtime quota
// violation (stream length or member rate). Failures are logged but do
// not block the consume loop.
func (s *teamService) recordQuotaAlert(teamID int, ruleID, severity, evidence string) {
	if s.collabSvc == nil {
		return
	}
	ruleName := map[string]string{
		"stream_limit_exceeded": "协同治理-队列容量超限",
		"rate_limit_exceeded":   "协同治理-发送速率超限",
	}[ruleID]
	if ruleName == "" {
		ruleName = "协同治理-" + ruleID
	}
	subject := fmt.Sprintf("team:%d", teamID)
	alert := &policy.Alert{
		Source:   "collab_governance",
		RuleID:   &ruleID,
		RuleName: &ruleName,
		Severity: severity,
		Action:   "throttled",
		Subject:  &subject,
		Evidence: &evidence,
	}
	if err := s.collabSvc.RecordExternalAlert(alert); err != nil {
		fmt.Printf("Warning: failed to record quota alert: %v\n", err)
	}
}
