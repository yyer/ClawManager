package services

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// probeACLHealth validates that a per-member Redis URL's ACL isolation
// still holds. Connects with the member credentials, then attempts a
// cross-team XADD. Expected outcome: NOPERM (ACL blocks the write),
// which means Healthy=true. A successful cross-team write means the ACL
// is not enforced (Breached=true); the probe cleans up the test entry.
//
// The probe does NOT detect real attacks happening inside member pods -
// those never traverse backend. It only verifies that the ACL configuration
// provisioned by Provision() is still effective. Misconfiguration (e.g.
// manual ACL rewrite, password_only fallback) is what this catches.
//
// fromTeamID is the team the member URL belongs to; otherTeamID is the
// team whose keys we attempt to write to. They must differ - probing
// same-team writes is meaningless because the ACL allows them.
func probeACLHealth(ctx context.Context, memberURL string, fromTeamID, otherTeamID int) (ACLProbeResult, error) {
	if strings.TrimSpace(memberURL) == "" {
		return ACLProbeResult{Error: "member url is empty"}, nil
	}
	if fromTeamID == otherTeamID {
		return ACLProbeResult{Error: "from_team and other_team must differ for acl probe"}, nil
	}

	bus, err := newRedisBus(memberURL)
	if err != nil {
		return ACLProbeResult{Error: fmt.Sprintf("parse member url: %v", err)}, nil
	}

	probeKey := fmt.Sprintf("claw:team:%d:__acl_probe__", otherTeamID)
	probeFields := map[string]string{
		"__ACL_PROBE__": fmt.Sprintf("from_team=%d_at=%d", fromTeamID, time.Now().UnixNano()),
	}

	id, err := bus.XAdd(ctx, probeKey, probeFields)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "NOPERM") {
			return ACLProbeResult{Healthy: true}, nil
		}
		if strings.Contains(msg, "auth failed") || strings.Contains(msg, "WRONGPASS") {
			return ACLProbeResult{Error: fmt.Sprintf("auth failed: %s", msg)}, nil
		}
		return ACLProbeResult{Error: fmt.Sprintf("xadd probe: %s", msg)}, nil
	}

	if _, delErr := bus.XDel(ctx, probeKey, id); delErr != nil {
		return ACLProbeResult{
			Breached: true,
			Error:    fmt.Sprintf("acl breached: cross-team XADD succeeded (id=%s) but cleanup failed: %v", id, delErr),
		}, nil
	}
	return ACLProbeResult{
		Breached: true,
		Error:    fmt.Sprintf("acl breached: cross-team XADD succeeded (id=%s, key=%s), cleaned up", id, probeKey),
	}, nil
}
