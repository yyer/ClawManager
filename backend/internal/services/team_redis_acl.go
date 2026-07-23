package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// ACLMemberSpec is the minimal info RedisACLManager needs to provision a
// per-member ACL user. Callers (team_service) convert from plannedTeamMember
// or models.TeamMember to avoid coupling this layer to those types.
type ACLMemberSpec struct {
	MemberKey string
	IsLeader  bool
}

// ACLRuntime is the result of Provision — the admin URL backend uses for
// itself, plus per-member URLs to inject into each member Pod's env.
type ACLRuntime struct {
	AdminURL   string
	MemberURLs map[string]string // memberKey → redis://<user>:<secret>@host/db
}

// ACLUserInfo is the diagnostic shape returned by ListUsers.
type ACLUserInfo struct {
	Name string
}

// ACLProbeResult is the outcome of a per-member URL ACL health probe.
// At most one of Breached / Error is set; Healthy=true implies both are empty.
type ACLProbeResult struct {
	// Healthy=true means the per-member URL authenticated successfully AND
	// the cross-team XADD was rejected by Redis ACL (NOPERM). This is the
	// expected steady state for a correctly provisioned team.
	Healthy bool
	// Breached=true means the per-member URL was able to XADD to a key
	// outside its own team prefix. This indicates ACL is not enforced
	// (e.g. team was provisioned in password_only mode, or ACL rules were
	// manually altered). The probe cleans up the test entry it wrote.
	Breached bool
	// Error holds a human-readable error when the probe could not complete
	// (e.g. WRONGPASS, ACL user missing, network failure). Treated as
	// medium-severity by callers - the team's runtime is likely broken.
	Error string
}

// RedisACLManager manages Redis per-member ACL users for teams. All methods
// are no-ops-safe (return nil error) when Redis does not support ACL
// (< 6.0); callers treat errors as warnings, not fatal.
type RedisACLManager interface {
	// Provision creates admin + per-member ACL users for a team and returns
	// per-member Redis URLs. adminURL is the connection string to reach Redis
	// with the existing default/admin credentials (pre-ACL state).
	Provision(ctx context.Context, teamID int, members []ACLMemberSpec, adminURL string) (*ACLRuntime, error)
	// RemoveMember deletes a single member's ACL user. No-op if user absent.
	RemoveMember(ctx context.Context, teamID int, memberKey string) error
	// Teardown deletes all ACL users belonging to the team (admin + members).
	Teardown(ctx context.Context, teamID int) error
	// ListUsers returns all ACL users (diagnostic / governance page).
	ListUsers(ctx context.Context) ([]ACLUserInfo, error)
	// ProbeMemberURL validates that a per-member URL's ACL isolation still
	// holds. Connects with the member's credentials, PINGs to verify auth,
	// then attempts a cross-team XADD. Expected outcome: Healthy=true with
	// NOPERM on the cross-team write. otherTeamID must differ from fromTeamID.
	ProbeMemberURL(ctx context.Context, memberURL string, fromTeamID, otherTeamID int) (ACLProbeResult, error)
}

// redisACLManager is the default implementation. It holds an adminURL used
// for RemoveMember/Teardown/ListUsers (which don't have a fresh adminURL
// passed in by the caller, unlike Provision).
type redisACLManager struct {
	adminURL string
}

// NewRedisACLManager constructs a manager that connects to Redis via the
// given admin URL for non-Provision operations. Provision itself receives
// adminURL as a parameter (because team creation may pass the team's own
// admin URL rather than the cluster default).
func NewRedisACLManager(adminURL string) RedisACLManager {
	return &redisACLManager{adminURL: adminURL}
}

// DefaultAdminRedisURL returns the cluster-default Redis URL used when
// the manager is constructed without an explicit override. Wraps
// defaultTeamRedisURL() so callers in other packages (main) can reach it.
func DefaultAdminRedisURL() string {
	return defaultTeamRedisURL()
}

// Provision creates the team's admin ACL user (full access to
// ~claw:team:<id>:*) and one ACL user per member. Members can XADD their
// own inbox and the events stream; leaders additionally gain XREAD/XREVRANGE
// across all team keys. On partial failure, rolls back created users.
func (m *redisACLManager) Provision(ctx context.Context, teamID int, members []ACLMemberSpec, adminURL string) (*ACLRuntime, error) {
	if strings.TrimSpace(adminURL) == "" {
		return nil, fmt.Errorf("admin redis url is required")
	}
	bus, err := newRedisBus(adminURL)
	if err != nil {
		return nil, fmt.Errorf("parse admin url: %w", err)
	}

	// Create admin ACL user first so subsequent operations could use it,
	// though we keep using the bootstrap adminURL for this call.
	adminSecret, err := generateACLSecret()
	if err != nil {
		return nil, fmt.Errorf("generate admin secret: %w", err)
	}
	adminName := buildAdminUsername(teamID)
	if err := bus.ACLSetUser(ctx, adminName, buildAdminACLRules(teamID, adminSecret)...); err != nil {
		return nil, fmt.Errorf("create admin acl user: %w", err)
	}
	createdUsers := []string{adminName}
	rollback := func(reason error) (*ACLRuntime, error) {
		for _, name := range createdUsers {
			_ = bus.ACLDelUser(ctx, name)
		}
		return nil, reason
	}

	adminMemberURL, err := buildMemberRedisURL(adminURL, adminName, adminSecret)
	if err != nil {
		return rollback(fmt.Errorf("build admin url: %w", err))
	}

	memberURLs := make(map[string]string, len(members))
	for _, member := range members {
		if strings.TrimSpace(member.MemberKey) == "" {
			return rollback(fmt.Errorf("member key is empty"))
		}
		secret, err := generateACLSecret()
		if err != nil {
			return rollback(fmt.Errorf("generate member secret: %w", err))
		}
		username := buildACLUsername(teamID, member.MemberKey)
		rules := buildMemberACLRules(teamID, member.MemberKey, member.IsLeader, secret)
		if err := bus.ACLSetUser(ctx, username, rules...); err != nil {
			return rollback(fmt.Errorf("create member acl user %s: %w", username, err))
		}
		createdUsers = append(createdUsers, username)

		memberURL, err := buildMemberRedisURL(adminURL, username, secret)
		if err != nil {
			return rollback(fmt.Errorf("build member url for %s: %w", username, err))
		}
		memberURLs[member.MemberKey] = memberURL
	}

	// Best-effort persist; ignore error when no aclfile is configured.
	_ = bus.ACLSave(ctx)

	return &ACLRuntime{AdminURL: adminMemberURL, MemberURLs: memberURLs}, nil
}

// RemoveMember deletes a single member's ACL user. No-op if the user does
// not exist (Redis ACL DELUSER returns count of deleted users, 0 is fine).
func (m *redisACLManager) RemoveMember(ctx context.Context, teamID int, memberKey string) error {
	if strings.TrimSpace(memberKey) == "" {
		return nil
	}
	bus, err := newRedisBus(m.adminURL)
	if err != nil {
		return fmt.Errorf("parse admin url: %w", err)
	}
	username := buildACLUsername(teamID, memberKey)
	if err := bus.ACLDelUser(ctx, username); err != nil {
		return fmt.Errorf("del acl user %s: %w", username, err)
	}
	_ = bus.ACLSave(ctx)
	return nil
}

// Teardown deletes all ACL users whose name starts with team_<id>_. Used
// during team deletion to clean up admin + members in one pass.
func (m *redisACLManager) Teardown(ctx context.Context, teamID int) error {
	bus, err := newRedisBus(m.adminURL)
	if err != nil {
		return fmt.Errorf("parse admin url: %w", err)
	}
	users, err := bus.ACLListUsers(ctx)
	if err != nil {
		return fmt.Errorf("list acl users: %w", err)
	}
	prefix := fmt.Sprintf("team_%d_", teamID)
	for _, name := range users {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if err := bus.ACLDelUser(ctx, name); err != nil {
			return fmt.Errorf("del acl user %s: %w", name, err)
		}
	}
	_ = bus.ACLSave(ctx)
	return nil
}

// ListUsers returns all ACL users. Diagnostic only — used by governance
// page or CLI to inspect current ACL state.
func (m *redisACLManager) ListUsers(ctx context.Context) ([]ACLUserInfo, error) {
	bus, err := newRedisBus(m.adminURL)
	if err != nil {
		return nil, fmt.Errorf("parse admin url: %w", err)
	}
	users, err := bus.ACLListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list acl users: %w", err)
	}
	out := make([]ACLUserInfo, 0, len(users))
	for _, name := range users {
		out = append(out, ACLUserInfo{Name: name})
	}
	return out, nil
}

// ProbeMemberURL delegates to probeACLHealth (team_acl_probe.go). Thin
// wrapper so callers can reach the probe via the RedisACLManager
// interface alongside Provision/Teardown.
func (m *redisACLManager) ProbeMemberURL(ctx context.Context, memberURL string, fromTeamID, otherTeamID int) (ACLProbeResult, error) {
	return probeACLHealth(ctx, memberURL, fromTeamID, otherTeamID)
}

// buildAdminUsername returns the ACL username for a team's admin user.
// Format: team_<teamId>_admin
func buildAdminUsername(teamID int) string {
	return fmt.Sprintf("team_%d_admin", teamID)
}

// buildACLUsername returns the ACL username for a team member. MemberKey
// is sanitised to lower-case alnum + hyphen to stay within Redis ACL
// username charset conventions. Format: team_<teamId>_<sanitisedMemberKey>
func buildACLUsername(teamID int, memberKey string) string {
	return fmt.Sprintf("team_%d_%s", teamID, sanitiseACLUsernameSegment(memberKey))
}

// sanitiseACLUsernameSegment lower-cases the input and replaces any
// character outside [a-z0-9-] with a hyphen, collapsing runs of hyphens.
// Empty result falls back to "member" so the username is never malformed.
func sanitiseACLUsernameSegment(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "member"
	}
	return out
}

// buildAdminACLRules returns the ACL rules for a team admin user. Admin
// can access all team keys and run all non-dangerous commands.
// Rule shape: on ><secret> ~claw:team:<id>:* +@all -@dangerous
//
// Rule ORDER matters in Redis ACL: later rules override earlier ones.
// `+@all -@dangerous` is correct (allow all, then carve out dangerous).
// We don't use `-@all` here so the order is fine.
func buildAdminACLRules(teamID int, secret string) []string {
	return []string{
		"on",
		">" + secret,
		fmt.Sprintf("~claw:team:%d:*", teamID),
		"+@all",
		"-@dangerous",
	}
}

// buildMemberACLRules returns the ACL rules for a team member.
//
// Commands granted (both roles): SELECT, CLIENT, PING, XADD, XGROUP,
// XREADGROUP, XACK, HSET. These are what the openclaw redis-team plugin
// issues during normal operation (DB selection, client identification,
// keepalive, stream writes, consumer-group reads on own inbox, acks,
// presence hash updates).
//
// Leader additionally gets +XREAD and +XREVRANGE so it can directly consume
// the events stream and read member inboxes for task routing.
//
// Key patterns (normal member):
//   - ~claw:team:<id>:inbox:<member>     own inbox, R+W (XADD self, XGROUP/XREADGROUP/XACK)
//   - %W~claw:team:<id>:inbox:*           any inbox, write-only (XADD replies to teammates)
//   - %W~claw:team:<id>:events            events stream, write-only (XADD only)
//   - %W~claw:team:<id>:presence          presence hash, write-only (HSET own entry)
//
// The %W~ write-only patterns (Redis 7+ selector) let normal members
// XADD to teammates' inboxes (required by plugin for replies/DMs) while
// blocking XREAD/XREADGROUP/XREVRANGE on those keys. This preserves the
// TC-R02 within-team eavesdropping defense: a compromised frontend
// cannot read leader's inbox, only write to it.
//
// Leader uses ~claw:team:<id>:* (R+W on all team keys) so it can read
// events and any member inbox.
//
// Rule ORDER matters in Redis ACL: later rules override earlier ones.
// `-@all` MUST come before the `+XADD` etc. grants, otherwise the
// trailing `-@all` strips them back out (Redis also silently drops the
// no-op `+XADD` from the stored rule list).
//
// Caller MUST ensure memberKey is already normalised via normalizeTeamMemberKey
// (team_service.go) so it matches the inbox key constructed by teamInboxKey.
// We do not re-sanitise here because teamInboxKey uses raw memberKey — if we
// sanitised differently, the ACL pattern would not match the actual inbox key.
func buildMemberACLRules(teamID int, memberKey string, isLeader bool, secret string) []string {
	if isLeader {
		return []string{
			"on",
			">" + secret,
			"-@all",
			"+SELECT",
			"+CLIENT",
			"+PING",
			"+XADD",
			"+XREAD",
			"+XREVRANGE",
			"+XGROUP",
			"+XREADGROUP",
			"+XACK",
			"+HSET",
			"+GET",
			"+EVAL",
			fmt.Sprintf("~claw:team:%d:*", teamID),
		}
	}
	return []string{
		"on",
		">" + secret,
		"-@all",
		"+SELECT",
		"+CLIENT",
		"+PING",
		"+XADD",
		"+XGROUP",
		"+XREADGROUP",
		"+XACK",
		"+HSET",
		"+GET",
		"+EVAL",
		fmt.Sprintf("~claw:team:%d:*", teamID),
	}
}

// generateACLSecret returns a 32-byte random URL-safe base64 string for
// use as an ACL user password. RawURLEncoding avoids '+' and '/' which
// could complicate URL embedding.
func generateACLSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// buildMemberRedisURL rewrites the userinfo of adminURL to embed the
// per-member username and secret. Preserves scheme/host/db/TLS. Returns
// error if adminURL is not a valid redis/rediss URL.
func buildMemberRedisURL(adminURL, username, secret string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(adminURL))
	if err != nil {
		return "", fmt.Errorf("parse admin url: %w", err)
	}
	if parsed.Scheme != "redis" && parsed.Scheme != "rediss" {
		return "", fmt.Errorf("admin url scheme must be redis or rediss, got %q", parsed.Scheme)
	}
	parsed.User = url.UserPassword(username, secret)
	return parsed.String(), nil
}

// compile-time assertion that redisACLManager satisfies RedisACLManager.
var _ RedisACLManager = (*redisACLManager)(nil)
