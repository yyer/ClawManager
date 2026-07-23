package services

import (
	"strings"
	"testing"
)

func TestBuildACLUsername(t *testing.T) {
	cases := []struct {
		teamID    int
		memberKey string
		want      string
	}{
		{12, "frontend", "team_12_frontend"},
		{12, "code-reviewer", "team_12_code-reviewer"},
		{12, "FrontEnd", "team_12_frontend"}, // lower-cased
		{12, "back_end", "team_12_back-end"}, // underscore → hyphen
		{12, "back.end", "team_12_back-end"}, // dot → hyphen
		{12, "a--b", "team_12_a-b"},          // collapsed hyphens
		{12, "-leading", "team_12_leading"},  // trimmed leading hyphen
		{12, "trailing-", "team_12_trailing"},
		{12, "", "team_12_member"},    // empty fallback
		{12, "!!!", "team_12_member"}, // all-invalid fallback
		{100, "leader", "team_100_leader"},
	}
	for _, c := range cases {
		got := buildACLUsername(c.teamID, c.memberKey)
		if got != c.want {
			t.Errorf("buildACLUsername(%d, %q) = %q, want %q", c.teamID, c.memberKey, got, c.want)
		}
	}
}

func TestBuildAdminUsername(t *testing.T) {
	if got := buildAdminUsername(12); got != "team_12_admin" {
		t.Errorf("buildAdminUsername(12) = %q, want team_12_admin", got)
	}
	if got := buildAdminUsername(100); got != "team_100_admin" {
		t.Errorf("buildAdminUsername(100) = %q, want team_100_admin", got)
	}
}

func TestSanitiseACLUsernameSegment(t *testing.T) {
	cases := map[string]string{
		"frontend":      "frontend",
		"FrontEnd":      "frontend",
		"code-reviewer": "code-reviewer",
		"code_reviewer": "code-reviewer",
		"a.b.c":         "a-b-c",
		"a--b":          "a-b",
		"-leading":      "leading",
		"trailing-":     "trailing",
		"":              "member",
		"!!!":           "member",
		"UPPER_CASE":    "upper-case",
	}
	for in, want := range cases {
		got := sanitiseACLUsernameSegment(in)
		if got != want {
			t.Errorf("sanitiseACLUsernameSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildAdminACLRules(t *testing.T) {
	rules := buildAdminACLRules(12, "s3cret")
	want := []string{
		"on",
		">s3cret",
		"~claw:team:12:*",
		"+@all",
		"-@dangerous",
	}
	if len(rules) != len(want) {
		t.Fatalf("admin rules length = %d, want %d (%v)", len(rules), len(want), rules)
	}
	for i, r := range rules {
		if r != want[i] {
			t.Errorf("admin rules[%d] = %q, want %q (full: %v)", i, r, want[i], rules)
		}
	}
}

func TestBuildMemberACLRules(t *testing.T) {
	secret := "mem-secret"

	t.Run("normal_member_exact_rules", func(t *testing.T) {
		// Rule order matters in Redis ACL: later rules override earlier ones.
		// `-@all` MUST come before `+XADD`, otherwise the trailing `-@all`
		// strips XADD back out (and Redis silently drops the no-op +XADD
		// from the stored rule list). Assert the EXACT sequence here so a
		// future reordering breaks the test, not production.
		//
		// %W~ is Redis 7+ write-only key pattern selector: allows XADD
		// (write) but blocks XREAD/XREADGROUP/XREVRANGE (read) on other
		// members' inboxes and on events. This preserves within-team
		// eavesdropping defense while allowing the redis-team plugin to
		// XADD replies to teammates.
		rules := buildMemberACLRules(12, "frontend", false, secret)
		want := []string{
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
			"~claw:team:12:*",
		}
		if len(rules) != len(want) {
			t.Fatalf("normal member rules length = %d, want %d (%v)", len(rules), len(want), rules)
		}
		for i, r := range rules {
			if r != want[i] {
				t.Errorf("normal member rules[%d] = %q, want %q (full: %v)", i, r, want[i], rules)
			}
		}
		// Sanity: must NOT have XREAD or XREVRANGE (eavesdropping defense).
		joined := strings.Join(rules, " ")
		if strings.Contains(joined, "+XREAD ") || strings.HasSuffix(joined, "+XREAD") {
			t.Errorf("normal member should not have +XREAD: %v", rules)
		}
		if strings.Contains(joined, "+XREVRANGE") {
			t.Errorf("normal member should not have +XREVRANGE: %v", rules)
		}
	})

	t.Run("leader_member_exact_rules", func(t *testing.T) {
		rules := buildMemberACLRules(12, "leader", true, secret)
		want := []string{
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
			"~claw:team:12:*",
		}
		if len(rules) != len(want) {
			t.Fatalf("leader rules length = %d, want %d (%v)", len(rules), len(want), rules)
		}
		for i, r := range rules {
			if r != want[i] {
				t.Errorf("leader rules[%d] = %q, want %q (full: %v)", i, r, want[i], rules)
			}
		}
		// Leader must NOT have a narrow per-member inbox key restriction.
		joined := strings.Join(rules, " ")
		if strings.Contains(joined, "~claw:team:12:inbox:leader") {
			t.Errorf("leader should not be restricted to own inbox key: %v", rules)
		}
	})

	t.Run("member_key_used_raw_in_inbox_pattern", func(t *testing.T) {
		// member rules use ~claw:team:<id>:* (team-scoped R+W) so memberKey
		// no longer appears in the pattern. Sanity-check the team-id is
		// rendered correctly instead.
		rules := buildMemberACLRules(12, "code-reviewer", false, secret)
		joined := strings.Join(rules, " ")
		if !strings.Contains(joined, "~claw:team:12:*") {
			t.Errorf("team pattern should be present: %v", rules)
		}
	})
}

func TestGenerateACLSecret(t *testing.T) {
	s1, err := generateACLSecret()
	if err != nil {
		t.Fatalf("generateACLSecret returned error: %v", err)
	}
	s2, err := generateACLSecret()
	if err != nil {
		t.Fatalf("generateACLSecret returned error: %v", err)
	}
	if s1 == s2 {
		t.Errorf("two calls returned identical secrets: %q", s1)
	}
	if len(s1) < 32 {
		t.Errorf("secret too short: %d chars (%q)", len(s1), s1)
	}
	// URL-safe base64 (RawURLEncoding) must not contain +, /, or =
	for _, ch := range s1 {
		if ch == '+' || ch == '/' || ch == '=' {
			t.Errorf("secret contains URL-unsafe char %q: %s", ch, s1)
		}
	}
}

func TestBuildMemberRedisURL(t *testing.T) {
	cases := []struct {
		name     string
		adminURL string
		username string
		secret   string
		want     string
	}{
		{
			name:     "plain_redis_no_db",
			adminURL: "redis://clawmanager-team-redis:6379/0",
			username: "team_12_frontend",
			secret:   "s3cret",
			want:     "redis://team_12_frontend:s3cret@clawmanager-team-redis:6379/0",
		},
		{
			name:     "rediss_tls",
			adminURL: "rediss://team-redis.example:6380/1",
			username: "team_12_leader",
			secret:   "lead-key",
			want:     "rediss://team_12_leader:lead-key@team-redis.example:6380/1",
		},
		{
			name:     "replaces_existing_userinfo",
			adminURL: "redis://old:oldpass@host:6379/0",
			username: "team_12_frontend",
			secret:   "newpass",
			want:     "redis://team_12_frontend:newpass@host:6379/0",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := buildMemberRedisURL(c.adminURL, c.username, c.secret)
			if err != nil {
				t.Fatalf("buildMemberRedisURL returned error: %v", err)
			}
			if got != c.want {
				t.Errorf("buildMemberRedisURL(%q, %q, %q) = %q, want %q",
					c.adminURL, c.username, c.secret, got, c.want)
			}
		})
	}
}

func TestBuildMemberRedisURL_ErrorOnBadScheme(t *testing.T) {
	_, err := buildMemberRedisURL("http://example.com", "user", "pass")
	if err == nil {
		t.Fatal("expected error for http scheme, got nil")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("error should mention scheme, got: %v", err)
	}
}

func TestTeamRuntimeSecretsRedisURLForMember(t *testing.T) {
	t.Run("nil_receiver_returns_empty", func(t *testing.T) {
		var r *teamRuntimeSecrets
		if got := r.RedisURLForMember("frontend"); got != "" {
			t.Errorf("nil receiver should return empty, got %q", got)
		}
	})

	t.Run("empty_member_urls_falls_back_to_admin", func(t *testing.T) {
		r := &teamRuntimeSecrets{RedisURL: "redis://admin-host:6379/0"}
		if got := r.RedisURLForMember("frontend"); got != "redis://admin-host:6379/0" {
			t.Errorf("expected fallback to admin URL, got %q", got)
		}
	})

	t.Run("missing_member_falls_back_to_admin", func(t *testing.T) {
		r := &teamRuntimeSecrets{
			RedisURL: "redis://admin-host:6379/0",
			MemberRedisURLs: map[string]string{
				"frontend": "redis://team_12_frontend:secret@host:6379/0",
			},
		}
		if got := r.RedisURLForMember("backend"); got != "redis://admin-host:6379/0" {
			t.Errorf("missing member should fall back to admin URL, got %q", got)
		}
	})

	t.Run("empty_member_url_falls_back_to_admin", func(t *testing.T) {
		r := &teamRuntimeSecrets{
			RedisURL: "redis://admin-host:6379/0",
			MemberRedisURLs: map[string]string{
				"frontend": "",
			},
		}
		if got := r.RedisURLForMember("frontend"); got != "redis://admin-host:6379/0" {
			t.Errorf("empty member URL should fall back to admin URL, got %q", got)
		}
	})

	t.Run("returns_per_member_url_when_present", func(t *testing.T) {
		r := &teamRuntimeSecrets{
			RedisURL: "redis://admin-host:6379/0",
			MemberRedisURLs: map[string]string{
				"frontend": "redis://team_12_frontend:secret@host:6379/0",
			},
		}
		want := "redis://team_12_frontend:secret@host:6379/0"
		if got := r.RedisURLForMember("frontend"); got != want {
			t.Errorf("expected per-member URL, got %q", got)
		}
	})
}

func TestDefaultAdminRedisURL(t *testing.T) {
	// DefaultAdminRedisURL is a thin wrapper around defaultTeamRedisURL.
	// Verify it returns the same value as the underlying function.
	t.Setenv("CLAWMANAGER_TEAM_REDIS_URL", "redis://test-host:6379/0")
	got := DefaultAdminRedisURL()
	want := defaultTeamRedisURL()
	if got != want {
		t.Errorf("DefaultAdminRedisURL() = %q, want %q (should match defaultTeamRedisURL)", got, want)
	}
	if got != "redis://test-host:6379/0" {
		t.Errorf("DefaultAdminRedisURL() = %q, want redis://test-host:6379/0", got)
	}
}

func TestNewRedisACLManager(t *testing.T) {
	m := NewRedisACLManager("redis://host:6379/0")
	if m == nil {
		t.Fatal("NewRedisACLManager returned nil")
	}
	// Verify it satisfies the interface at compile time via the return type;
	// here we just check it's not nil and is the concrete impl.
	impl, ok := m.(*redisACLManager)
	if !ok {
		t.Fatalf("expected *redisACLManager, got %T", m)
	}
	if impl.adminURL != "redis://host:6379/0" {
		t.Errorf("adminURL = %q, want redis://host:6379/0", impl.adminURL)
	}
}
