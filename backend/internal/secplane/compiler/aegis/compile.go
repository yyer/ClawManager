// Package aegis compiles secplane policy rules into a ClawAegis userConfig
// JSON payload. The output schema mirrors openclaw.plugin.json's configSchema
// so the agent can write the result straight to the plugin's userConfig
// section and trigger a hot-reload.
package aegis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"clawreef/internal/secplane/policy"
)

// OutboundTrustedEntry — 单条出站白名单条目。fingerprint 为空 = 仅域名白名单。
type OutboundTrustedEntry struct {
	Domain      string `json:"domain"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Label       string `json:"label,omitempty"`
}

// UserConfig mirrors ClawAegis ClawAegisPluginConfig (ClawAegis/src/config.ts).
// Field names and JSON tags must stay byte-identical to what ClawAegis reads —
// changes here MUST be paired with a config.ts update and a base zip rebuild.
type UserConfig struct {
	AllDefensesEnabled  bool   `json:"allDefensesEnabled"`
	DefaultBlockingMode string `json:"defaultBlockingMode"`

	SelfProtectionEnabled        bool   `json:"selfProtectionEnabled"`
	SelfProtectionMode           string `json:"selfProtectionMode,omitempty"`
	CommandBlockEnabled          bool   `json:"commandBlockEnabled"`
	CommandBlockMode             string `json:"commandBlockMode,omitempty"`
	EncodingGuardEnabled         bool   `json:"encodingGuardEnabled"`
	EncodingGuardMode            string `json:"encodingGuardMode,omitempty"`
	ScriptProvenanceGuardEnabled bool   `json:"scriptProvenanceGuardEnabled"`
	ScriptProvenanceGuardMode    string `json:"scriptProvenanceGuardMode,omitempty"`
	MemoryGuardEnabled           bool   `json:"memoryGuardEnabled"`
	MemoryGuardMode              string `json:"memoryGuardMode,omitempty"`
	UserRiskScanEnabled          bool   `json:"userRiskScanEnabled"`
	SkillScanEnabled             bool   `json:"skillScanEnabled"`
	ToolResultScanEnabled        bool   `json:"toolResultScanEnabled"`
	OutputRedactionEnabled       bool   `json:"outputRedactionEnabled"`
	PromptGuardEnabled           bool   `json:"promptGuardEnabled"`
	LoopGuardEnabled             bool   `json:"loopGuardEnabled"`
	LoopGuardMode                string `json:"loopGuardMode,omitempty"`
	ExfiltrationGuardEnabled     bool   `json:"exfiltrationGuardEnabled"`
	ExfiltrationGuardMode        string `json:"exfiltrationGuardMode,omitempty"`
	ToolCallEnforcementEnabled   bool   `json:"toolCallEnforcementEnabled"`
	DispatchGuardEnabled         bool   `json:"dispatchGuardEnabled"`
	DispatchGuardMode            string `json:"dispatchGuardMode,omitempty"`
	RequireHttpsEnabled          bool   `json:"requireHttpsEnabled"`
	RequireHttpsMode             string `json:"requireHttpsMode,omitempty"`
	OutboundTrustEnabled         bool   `json:"outboundTrustEnabled"`
	OutboundTrustMode            string `json:"outboundTrustMode,omitempty"`

	// 应急熔断（kill switch）。启用后 ClawAegis 在 before_tool_call 中
	// 无条件 block 所有工具调用，理由取 KillSwitchReason。
	KillSwitchEnabled bool   `json:"killSwitchEnabled"`
	KillSwitchReason  string `json:"killSwitchReason,omitempty"`

	StartupSkillScan bool `json:"startupSkillScan"`

	// 出站可信端点（域名白名单 + 可选证书指纹）。ClawAegis before_tool_call 钩子
	// 配合 RequireHttpsEnabled + OutboundTrustEnabled 校验。空列表 = 不限制（仅日志）。
	OutboundTrustedEndpoints []OutboundTrustedEntry `json:"outboundTrustedEndpoints,omitempty"`

	ProtectedPaths   []string `json:"protectedPaths,omitempty"`
	ProtectedSkills  []string `json:"protectedSkills,omitempty"`
	ProtectedPlugins []string `json:"protectedPlugins,omitempty"`

	// Flag-level granularity. Each flag is in at most one set:
	//   - disabled    → ClawAegis suppresses the detector entirely
	//   - observeOnly → detection fires + event emitted (action=observed)
	//                   but downstream prompt-guard reminder is skipped
	//   - (neither)   → full enforcement, the default
	DisabledUserRiskFlags      []string `json:"disabledUserRiskFlags,omitempty"`
	ObserveOnlyUserRiskFlags   []string `json:"observeOnlyUserRiskFlags,omitempty"`
	DisabledToolResultFlags    []string `json:"disabledToolResultFlags,omitempty"`
	ObserveOnlyToolResultFlags []string `json:"observeOnlyToolResultFlags,omitempty"`

	// Collaboration governance (collab_guard). Driven by a single
	// KindCollabPolicy rule row whose Pattern is the full policy JSON.
	// CollabGuardMode is the master switch (off disables the whole defense);
	// the four sub-mode fields (Identity/Schema/Quota/Approval) each control
	// one rule inside detectCollabGuardViolation.
	CollabGuardEnabled    bool   `json:"collabGuardEnabled,omitempty"`
	CollabGuardMode       string `json:"collabGuardMode,omitempty"`
	CollabTeamId          string `json:"collabTeamId,omitempty"`
	CollabIdentityMode    string `json:"collabIdentityMode,omitempty"`
	CollabSchemaMode      string `json:"collabSchemaMode,omitempty"`
	CollabQuotaMode       string `json:"collabQuotaMode,omitempty"`
	CollabApprovalMode    string `json:"collabApprovalMode,omitempty"`
	CollabXaddRps         int    `json:"collabXaddRps,omitempty"`
	CollabXaddWindowSecs  int    `json:"collabXaddWindowSecs,omitempty"`
	CollabStreamMaxLen    int    `json:"collabStreamMaxLen,omitempty"`
	CollabMuteOnAnomaly   bool   `json:"collabMuteOnAnomaly,omitempty"`
	CollabAuditReplay     bool   `json:"collabAuditReplay,omitempty"`
	CollabApprovalThreshold int  `json:"collabApprovalThreshold,omitempty"`
	CollabRedisAclPreview string `json:"collabRedisAclPreview,omitempty"`
}

// Bundle is the full payload shipped via InstanceCommand. Revision + Sha256
// let the agent perform idempotent applies.
type Bundle struct {
	Revision    string     `json:"revision"`
	Sha256      string     `json:"sha256"`
	GeneratedAt string     `json:"generated_at,omitempty"`
	Source      string     `json:"source"` // "secplane.policy"
	UserConfig  UserConfig `json:"user_config"`
}

// Compile turns the full set of secplane rules into a ClawAegis bundle.
//
// Wiring summary:
//   defense_toggle    → cfg.<X>Enabled (+ cfg.<X>Mode for the 8 mode-supporting defenses)
//   user_risk_flag    → disabled/observeOnly UserRiskFlags lists
//   tool_result_flag  → disabled/observeOnly ToolResultFlags lists
//   protected_path    → ProtectedPaths
//   protected_skill   → ProtectedSkills
//   protected_plugin  → ProtectedPlugins
//
// Legacy kinds (prompt_filter / tool_control / memory_guard / file_protect)
// are intentionally inert. They survive in the DB for historical display
// but no longer drive ClawAegis behavior; the equivalent control now lives
// in defense_toggle + flag rules.
func Compile(rules []policy.Rule, revision string) (Bundle, error) {
	// Defaults: every defense ON at enforce, everything observable. Missing
	// defense_toggle seeds therefore degrade safely to "full protection"
	// rather than silently disabling guards.
	cfg := UserConfig{
		AllDefensesEnabled:           true,
		DefaultBlockingMode:          modeEnforce,
		SelfProtectionEnabled:        true,
		SelfProtectionMode:           modeEnforce,
		CommandBlockEnabled:          true,
		CommandBlockMode:             modeEnforce,
		EncodingGuardEnabled:         true,
		EncodingGuardMode:            modeEnforce,
		ScriptProvenanceGuardEnabled: true,
		ScriptProvenanceGuardMode:    modeEnforce,
		MemoryGuardEnabled:           true,
		MemoryGuardMode:              modeEnforce,
		UserRiskScanEnabled:          true,
		SkillScanEnabled:             true,
		ToolResultScanEnabled:        true,
		OutputRedactionEnabled:       true,
		PromptGuardEnabled:           true,
		LoopGuardEnabled:             true,
		LoopGuardMode:                modeEnforce,
		ExfiltrationGuardEnabled:     true,
		ExfiltrationGuardMode:        modeEnforce,
		ToolCallEnforcementEnabled:   true,
		DispatchGuardEnabled:         true,
		DispatchGuardMode:            modeEnforce,
		RequireHttpsEnabled:          true,
		RequireHttpsMode:             modeEnforce,
		OutboundTrustEnabled:         true,
		OutboundTrustMode:            modeEnforce,
		StartupSkillScan:             true,

		// Collab guard defaults: defense on but in observe mode (safe default —
		// logs violations without blocking Redis Stream tool calls). Sub-rules
		// also default to observe. Zero teamId means the defense is inert
		// until a policy is dispatched.
		CollabGuardEnabled:          true,
		CollabGuardMode:             modeObserve,
		CollabIdentityMode:          modeObserve,
		CollabSchemaMode:            modeObserve,
		CollabQuotaMode:             modeObserve,
		CollabApprovalMode:          modeObserve,
		CollabXaddRps:               5,
		CollabXaddWindowSecs:         1,
		CollabStreamMaxLen:           1000,
		CollabMuteOnAnomaly:         true,
		CollabAuditReplay:            true,
		CollabApprovalThreshold:     85,
	}

	pathSet := map[string]struct{}{}
	skillSet := map[string]struct{}{}
	pluginSet := map[string]struct{}{}

	disabledURF := map[string]struct{}{}
	observeURF := map[string]struct{}{}
	disabledTRF := map[string]struct{}{}
	observeTRF := map[string]struct{}{}

	for _, r := range rules {
		switch r.Kind {
		case policy.KindDefenseToggle:
			applyDefenseToggle(&cfg, r)
		case policy.KindUserRiskFlag:
			applyFlagRule(r, "urf.", disabledURF, observeURF)
		case policy.KindToolResultFlag:
			applyFlagRule(r, "trf.", disabledTRF, observeTRF)
		case policy.KindProtectedPath:
			if p := normalizedPattern(r); p != "" {
				pathSet[p] = struct{}{}
			}
		case policy.KindProtectedSkill:
			if p := normalizedPattern(r); p != "" {
				skillSet[p] = struct{}{}
			}
		case policy.KindProtectedPlugin:
			if p := normalizedPattern(r); p != "" {
				pluginSet[p] = struct{}{}
			}
		case policy.KindCollabPolicy:
			applyCollabPolicy(&cfg, r)
		}
	}

	cfg.ProtectedPaths = sortedKeys(pathSet)
	cfg.ProtectedSkills = sortedKeys(skillSet)
	cfg.ProtectedPlugins = sortedKeys(pluginSet)
	cfg.DisabledUserRiskFlags = sortedKeys(disabledURF)
	cfg.ObserveOnlyUserRiskFlags = sortedKeys(observeURF)
	cfg.DisabledToolResultFlags = sortedKeys(disabledTRF)
	cfg.ObserveOnlyToolResultFlags = sortedKeys(observeTRF)

	encoded, err := json.Marshal(cfg)
	if err != nil {
		return Bundle{}, err
	}
	sum := sha256.Sum256(encoded)

	return Bundle{
		Revision:   revision,
		Sha256:     hex.EncodeToString(sum[:]),
		Source:     "secplane.policy",
		UserConfig: cfg,
	}, nil
}

func applyDefenseToggle(cfg *UserConfig, r policy.Rule) {
	name := strings.TrimPrefix(r.RuleID, "defense.")
	enabled := r.IsEnabled && r.Mode != policy.ModeOff
	mode := normalizeMode(r.Mode)
	if !enabled {
		mode = modeOff
	}
	switch name {
	case "selfProtection":
		cfg.SelfProtectionEnabled = enabled
		cfg.SelfProtectionMode = mode
	case "commandBlock":
		cfg.CommandBlockEnabled = enabled
		cfg.CommandBlockMode = mode
	case "encodingGuard":
		cfg.EncodingGuardEnabled = enabled
		cfg.EncodingGuardMode = mode
	case "scriptProvenanceGuard":
		cfg.ScriptProvenanceGuardEnabled = enabled
		cfg.ScriptProvenanceGuardMode = mode
	case "memoryGuard":
		cfg.MemoryGuardEnabled = enabled
		cfg.MemoryGuardMode = mode
	case "userRiskScan":
		cfg.UserRiskScanEnabled = enabled
	case "skillScan":
		cfg.SkillScanEnabled = enabled
	case "toolResultScan":
		cfg.ToolResultScanEnabled = enabled
	case "outputRedaction":
		cfg.OutputRedactionEnabled = enabled
	case "promptGuard":
		cfg.PromptGuardEnabled = enabled
	case "loopGuard":
		cfg.LoopGuardEnabled = enabled
		cfg.LoopGuardMode = mode
	case "exfiltrationGuard":
		cfg.ExfiltrationGuardEnabled = enabled
		cfg.ExfiltrationGuardMode = mode
	case "toolCallEnforcement":
		cfg.ToolCallEnforcementEnabled = enabled
	case "dispatchGuard":
		cfg.DispatchGuardEnabled = enabled
		cfg.DispatchGuardMode = mode
	case "requireHttps":
		cfg.RequireHttpsEnabled = enabled
		cfg.RequireHttpsMode = mode
	case "outboundTrust":
		cfg.OutboundTrustEnabled = enabled
		cfg.OutboundTrustMode = mode
	}
}

// applyFlagRule classifies a flag rule into the disabled or observe-only
// set. Enforce mode (the default) leaves the flag out of both sets so
// ClawAegis treats it with full enforcement.
func applyFlagRule(r policy.Rule, prefix string, disabled, observe map[string]struct{}) {
	flag := strings.TrimPrefix(r.RuleID, prefix)
	if flag == "" {
		return
	}
	if !r.IsEnabled || r.Mode == policy.ModeOff {
		disabled[flag] = struct{}{}
		return
	}
	if r.Mode == policy.ModeObserve {
		observe[flag] = struct{}{}
	}
}

func normalizedPattern(r policy.Rule) string {
	if !r.IsEnabled || r.Mode == policy.ModeOff {
		return ""
	}
	return strings.TrimSpace(r.Pattern)
}

// applyCollabPolicy parses the JSON policy stored in r.Pattern and maps it
// onto UserConfig.CollabGuard* fields. The master CollabGuardMode follows
// r.Mode (off/observe/enforce); sub-rules (identity/schema/quota/approval)
// get their own mode from the JSON payload so operators can tune each rule
// independently. Missing fields fall back to safe observe defaults.
func applyCollabPolicy(cfg *UserConfig, r policy.Rule) {
	if !r.IsEnabled || r.Mode == policy.ModeOff {
		cfg.CollabGuardEnabled = false
		cfg.CollabGuardMode = modeOff
		return
	}
	cfg.CollabGuardEnabled = true
	cfg.CollabGuardMode = normalizeMode(r.Mode)

	payload := policy.CollabPolicyPayload{}
	if strings.TrimSpace(r.Pattern) != "" {
		if err := json.Unmarshal([]byte(r.Pattern), &payload); err != nil {
			// Malformed JSON — keep defaults, do not wipe config.
			return
		}
	}
	cfg.CollabTeamId = payload.TeamId
	cfg.CollabIdentityMode = normalizeCollabSubMode(payload.IdentityMode, modeObserve)
	cfg.CollabSchemaMode = normalizeCollabSubMode(payload.SchemaMode, modeObserve)
	cfg.CollabQuotaMode = normalizeCollabSubMode(payload.QuotaMode, modeObserve)
	cfg.CollabApprovalMode = normalizeCollabSubMode(payload.ApprovalMode, modeObserve)
	if payload.XaddRps > 0 {
		cfg.CollabXaddRps = payload.XaddRps
	}
	if payload.XaddWindowSeconds > 0 {
		cfg.CollabXaddWindowSecs = payload.XaddWindowSeconds
	}
	if payload.StreamMaxLen > 0 {
		cfg.CollabStreamMaxLen = payload.StreamMaxLen
	}
	if payload.ApprovalThreshold > 0 {
		cfg.CollabApprovalThreshold = payload.ApprovalThreshold
	}
	cfg.CollabMuteOnAnomaly = payload.MuteOnAnomaly
	cfg.CollabAuditReplay = payload.AuditReplay
	cfg.CollabRedisAclPreview = payload.RedisAclPreview
}

// normalizeCollabSubMode coerces a frontend RuleMode ("enforce"/"observe"/"off")
// into the canonical short form used by compile.go. Empty falls back to the
// provided default (typically modeObserve for safe rollout).
func normalizeCollabSubMode(in string, fallback string) string {
	switch in {
	case modeEnforce:
		return modeEnforce
	case modeObserve:
		return modeObserve
	case modeOff:
		return modeOff
	case "":
		return fallback
	default:
		return fallback
	}
}

const (
	modeOff     = "off"
	modeObserve = "observe"
	modeEnforce = "enforce"
)

func normalizeMode(m string) string {
	switch m {
	case policy.ModeEnforce:
		return modeEnforce
	case policy.ModeObserve:
		return modeObserve
	default:
		return modeOff
	}
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
