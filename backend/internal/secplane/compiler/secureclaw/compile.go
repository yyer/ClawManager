// Package secureclaw compiles secplane policy rules of kind=secureclaw_config
// into a SecureClawConfig JSON payload, ready to be packaged into a SecureClaw
// plugin zip and dispatched via the existing install_skill channel.
//
// Output schema mirrors secureclaw/secureclaw/src/types.ts SecureClawConfig.
// Field names and JSON tags MUST stay byte-identical to what the TS plugin
// reads — changes here pair with a TS-side change and a base zip rebuild.
package secureclaw

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/secplane/policy"
)

// UserConfig is the JSON shape consumed by SecureClaw via user_config.json.
// Mirrors secureclaw/secureclaw/src/types.ts SecureClawConfig. Optional knobs
// are omitempty so a partial push doesn't wipe SecureClaw's internal
// defaults — the TS-side merge logic (mergeUserConfig in
// secureclaw/src/user-config.ts) does a one-level-deep merge on objects.
type UserConfig struct {
	AutoHarden  bool    `json:"autoHarden"`
	FailureMode string  `json:"failureMode,omitempty"` // block_all / safe_mode / read_only
	RiskProfile string  `json:"riskProfile,omitempty"` // strict / standard / permissive
	Cost        CostCfg `json:"cost,omitempty"`

	Monitors   MonitorsCfg   `json:"monitors,omitempty"`
	Memory     MemoryCfg     `json:"memory,omitempty"`
	Skills     SkillsCfg     `json:"skills,omitempty"`
	Network    NetworkCfg    `json:"network,omitempty"`
	Behavioral BehavioralCfg `json:"behavioral,omitempty"`

	// Per-check toggles. disabledAuditChecks: SecureClaw skips the check
	// entirely. observeOnlyAuditChecks: finding is emitted (action=observed)
	// but severity is capped so harden() ignores it. Mirrors the
	// disabledUserRiskFlags / observeOnlyUserRiskFlags pattern in
	// ClawAegis.
	DisabledAuditChecks    []string `json:"disabledAuditChecks,omitempty"`
	ObserveOnlyAuditChecks []string `json:"observeOnlyAuditChecks,omitempty"`

	// DisabledHardenings: hardening fixes whose ID is in this list don't
	// run during harden(). Audit findings with the same ID still emit
	// (independent control via DisabledAuditChecks).
	DisabledHardenings []string `json:"disabledHardenings,omitempty"`

	// SecplaneIngestEnabled is read by the TS reporter; lets the operator
	// kill HTTP ingest centrally without having to redeploy the plugin.
	SecplaneIngestEnabled bool `json:"secplaneIngestEnabled"`
}

// CostCfg drives SecureClaw's cost monitor + circuit breaker.
type CostCfg struct {
	HourlyLimitUsd        float64 `json:"hourlyLimitUsd,omitempty"`
	DailyLimitUsd         float64 `json:"dailyLimitUsd,omitempty"`
	MonthlyLimitUsd       float64 `json:"monthlyLimitUsd,omitempty"`
	CircuitBreakerEnabled bool    `json:"circuitBreakerEnabled,omitempty"`
}

// MonitorsCfg toggles each background monitor. SecureClaw spins these up in
// onGatewayStart; turning one off here skips the start() call entirely so
// no CPU is spent on its scanning loop.
type MonitorsCfg struct {
	Credentials bool `json:"credentials"`
	Memory      bool `json:"memory"`
	Skills      bool `json:"skills"`
	Cost        bool `json:"cost"`
}

// MemoryCfg controls the memory-integrity scanner behavior.
type MemoryCfg struct {
	IntegrityChecks     bool `json:"integrityChecks"`
	PromptInjectionScan bool `json:"promptInjectionScan"`
	QuarantineEnabled   bool `json:"quarantineEnabled"`
	TrustLevels         bool `json:"trustLevels"`
}

// SkillsCfg controls the skill scanner behavior.
type SkillsCfg struct {
	BlockUnaudited  bool `json:"blockUnaudited"`
	ScanOnInstall   bool `json:"scanOnInstall"`
	IocCheckEnabled bool `json:"iocCheckEnabled"`
}

// NetworkCfg controls outbound egress filtering. EgressAllowlist itself is
// not driven by secplane yet — operators manage the list directly in
// openclaw.json. Only the master enable flag is exposed here.
type NetworkCfg struct {
	EgressAllowlistEnabled bool `json:"egressAllowlistEnabled"`
}

// BehavioralCfg controls the behavioral baseline tracker.
type BehavioralCfg struct {
	BaselineEnabled    bool    `json:"baselineEnabled"`
	DeviationThreshold float64 `json:"deviationThreshold,omitempty"`
	WindowMinutes      int     `json:"windowMinutes,omitempty"`
}

// Bundle is the dispatch result shipped via InstanceCommand. Revision +
// Sha256 let the agent perform idempotent applies.
type Bundle struct {
	Revision    string     `json:"revision"`
	Sha256      string     `json:"sha256"`
	GeneratedAt string     `json:"generated_at,omitempty"`
	Source      string     `json:"source"` // "secplane.policy"
	UserConfig  UserConfig `json:"user_config"`
	// SkillConfigs are the 4 rebuilt JSON files from skill/configs/*.json.
	// Keys: dangerous-commands / injection-patterns / privacy-rules /
	// supply-chain-ioc. Values: marshaled JSON bytes. Packaged into the
	// install zip at skill/configs/<key>.json so the SecureClaw skill
	// scripts read operator overrides instead of the bundled defaults.
	SkillConfigs map[string][]byte `json:"-"`
}

// Compile turns the full set of secplane rules into a SecureClaw bundle.
// Non-secureclaw_config kinds are ignored. The mapping below is the only
// place to add a knob — new ones need: model.go SecureClawConfigDefaults
// entry + this switch case + (if needed) a struct field above.
func Compile(rules []policy.Rule, revision string) (Bundle, error) {
	cfg := UserConfig{
		SecplaneIngestEnabled: true,
	}

	disabledAudit := map[string]struct{}{}
	observeAudit := map[string]struct{}{}
	disabledHarden := map[string]struct{}{}

	for _, r := range rules {
		switch r.Kind {
		case policy.KindSecureClawConfig:
			applyRule(&cfg, r)
		case policy.KindSecureClawAuditCheck:
			// rule_id format: sc.audit.SC-XX-NNN — strip the prefix.
			id := strings.TrimPrefix(r.RuleID, "sc.audit.")
			if id == "" {
				continue
			}
			if !r.IsEnabled || r.Mode == policy.ModeOff {
				disabledAudit[id] = struct{}{}
				continue
			}
			if r.Mode == policy.ModeObserve {
				observeAudit[id] = struct{}{}
			}
		case policy.KindSecureClawHardening:
			id := strings.TrimPrefix(r.RuleID, "sc.harden.")
			if id == "" {
				continue
			}
			if !r.IsEnabled || r.Mode == policy.ModeOff {
				disabledHarden[id] = struct{}{}
			}
		}
	}

	cfg.DisabledAuditChecks = sortedKeys(disabledAudit)
	cfg.ObserveOnlyAuditChecks = sortedKeys(observeAudit)
	cfg.DisabledHardenings = sortedKeys(disabledHarden)

	// Rebuild the 4 skill/configs/*.json files from rule rows. Each file's
	// rows are gathered into a fresh JSON document with the same shape the
	// SecureClaw skill scripts already expect; only enabled rows ship.
	skillConfigs, err := buildSkillConfigs(rules)
	if err != nil {
		return Bundle{}, err
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		return Bundle{}, err
	}
	sum := sha256.Sum256(encoded)
	return Bundle{
		Revision:     revision,
		Sha256:       hex.EncodeToString(sum[:]),
		Source:       "secplane.policy",
		UserConfig:   cfg,
		SkillConfigs: skillConfigs,
	}, nil
}

// buildSkillConfigs assembles the 4 skill/configs/*.json files from the
// 6 layer-3 rule kinds. Returns a map of filename → JSON bytes (without
// the .json suffix). Disabled rows are omitted from the output — that's
// the semantic operators expect ("flip off in UI → no longer scanned").
func buildSkillConfigs(rules []policy.Rule) (map[string][]byte, error) {
	// --- dangerous-commands.json ---
	type dangerousCat struct {
		Severity string   `json:"severity"`
		Action   string   `json:"action"`
		Patterns []string `json:"patterns"`
	}
	dangerousCats := map[string]*dangerousCat{}
	for _, r := range rules {
		if r.Kind != policy.KindSecureClawDangerousCategory || !r.IsEnabled {
			continue
		}
		key := strings.TrimPrefix(r.RuleID, "sc.dc.cat.")
		dangerousCats[key] = &dangerousCat{
			Severity: r.Severity,
			Action:   strings.TrimSpace(r.Pattern), // stored in pattern column
			Patterns: []string{},
		}
	}
	for _, r := range rules {
		if r.Kind != policy.KindSecureClawDangerousPattern || !r.IsEnabled {
			continue
		}
		cat := ""
		if r.Tags != nil {
			cat = *r.Tags
		}
		if c, ok := dangerousCats[cat]; ok {
			c.Patterns = append(c.Patterns, r.Pattern)
		}
	}
	// Sort patterns within each category for stable output (and for
	// deterministic sha256 on the dispatch path).
	for _, c := range dangerousCats {
		sort.Strings(c.Patterns)
	}
	dangerous := map[string]interface{}{
		"version":    "2.0.0",
		"owasp_asi":  "ASI02,ASI05",
		"categories": dangerousCats,
	}
	dangerousJSON, err := json.MarshalIndent(dangerous, "", "  ")
	if err != nil {
		return nil, err
	}

	// --- injection-patterns.json ---
	injection := map[string][]string{}
	for _, r := range rules {
		if r.Kind != policy.KindSecureClawInjectionPattern || !r.IsEnabled {
			continue
		}
		cat := ""
		if r.Tags != nil {
			cat = *r.Tags
		}
		injection[cat] = append(injection[cat], r.Pattern)
	}
	for _, v := range injection {
		sort.Strings(v)
	}
	injectionDoc := map[string]interface{}{
		"version":   "2.0.0",
		"owasp_asi": "ASI01",
		"patterns":  injection,
	}
	injectionJSON, err := json.MarshalIndent(injectionDoc, "", "  ")
	if err != nil {
		return nil, err
	}

	// --- privacy-rules.json ---
	type privacyRule struct {
		ID       string `json:"id"`
		Regex    string `json:"regex"`
		Severity string `json:"severity"`
		Action   string `json:"action"`
		Fix      string `json:"fix,omitempty"`
	}
	var privacyRules []privacyRule
	for _, r := range rules {
		if r.Kind != policy.KindSecureClawPrivacyRule || !r.IsEnabled {
			continue
		}
		fix := ""
		if r.Description != nil {
			fix = *r.Description
		}
		privacyRules = append(privacyRules, privacyRule{
			ID:       strings.TrimPrefix(r.RuleID, "sc.pr."),
			Regex:    r.Pattern,
			Severity: r.Severity,
			Action:   r.Action,
			Fix:      fix,
		})
	}
	sort.Slice(privacyRules, func(i, j int) bool { return privacyRules[i].ID < privacyRules[j].ID })
	privacyDoc := map[string]interface{}{
		"version":     "2.0.0",
		"owasp_asi":   "ASI09",
		"description": "PII patterns checked by check-privacy.sh — secplane-driven overrides",
		"rules":       privacyRules,
	}
	privacyJSON, err := json.MarshalIndent(privacyDoc, "", "  ")
	if err != nil {
		return nil, err
	}

	// --- supply-chain-ioc.json ---
	iocBuckets := map[string][]string{
		"suspicious_skill_pattern": {},
		"c2_server":                {},
		"clawhavoc_name":           {},
		"clawhavoc_malware":        {},
		"malicious_domain":         {},
		"infostealer_target":       {},
	}
	for _, r := range rules {
		if r.Kind != policy.KindSecureClawIoc || !r.IsEnabled {
			continue
		}
		sub := ""
		if r.Tags != nil {
			sub = *r.Tags
		}
		if _, ok := iocBuckets[sub]; ok {
			iocBuckets[sub] = append(iocBuckets[sub], r.Pattern)
		}
	}
	for k := range iocBuckets {
		sort.Strings(iocBuckets[k])
	}
	iocDoc := map[string]interface{}{
		"version":                   "2.0.0",
		"owasp_asi":                 "ASI04",
		"suspicious_skill_patterns": iocBuckets["suspicious_skill_pattern"],
		"clawhavoc": map[string]interface{}{
			"c2_servers":    iocBuckets["c2_server"],
			"name_patterns": iocBuckets["clawhavoc_name"],
			"malware":       iocBuckets["clawhavoc_malware"],
		},
		"malicious_domains":   iocBuckets["malicious_domain"],
		"infostealer_targets": iocBuckets["infostealer_target"],
	}
	iocJSON, err := json.MarshalIndent(iocDoc, "", "  ")
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		"dangerous-commands": dangerousJSON,
		"injection-patterns": injectionJSON,
		"privacy-rules":      privacyJSON,
		"supply-chain-ioc":   iocJSON,
	}, nil
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func applyRule(cfg *UserConfig, r policy.Rule) {
	value := strings.TrimSpace(r.Pattern)
	switch r.RuleID {
	case "sc.autoHarden":
		// is_enabled=true → autoHarden=true; semantics: the toggle IS the value.
		cfg.AutoHarden = r.IsEnabled
	case "sc.failureMode":
		if r.IsEnabled && value != "" {
			cfg.FailureMode = value
		}
	case "sc.riskProfile":
		if r.IsEnabled && value != "" {
			cfg.RiskProfile = value
		}
	case "sc.cost.circuitBreakerEnabled":
		cfg.Cost.CircuitBreakerEnabled = r.IsEnabled
	case "sc.cost.hourlyLimitUsd":
		if r.IsEnabled {
			if v, err := strconv.ParseFloat(value, 64); err == nil {
				cfg.Cost.HourlyLimitUsd = v
			}
		}
	case "sc.cost.dailyLimitUsd":
		if r.IsEnabled {
			if v, err := strconv.ParseFloat(value, 64); err == nil {
				cfg.Cost.DailyLimitUsd = v
			}
		}
	case "sc.cost.monthlyLimitUsd":
		if r.IsEnabled {
			if v, err := strconv.ParseFloat(value, 64); err == nil {
				cfg.Cost.MonthlyLimitUsd = v
			}
		}

	// monitors group — boolean toggles
	case "sc.monitors.credentials":
		cfg.Monitors.Credentials = r.IsEnabled
	case "sc.monitors.memory":
		cfg.Monitors.Memory = r.IsEnabled
	case "sc.monitors.skills":
		cfg.Monitors.Skills = r.IsEnabled
	case "sc.monitors.cost":
		cfg.Monitors.Cost = r.IsEnabled

	// memory group — boolean toggles
	case "sc.memory.integrityChecks":
		cfg.Memory.IntegrityChecks = r.IsEnabled
	case "sc.memory.promptInjectionScan":
		cfg.Memory.PromptInjectionScan = r.IsEnabled
	case "sc.memory.quarantineEnabled":
		cfg.Memory.QuarantineEnabled = r.IsEnabled
	case "sc.memory.trustLevels":
		cfg.Memory.TrustLevels = r.IsEnabled

	// skills group — boolean toggles
	case "sc.skills.blockUnaudited":
		cfg.Skills.BlockUnaudited = r.IsEnabled
	case "sc.skills.scanOnInstall":
		cfg.Skills.ScanOnInstall = r.IsEnabled
	case "sc.skills.iocCheckEnabled":
		cfg.Skills.IocCheckEnabled = r.IsEnabled

	// network group — only master toggle for now; allowlist list stays in
	// openclaw.json until a list-editor UI lands for protected_path-style
	// rules.
	case "sc.network.egressAllowlistEnabled":
		cfg.Network.EgressAllowlistEnabled = r.IsEnabled

	// behavioral group — bool + 2 numerics
	case "sc.behavioral.baselineEnabled":
		cfg.Behavioral.BaselineEnabled = r.IsEnabled
	case "sc.behavioral.deviationThreshold":
		if r.IsEnabled {
			if v, err := strconv.ParseFloat(value, 64); err == nil {
				cfg.Behavioral.DeviationThreshold = v
			}
		}
	case "sc.behavioral.windowMinutes":
		if r.IsEnabled {
			if v, err := strconv.Atoi(value); err == nil {
				cfg.Behavioral.WindowMinutes = v
			}
		}
	}
}
