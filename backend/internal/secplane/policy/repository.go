package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/upper/db/v4"
)

// RuleRepository persists secplane_policy_rule rows.
type RuleRepository interface {
	List(kind string) ([]Rule, error)
	ListEnabled(kind string) ([]Rule, error)
	GetByRuleID(ruleID string) (*Rule, error)
	Upsert(rule *Rule) error
	BulkSetEnabled(ruleIDs []string, enabled bool) error
	Delete(ruleID string) error
}

// AlertRepository persists secplane_alert rows.
type AlertRepository interface {
	Insert(alert *Alert) error
	List(filter AlertFilter) ([]Alert, error)
}

// AlertFilter narrows recent-alert queries.
type AlertFilter struct {
	Source   string
	Severity string
	RuleID   string
	Limit    int
}

type ruleRepository struct{ sess db.Session }
type alertRepository struct{ sess db.Session }

// NewRuleRepository wires the rule repository and seeds default prompt_filter
// rules on first use.
func NewRuleRepository(sess db.Session) RuleRepository {
	repo := &ruleRepository{sess: sess}
	repo.seedDefaults()
	return repo
}

// NewAlertRepository wires the alert repository.
func NewAlertRepository(sess db.Session) AlertRepository {
	return &alertRepository{sess: sess}
}

func (r *ruleRepository) List(kind string) ([]Rule, error) {
	var items []Rule
	q := r.sess.Collection("secplane_policy_rule").Find()
	if kind != "" {
		q = r.sess.Collection("secplane_policy_rule").Find(db.Cond{"kind": kind})
	}
	if err := q.OrderBy("sort_order", "rule_id").All(&items); err != nil {
		return nil, fmt.Errorf("failed to list secplane policy rules: %w", err)
	}
	return items, nil
}

func (r *ruleRepository) ListEnabled(kind string) ([]Rule, error) {
	cond := db.Cond{"is_enabled": true}
	if kind != "" {
		cond["kind"] = kind
	}
	var items []Rule
	if err := r.sess.Collection("secplane_policy_rule").Find(cond).OrderBy("sort_order", "rule_id").All(&items); err != nil {
		return nil, fmt.Errorf("failed to list enabled secplane policy rules: %w", err)
	}
	return items, nil
}

func (r *ruleRepository) GetByRuleID(ruleID string) (*Rule, error) {
	var item Rule
	err := r.sess.Collection("secplane_policy_rule").Find(db.Cond{"rule_id": ruleID}).One(&item)
	if err != nil {
		if err == db.ErrNoMoreRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get secplane policy rule: %w", err)
	}
	return &item, nil
}

func (r *ruleRepository) Upsert(rule *Rule) error {
	existing, err := r.GetByRuleID(rule.RuleID)
	if err != nil {
		return err
	}
	now := time.Now()
	if existing == nil {
		rule.CreatedAt = now
		rule.UpdatedAt = now
		res, err := r.sess.Collection("secplane_policy_rule").Insert(rule)
		if err != nil {
			return fmt.Errorf("failed to insert secplane policy rule: %w", err)
		}
		if id, ok := res.ID().(int64); ok {
			rule.ID = int(id)
		}
		return nil
	}

	existing.Kind = rule.Kind
	existing.DisplayName = rule.DisplayName
	existing.Description = rule.Description
	existing.Pattern = rule.Pattern
	existing.Target = rule.Target
	existing.Severity = rule.Severity
	existing.Action = rule.Action
	existing.Mode = rule.Mode
	existing.IsEnabled = rule.IsEnabled
	existing.SortOrder = rule.SortOrder
	existing.Tags = rule.Tags
	existing.UpdatedAt = now
	if err := r.sess.Collection("secplane_policy_rule").Find(db.Cond{"id": existing.ID}).Update(existing); err != nil {
		return fmt.Errorf("failed to update secplane policy rule: %w", err)
	}
	*rule = *existing
	return nil
}

func (r *ruleRepository) BulkSetEnabled(ruleIDs []string, enabled bool) error {
	if len(ruleIDs) == 0 {
		return nil
	}
	_, err := r.sess.SQL().Exec(
		"UPDATE secplane_policy_rule SET is_enabled = ?, updated_at = ? WHERE rule_id IN (?"+commaPlaceholders(len(ruleIDs)-1)+")",
		append([]interface{}{enabled, time.Now()}, stringsToInterfaces(ruleIDs)...)...,
	)
	if err != nil {
		return fmt.Errorf("failed to bulk update secplane policy rule status: %w", err)
	}
	return nil
}

func (r *ruleRepository) Delete(ruleID string) error {
	if err := r.sess.Collection("secplane_policy_rule").Find(db.Cond{"rule_id": ruleID}).Delete(); err != nil {
		return fmt.Errorf("failed to delete secplane policy rule: %w", err)
	}
	return nil
}

// seedDefaults inserts the starter rule set on a fresh database. Existing
// rule_ids are skipped (no overwrite) so operator edits via the admin UI
// survive backend restarts.
func (r *ruleRepository) seedDefaults() {
	// Legacy prompt_filter rules used to seed here via builtInRules() —
	// dropped because compile.go no longer consumes them; their per-flag
	// equivalents live in user_risk_flag / tool_result_flag rules now.
	var seeds []Rule
	seeds = append(seeds, builtInDefenseToggleRules()...)
	seeds = append(seeds, builtInUserRiskFlagRules()...)
	seeds = append(seeds, builtInToolResultFlagRules()...)
	seeds = append(seeds, builtInSecureClawRules()...)
	seeds = append(seeds, builtInSecureClawAuditCheckRules()...)
	seeds = append(seeds, builtInSecureClawHardeningRules()...)
	seeds = append(seeds, builtInSecureClawDangerousCategoryRules()...)
	seeds = append(seeds, builtInSecureClawDangerousPatternRules()...)
	seeds = append(seeds, builtInSecureClawInjectionPatternRules()...)
	seeds = append(seeds, builtInSecureClawPrivacyRuleRules()...)
	seeds = append(seeds, builtInSecureClawIocRules()...)
	for _, item := range seeds {
		existing, err := r.GetByRuleID(item.RuleID)
		if err != nil {
			panic(fmt.Errorf("failed to inspect secplane rule %s: %w", item.RuleID, err))
		}
		if existing != nil {
			continue
		}
		rule := item
		now := time.Now()
		rule.CreatedAt = now
		rule.UpdatedAt = now
		if _, err := r.sess.Collection("secplane_policy_rule").Insert(&rule); err != nil {
			panic(fmt.Errorf("failed to seed secplane rule %s: %w", item.RuleID, err))
		}
	}
}

// builtInDefenseToggleRules seeds one row per ClawAegis defense module so
// the admin UI exposes every guard. is_enabled defaults to true and mode
// to enforce; defenses without a runtime mode still carry mode=enforce as
// a placeholder (compile.go ignores mode for them).
func builtInDefenseToggleRules() []Rule {
	out := make([]Rule, 0, len(AegisDefenseNames))
	for idx, name := range AegisDefenseNames {
		display := AegisDefenseDisplay[name]
		if display == "" {
			display = name
		}
		desc := fmt.Sprintf("控制 ClawAegis 防御模块 %s 是否启用以及运行模式。", name)
		out = append(out, Rule{
			RuleID:      "defense." + name,
			Kind:        KindDefenseToggle,
			DisplayName: display,
			Description: strPtr(desc),
			Pattern:     "",
			Target:      TargetUserInput,
			Severity:    SeverityMedium,
			Action:      ActionObserve,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   100 + idx*10,
		})
	}
	return out
}

// builtInUserRiskFlagRules seeds one row per built-in user_risk flag.
// Disabling a row → flag goes into disabledUserRiskFlags;
// mode=observe → flag goes into observeOnlyUserRiskFlags;
// mode=enforce (default) → flag stays in full enforcement.
func builtInUserRiskFlagRules() []Rule {
	out := make([]Rule, 0, len(AegisUserRiskFlags))
	for idx, flag := range AegisUserRiskFlags {
		display := AegisUserRiskFlagDisplay[flag]
		if display == "" {
			display = flag
		}
		desc := fmt.Sprintf("ClawAegis userRiskScan 内置 flag %q 的三态开关。", flag)
		out = append(out, Rule{
			RuleID:      "urf." + flag,
			Kind:        KindUserRiskFlag,
			DisplayName: display,
			Description: strPtr(desc),
			Pattern:     "",
			Target:      TargetUserInput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   300 + idx*10,
		})
	}
	return out
}

// builtInToolResultFlagRules seeds one row per built-in tool_result flag.
// Same three-state semantics as user_risk_flag but drives
// disabledToolResultFlags / observeOnlyToolResultFlags in user_config.json
// (added to ClawAegis in this work).
func builtInToolResultFlagRules() []Rule {
	out := make([]Rule, 0, len(AegisToolResultFlags))
	for idx, flag := range AegisToolResultFlags {
		display := AegisToolResultFlagDisplay[flag]
		if display == "" {
			display = flag
		}
		desc := fmt.Sprintf("ClawAegis toolResultScan 内置 flag %q 的三态开关。", flag)
		out = append(out, Rule{
			RuleID:      "trf." + flag,
			Kind:        KindToolResultFlag,
			DisplayName: display,
			Description: strPtr(desc),
			Pattern:     "",
			Target:      TargetToolOutput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   500 + idx*10,
		})
	}
	return out
}

func (a *alertRepository) Insert(alert *Alert) error {
	if alert.Ts.IsZero() {
		alert.Ts = time.Now()
	}
	res, err := a.sess.Collection("secplane_alert").Insert(alert)
	if err != nil {
		return fmt.Errorf("failed to insert secplane alert: %w", err)
	}
	if id, ok := res.ID().(int64); ok {
		alert.ID = id
	}
	return nil
}

func (a *alertRepository) List(filter AlertFilter) ([]Alert, error) {
	cond := db.Cond{}
	if filter.Source != "" {
		cond["source"] = filter.Source
	}
	if filter.Severity != "" {
		cond["severity"] = filter.Severity
	}
	if filter.RuleID != "" {
		cond["rule_id"] = filter.RuleID
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var items []Alert
	if err := a.sess.Collection("secplane_alert").Find(cond).OrderBy("-ts").Limit(limit).All(&items); err != nil {
		return nil, fmt.Errorf("failed to list secplane alerts: %w", err)
	}
	return items, nil
}

func commaPlaceholders(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += ",?"
	}
	return out
}

func stringsToInterfaces(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func strPtr(s string) *string { return &s }

// builtInSecureClawAuditCheckRules seeds one row per SC-* audit check.
// All start enabled+enforce (default behavior) — operators can flip to
// observe (record but don't auto-harden) or disabled (skip entirely)
// via the admin UI.
func builtInSecureClawAuditCheckRules() []Rule {
	out := make([]Rule, 0, len(SecureClawAuditCheckDefaults))
	for idx, row := range SecureClawAuditCheckDefaults {
		// rule_id namespace: sc.audit.<SC-XX-NNN>
		out = append(out, Rule{
			RuleID:      "sc.audit." + row.ID,
			Kind:        KindSecureClawAuditCheck,
			DisplayName: row.ID,
			Description: strPtr(row.Title),
			Pattern:     row.Category, // store category as pattern for cheap filtering
			Target:      TargetUserInput,
			Severity:    row.Severity,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   2000 + idx*5,
		})
	}
	return out
}

// builtInSecureClawHardeningRules seeds one row per SC-* hardening fix.
// All disabled by default (autoHarden=false in the seed reinforces this)
// so a fresh deploy never auto-mutates a pod's config. Enable per-fix
// explicitly when an operator has reviewed the change.
func builtInSecureClawHardeningRules() []Rule {
	out := make([]Rule, 0, len(SecureClawHardeningDefaults))
	for idx, row := range SecureClawHardeningDefaults {
		out = append(out, Rule{
			RuleID:      "sc.harden." + row.ID,
			Kind:        KindSecureClawHardening,
			DisplayName: row.ID,
			Description: strPtr(row.Description),
			Pattern:     row.Module, // store module name for grouping
			Target:      TargetUserInput,
			Severity:    "medium",
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   false, // safe default — operator must opt in
			SortOrder:   3000 + idx*5,
		})
	}
	return out
}

// builtInSecureClawRules seeds the SecureClaw plugin config knobs (one
// secplane_policy_rule row per setting). Sort orders 1000+ keep these
// distinct from the aegis kinds (100-700).
func builtInSecureClawRules() []Rule {
	out := make([]Rule, 0, len(SecureClawConfigDefaults))
	for idx, row := range SecureClawConfigDefaults {
		mode := ModeEnforce
		if !row.IsEnabled {
			mode = ModeObserve // off would hide it from default-on heuristics; observe = "value carried but flag off"
		}
		out = append(out, Rule{
			RuleID:      row.RuleID,
			Kind:        KindSecureClawConfig,
			DisplayName: row.Display,
			Description: strPtr(row.Description),
			Pattern:     row.Pattern,
			Target:      TargetUserInput,
			Severity:    row.Severity,
			Action:      row.Action,
			Mode:        mode,
			IsEnabled:   row.IsEnabled,
			SortOrder:   1000 + idx*10,
		})
	}
	return out
}


// sha8 returns first 8 hex chars of SHA-256 of s — used to derive stable
// rule_id slugs for free-form data (regex patterns, IOC values).
func sha8slug(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}

func builtInSecureClawDangerousCategoryRules() []Rule {
	out := make([]Rule, 0, len(SecureClawDangerousCategoryDefaults))
	for idx, row := range SecureClawDangerousCategoryDefaults {
		// Pattern stores both severity and action as a single string so the
		// row schema stays single-column — compile.go parses it back. We
		// also mirror Severity/Action into native columns for UI ergonomics.
		out = append(out, Rule{
			RuleID:      "sc.dc.cat." + row.Key,
			Kind:        KindSecureClawDangerousCategory,
			DisplayName: row.Key,
			Description: strPtr("dangerous-commands.json category"),
			Pattern:     row.Action, // primary control value (block/require_approval/warn)
			Target:      TargetUserInput,
			Severity:    row.Severity,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   4000 + idx*5,
		})
	}
	return out
}

func builtInSecureClawDangerousPatternRules() []Rule {
	out := make([]Rule, 0, len(SecureClawDangerousPatternDefaults))
	for idx, row := range SecureClawDangerousPatternDefaults {
		tags := row.Category
		out = append(out, Rule{
			RuleID:      "sc.dc.pat." + row.Category + "." + sha8slug(row.Pattern),
			Kind:        KindSecureClawDangerousPattern,
			DisplayName: row.Pattern,
			Description: strPtr("dangerous-commands.json pattern under " + row.Category),
			Pattern:     row.Pattern,
			Target:      TargetUserInput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			Tags:        &tags,
			IsEnabled:   true,
			SortOrder:   4500 + idx,
		})
	}
	return out
}

func builtInSecureClawInjectionPatternRules() []Rule {
	out := make([]Rule, 0, len(SecureClawInjectionPatternDefaults))
	for idx, row := range SecureClawInjectionPatternDefaults {
		tags := row.Category
		out = append(out, Rule{
			RuleID:      "sc.ip.pat." + row.Category + "." + sha8slug(row.Pattern),
			Kind:        KindSecureClawInjectionPattern,
			DisplayName: row.Pattern,
			Description: strPtr("injection-patterns.json string under " + row.Category),
			Pattern:     row.Pattern,
			Target:      TargetUserInput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			Tags:        &tags,
			IsEnabled:   true,
			SortOrder:   5500 + idx,
		})
	}
	return out
}

func builtInSecureClawPrivacyRuleRules() []Rule {
	out := make([]Rule, 0, len(SecureClawPrivacyRuleDefaults))
	for idx, row := range SecureClawPrivacyRuleDefaults {
		// Store the fix hint in Description so the UI can show + edit it
		// alongside the regex. Action carries the rewrite/remove/block mode.
		out = append(out, Rule{
			RuleID:      "sc.pr." + row.ID,
			Kind:        KindSecureClawPrivacyRule,
			DisplayName: row.ID,
			Description: strPtr(row.Fix),
			Pattern:     row.Regex,
			Target:      TargetUserInput,
			Severity:    row.Severity,
			Action:      row.Action,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   7000 + idx*5,
		})
	}
	return out
}

func builtInSecureClawIocRules() []Rule {
	out := make([]Rule, 0, len(SecureClawIocDefaults))
	for idx, row := range SecureClawIocDefaults {
		tags := row.Subtype
		out = append(out, Rule{
			RuleID:      "sc.ioc." + row.Subtype + "." + sha8slug(row.Value),
			Kind:        KindSecureClawIoc,
			DisplayName: row.Value,
			Description: strPtr("supply-chain-ioc.json entry under " + row.Subtype),
			Pattern:     row.Value,
			Target:      TargetUserInput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			Tags:        &tags,
			IsEnabled:   true,
			SortOrder:   8000 + idx,
		})
	}
	return out
}
