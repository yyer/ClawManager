package policy

import (
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
	seeds := builtInRules()
	seeds = append(seeds, builtInDefenseToggleRules()...)
	seeds = append(seeds, builtInUserRiskFlagRules()...)
	seeds = append(seeds, builtInToolResultFlagRules()...)
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

// builtInRules is the seed list for FR-01 prompt_filter rules. Patterns are
// deliberately conservative — operators can refine via the admin UI.
func builtInRules() []Rule {
	return []Rule{
		{
			RuleID:      "prompt_injection_ignore_previous",
			Kind:        KindPromptFilter,
			DisplayName: "提示词注入：忽略前文指令",
			Description: strPtr("检测要求模型忽略/忘记之前指令的常见注入语句。"),
			Pattern:     `(?i)(ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above)\s+(?:instructions|prompts)|忽略(?:以上|之前|前面)?(?:所有)?(?:指令|提示))`,
			Target:      TargetUserInput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   10,
		},
		{
			RuleID:      "prompt_injection_role_override",
			Kind:        KindPromptFilter,
			DisplayName: "提示词注入：角色覆盖",
			Description: strPtr("检测试图覆盖系统角色或冒充开发者/管理员的语句。"),
			Pattern:     `(?i)(you are now|act as|pretend to be|从现在起你是|扮演)\s*(?:DAN|developer|admin|root|system|管理员|开发者)`,
			Target:      TargetUserInput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   20,
		},
		{
			RuleID:      "jailbreak_dan",
			Kind:        KindPromptFilter,
			DisplayName: "越狱：DAN/无限制模式",
			Description: strPtr("检测 DAN/Jailbreak/不受限模式之类越狱套路。"),
			Pattern:     `(?i)\b(DAN mode|do anything now|jailbreak|越狱|无限制模式|无规则模式)\b`,
			Target:      TargetUserInput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   30,
		},
		{
			RuleID:      "system_prompt_extraction",
			Kind:        KindPromptFilter,
			DisplayName: "系统提示词窃取",
			Description: strPtr("检测意图获取/泄露系统提示词、初始指令的请求。"),
			Pattern:     `(?i)(reveal|show|print|leak|repeat|输出|展示|打印)\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|initial\s+instructions?|系统提示(词)?|初始指令)`,
			Target:      TargetUserInput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   40,
		},
		{
			RuleID:      "encoded_payload_marker",
			Kind:        KindPromptFilter,
			DisplayName: "编码载荷：base64/hex 长串",
			Description: strPtr("检测疑似编码后的注入载荷（长 base64/hex 字符串）。"),
			Pattern:     `(?i)\b(?:[A-Za-z0-9+/]{120,}={0,2}|[a-f0-9]{160,})\b`,
			Target:      TargetUserInput,
			Severity:    SeverityMedium,
			Action:      ActionObserve,
			Mode:        ModeObserve,
			IsEnabled:   true,
			SortOrder:   50,
		},
		{
			RuleID:      "tool_misuse_shell_pipe",
			Kind:        KindPromptFilter,
			DisplayName: "高危工具诱导：curl|sh / wget|sh",
			Description: strPtr("检测要求 Agent 通过 pipe-to-shell 方式执行远端脚本。"),
			Pattern:     `(?i)(curl|wget)\s+[^|]+\|\s*(bash|sh|zsh)`,
			Target:      TargetUserInput,
			Severity:    SeverityHigh,
			Action:      ActionBlock,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   60,
		},
		{
			RuleID:      "rag_external_instruction",
			Kind:        KindPromptFilter,
			DisplayName: "RAG/外部内容注入",
			Description: strPtr("检测从 RAG/网页/邮件来源混入的高优先级伪造指令。"),
			Pattern:     `(?i)(\[\[\s*system\s*\]\]|<!--\s*system:|^\s*###\s*new\s+instructions)`,
			Target:      TargetRAGResult,
			Severity:    SeverityMedium,
			Action:      ActionRedact,
			Mode:        ModeEnforce,
			IsEnabled:   true,
			SortOrder:   70,
		},
	}
}
