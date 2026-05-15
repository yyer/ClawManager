package policy

import "time"

const (
	// Kinds of secplane policy rules. Kept open-ended; new kinds can be added
	// without schema changes.
	KindPromptFilter   = "prompt_filter"
	KindToolControl    = "tool_control"
	KindFileProtect    = "file_protect"
	KindNetworkACL     = "network_acl"
	KindProcessControl = "process_control"

	// Extended kinds: each row is one fine-grained ClawAegis switch.
	//   defense_toggle    rule_id="defense.<name>"   → cfg.<Name>Enabled/Mode
	//   user_risk_flag    rule_id="urf.<flagName>"   → disabledUserRiskFlags / observeOnlyUserRiskFlags
	//   tool_result_flag  rule_id="trf.<flagName>"   → disabledToolResultFlags / observeOnlyToolResultFlags
	//   protected_path    rule_id="pp.<sha8(path)>", pattern=absolute path
	//   protected_skill   rule_id="psk.<sha8(name)>", pattern=skill name
	//   protected_plugin  rule_id="ppl.<sha8(name)>", pattern=plugin name
	KindDefenseToggle   = "defense_toggle"
	KindUserRiskFlag    = "user_risk_flag"
	KindToolResultFlag  = "tool_result_flag"
	KindProtectedPath   = "protected_path"
	KindProtectedSkill  = "protected_skill"
	KindProtectedPlugin = "protected_plugin"

	// Targets describe where the rule is evaluated against. For prompt_filter
	// rules, content can come from several upstream sources.
	TargetUserInput  = "user_input"
	TargetRAGResult  = "rag_result"
	TargetWebContent = "web_content"
	TargetEmail      = "email"
	TargetDocument   = "document"
	TargetToolOutput = "tool_output"

	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"

	ActionObserve = "observe"
	ActionRedact  = "redact"
	ActionBlock   = "block"

	ModeEnforce = "enforce"
	ModeObserve = "observe"
	ModeOff     = "off"
)

// Rule is a single secplane policy rule. The kind discriminator lets the
// table host all enforcement primitives (prompt_filter, tool_control, ...).
type Rule struct {
	ID          int       `db:"id,primarykey,autoincrement" json:"id"`
	RuleID      string    `db:"rule_id" json:"rule_id"`
	Kind        string    `db:"kind" json:"kind"`
	DisplayName string    `db:"display_name" json:"display_name"`
	Description *string   `db:"description" json:"description,omitempty"`
	Pattern     string    `db:"pattern" json:"pattern"`
	Target      string    `db:"target" json:"target"`
	Severity    string    `db:"severity" json:"severity"`
	Action      string    `db:"action" json:"action"`
	Mode        string    `db:"mode" json:"mode"`
	IsEnabled   bool      `db:"is_enabled" json:"is_enabled"`
	SortOrder   int       `db:"sort_order" json:"sort_order"`
	Tags        *string   `db:"tags" json:"tags,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

// TableName for upper/db.
func (Rule) TableName() string { return "secplane_policy_rule" }

// AegisDefenseNames lists the 14 ClawAegis defense modules in the order
// the UI surfaces them. Names match the `ClawAegisPluginConfig` field
// stem in ClawAegis/src/config.ts — e.g. "selfProtection" backs
// selfProtectionEnabled (+ selfProtectionMode for the 8 below).
var AegisDefenseNames = []string{
	"selfProtection",
	"commandBlock",
	"encodingGuard",
	"scriptProvenanceGuard",
	"memoryGuard",
	"userRiskScan",
	"skillScan",
	"toolResultScan",
	"outputRedaction",
	"promptGuard",
	"loopGuard",
	"exfiltrationGuard",
	"toolCallEnforcement",
	"dispatchGuard",
}

// AegisDefenseSupportsMode is true for defenses whose enabled state has
// a companion "off"/"observe"/"enforce" mode field in user_config.json.
// The other 6 defenses are boolean-only.
var AegisDefenseSupportsMode = map[string]bool{
	"selfProtection":        true,
	"commandBlock":          true,
	"encodingGuard":         true,
	"scriptProvenanceGuard": true,
	"memoryGuard":           true,
	"loopGuard":             true,
	"exfiltrationGuard":     true,
	"dispatchGuard":         true,
}

// AegisDefenseDisplay is a friendly Chinese label per defense for the UI.
var AegisDefenseDisplay = map[string]string{
	"selfProtection":        "受保护路径访问拦截",
	"commandBlock":          "高危命令拦截",
	"encodingGuard":         "编码/混淆载荷检测",
	"scriptProvenanceGuard": "脚本来源追踪",
	"memoryGuard":           "记忆写入审查",
	"userRiskScan":          "用户输入风险扫描",
	"skillScan":             "Skill 启动扫描",
	"toolResultScan":        "工具结果风险扫描",
	"outputRedaction":       "敏感输出脱敏",
	"promptGuard":           "提示词安全提醒注入",
	"loopGuard":             "工具调用循环熔断",
	"exfiltrationGuard":     "外发链路检测",
	"toolCallEnforcement":   "工具调用强约束",
	"dispatchGuard":         "消息分发拦截",
}

// AegisUserRiskFlags mirrors ClawAegis/src/security-strategies.ts
// USER_RISK_RULES (consumed by detectUserRiskFlags). One flag per row in
// the user_risk_flag rule kind.
var AegisUserRiskFlags = []string{
	"jailbreak-bypass",
	"system-prompt-exfiltration",
	"disable-plugin",
	"plugin-path-access",
	"dangerous-execution-request",
	"sensitive-secret-request",
	"third-party-as-instructions",
}

// AegisToolResultFlags mirrors TOOL_RESULT_RISK_RULES — checked against
// toolResult content and encoded blobs. One flag per row in the
// tool_result_flag rule kind.
var AegisToolResultFlags = []string{
	"role-takeover",
	"policy-bypass",
	"tool-induction",
	"secret-request",
	"exfiltration-request",
	"remote-script-bootstrap",
	"remote-binary-bootstrap",
	"system-prompt-leak",
	"approval-bypass",
	"disable-claw-aegis",
	"high-risk-command",
	"credential-exfiltration",
}

// AegisUserRiskFlagDisplay / AegisToolResultFlagDisplay surface Chinese
// labels in the UI seed.
var AegisUserRiskFlagDisplay = map[string]string{
	"jailbreak-bypass":            "越狱/绕过守护",
	"system-prompt-exfiltration":  "系统提示词窃取",
	"disable-plugin":              "禁用安全插件",
	"plugin-path-access":          "访问插件源码路径",
	"dangerous-execution-request": "高危执行请求",
	"sensitive-secret-request":    "敏感凭据请求",
	"third-party-as-instructions": "第三方内容当指令",
}

var AegisToolResultFlagDisplay = map[string]string{
	"role-takeover":           "角色覆盖",
	"policy-bypass":           "策略绕过",
	"tool-induction":          "工具诱导",
	"secret-request":          "密钥窃取请求",
	"exfiltration-request":    "数据外发请求",
	"remote-script-bootstrap": "远程脚本引导",
	"remote-binary-bootstrap": "远程二进制引导",
	"system-prompt-leak":      "系统提示泄漏",
	"approval-bypass":         "审批流程绕过",
	"disable-claw-aegis":      "禁用 ClawAegis",
	"high-risk-command":       "高危命令",
	"credential-exfiltration": "凭据外发",
}

// Alert is a normalized security event row. Multiple emitters (gateway,
// claw-aegis, secureclaw, ksecure, kubearmor, platform) all land here.
type Alert struct {
	ID         int64     `db:"id,primarykey,autoincrement" json:"id"`
	TraceID    *string   `db:"trace_id" json:"trace_id,omitempty"`
	Source     string    `db:"source" json:"source"`
	RuleID     *string   `db:"rule_id" json:"rule_id,omitempty"`
	RuleName   *string   `db:"rule_name" json:"rule_name,omitempty"`
	Severity   string    `db:"severity" json:"severity"`
	Action     string    `db:"action" json:"action"`
	AgentID    *string   `db:"agent_id" json:"agent_id,omitempty"`
	Subject    *string   `db:"subject" json:"subject,omitempty"`
	Evidence   *string   `db:"evidence" json:"evidence,omitempty"`
	RawPayload *string   `db:"raw_payload" json:"raw_payload,omitempty"`
	Ts         time.Time `db:"ts" json:"ts"`
}

// TableName for upper/db.
func (Alert) TableName() string { return "secplane_alert" }
