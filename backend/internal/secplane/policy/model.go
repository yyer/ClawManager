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

	// SecureClaw plugin configuration. Each row is one knob in
	// secureclaw/secureclaw/src/types.ts SecureClawConfig. rule_id encodes the
	// dotted path; pattern carries the value as string; is_enabled gates
	// whether the value is shipped at all (an unchecked optional knob lets
	// SecureClaw use its built-in default).
	KindSecureClawConfig = "secureclaw_config"

	// SecureClaw audit check toggle. One row per SC-* audit check defined in
	// secureclaw/src/auditor.ts. Three-state semantics like user_risk_flag:
	//   is_enabled=false  → disabledAuditChecks (SecureClaw skips entirely)
	//   mode=observe      → observeOnlyAuditChecks (finding emitted but
	//                       severity capped at low so auto-harden ignores)
	//   default           → full enforcement
	KindSecureClawAuditCheck = "secureclaw_audit_check"

	// SecureClaw hardening fix toggle. Shares SC-* namespace with audit
	// checks but lives in its own kind row — disabling here only stops the
	// fix from running during harden(), the audit check still emits the
	// finding (use KindSecureClawAuditCheck to suppress the finding).
	KindSecureClawHardening = "secureclaw_hardening"

	// SecureClaw skill-layer data files. These 4 JSON files live in
	// secureclaw/skill/configs/ and are consumed by skill/scripts/*.sh.
	// secplane mirrors them as rule rows so the admin UI can edit
	// detection rules (regex / severity / action / threat intel lists)
	// without touching the plugin source. compile.go reconstructs the
	// 4 JSON files from these rows and packages them into the install
	// zip at the original paths.
	KindSecureClawDangerousCategory = "secureclaw_dangerous_cat" // 7 categories with severity+action
	KindSecureClawDangerousPattern  = "secureclaw_dangerous_pat" // ~35 regex patterns (tags = category)
	KindSecureClawInjectionPattern  = "secureclaw_injection_pat" // ~65 strings (tags = category)
	KindSecureClawPrivacyRule       = "secureclaw_privacy_rule"  // 14 PII rules with regex/severity/action/fix
	KindSecureClawIoc               = "secureclaw_ioc"           // ~20 IOC entries (tags = subtype)

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
	"requireHttps",
	"outboundTrust",
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
	"requireHttps":          true,
	"outboundTrust":         true,
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
	"requireHttps":          "强制 HTTPS 出站",
	"outboundTrust":         "出站可信端点白名单",
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

// SecureClawConfigRow describes one knob seeded into secplane_policy_rule
// for the SecureClaw plugin. order: stable UI sort + seed insertion order.
type SecureClawConfigRow struct {
	RuleID      string
	Display     string
	Description string
	Pattern     string // default value as string
	IsEnabled   bool   // default "ship this knob?"
	Severity    string
	Action      string
}

// SecureClawConfigDefaults is the canonical seed for kind=secureclaw_config.
// autoHarden defaults to FALSE per the design decision: SecureClaw's harden
// step writes real files (changes openclaw.json, locks sockets), and we
// don't want a pod to auto-mutate itself just because the plugin loaded.
// Operators must explicitly flip this on if they want harden-on-start.
var SecureClawConfigDefaults = []SecureClawConfigRow{
	{
		RuleID:      "sc.autoHarden",
		Display:     "网关启动时自动 harden",
		Description: "启用后插件会在 onGatewayStart 自动修改 openclaw.json / 锁权限 / 改 socket。生产环境慎开。",
		Pattern:     "",
		IsEnabled:   false,
		Severity:    "high",
		Action:      "block",
	},
	{
		RuleID:      "sc.failureMode",
		Display:     "失败降级模式",
		Description: "block_all (默认, 全部拦截) / safe_mode (只允许读) / read_only (只允许 ls/cat/git status)",
		Pattern:     "block_all",
		IsEnabled:   true,
		Severity:    "medium",
		Action:      "block",
	},
	{
		RuleID:      "sc.riskProfile",
		Display:     "运行风险等级",
		Description: "strict / standard / permissive — 影响 SecureClaw 默认审批严格度",
		Pattern:     "standard",
		IsEnabled:   true,
		Severity:    "medium",
		Action:      "observe",
	},
	{
		RuleID:      "sc.cost.circuitBreakerEnabled",
		Display:     "成本熔断器",
		Description: "超过下面任意一个 cost 上限时自动暂停 session",
		Pattern:     "",
		IsEnabled:   true,
		Severity:    "medium",
		Action:      "block",
	},
	{
		RuleID:      "sc.cost.hourlyLimitUsd",
		Display:     "每小时成本上限 (USD)",
		Description: "数值字符串, 例如 10.0",
		Pattern:     "10.0",
		IsEnabled:   false,
		Severity:    "low",
		Action:      "observe",
	},
	{
		RuleID:      "sc.cost.dailyLimitUsd",
		Display:     "每天成本上限 (USD)",
		Description: "数值字符串, 例如 100.0",
		Pattern:     "100.0",
		IsEnabled:   false,
		Severity:    "low",
		Action:      "observe",
	},
	{
		RuleID:      "sc.cost.monthlyLimitUsd",
		Display:     "每月成本上限 (USD)",
		Description: "数值字符串, 例如 2000.0",
		Pattern:     "2000.0",
		IsEnabled:   false,
		Severity:    "low",
		Action:      "observe",
	},
	// ---------- monitors: 后台监视器开关 ----------
	{RuleID: "sc.monitors.credentials", Display: "凭据泄漏监视器", Description: "扫描 stateDir 内潜在的 API key / 私钥 / cookie 文件", IsEnabled: true, Severity: "high", Action: "block"},
	{RuleID: "sc.monitors.memory", Display: "记忆完整性监视器", Description: "监视 memory_store / MEMORY.md / SOUL.md 的非预期写入", IsEnabled: true, Severity: "high", Action: "block"},
	{RuleID: "sc.monitors.skills", Display: "Skill 扫描监视器", Description: "扫描 ~/.openclaw/skills 与 workspace/skills 的可疑安装", IsEnabled: true, Severity: "medium", Action: "observe"},
	{RuleID: "sc.monitors.cost", Display: "Cost 监视器", Description: "采集 LLM 调用 token / cost, 是 cost.* 上限的前提", IsEnabled: true, Severity: "low", Action: "observe"},
	// ---------- memory: 记忆审查细项 ----------
	{RuleID: "sc.memory.integrityChecks", Display: "记忆完整性校验", Description: "对受保护的记忆文件做 hash baseline 比对", IsEnabled: true, Severity: "high", Action: "block"},
	{RuleID: "sc.memory.promptInjectionScan", Display: "记忆注入扫描", Description: "在读取记忆内容时扫描 prompt 注入 pattern", IsEnabled: true, Severity: "high", Action: "block"},
	{RuleID: "sc.memory.quarantineEnabled", Display: "可疑记忆隔离", Description: "命中风险时把记忆条目移到 quarantine 目录而不是直接读入 context", IsEnabled: false, Severity: "medium", Action: "block"},
	{RuleID: "sc.memory.trustLevels", Display: "记忆来源信任分级", Description: "按来源标注 trusted/unverified/external, 影响是否注入到 LLM context", IsEnabled: true, Severity: "medium", Action: "observe"},
	// ---------- skills: skill 安装审计 ----------
	{RuleID: "sc.skills.blockUnaudited", Display: "拦截未审计 Skill", Description: "未通过 skill scan 的 skill 不允许安装/启用", IsEnabled: false, Severity: "high", Action: "block"},
	{RuleID: "sc.skills.scanOnInstall", Display: "安装时扫描", Description: "新 skill 安装前自动跑 quick-audit, 高危直接拒绝", IsEnabled: true, Severity: "high", Action: "block"},
	{RuleID: "sc.skills.iocCheckEnabled", Display: "IOC 比对", Description: "对照 ioc/indicators.json 的恶意 hash / 域名做匹配", IsEnabled: true, Severity: "high", Action: "block"},
	// ---------- network: 出口控制 ----------
	{RuleID: "sc.network.egressAllowlistEnabled", Display: "启用出口白名单", Description: "开启后只有 SecureClaw allowlist 内的域名能被工具调用访问。当前 allowlist 列表在 openclaw.json 维护; secplane 暂不下发列表本身。", IsEnabled: false, Severity: "high", Action: "block"},
	// ---------- behavioral: 行为基线 ----------
	{RuleID: "sc.behavioral.baselineEnabled", Display: "启用行为基线", Description: "累积 tool 调用频率, 用于异常检测", IsEnabled: true, Severity: "medium", Action: "observe"},
	{RuleID: "sc.behavioral.deviationThreshold", Display: "行为偏差阈值", Description: "0-1 之间的小数, 超过阈值触发 deviation 告警", Pattern: "0.5", IsEnabled: true, Severity: "low", Action: "observe"},
	{RuleID: "sc.behavioral.windowMinutes", Display: "基线窗口 (分钟)", Description: "基线统计的滑动窗口长度", Pattern: "60", IsEnabled: true, Severity: "low", Action: "observe"},
}

// SecureClawCheckRow describes one SC-* audit check from
// secureclaw/src/auditor.ts. Seeded as kind=secureclaw_audit_check rows so
// operators can toggle individual checks via the admin UI.
type SecureClawCheckRow struct {
	ID       string
	Category string
	Severity string // low / medium / high (CRITICAL → high, INFO → low)
	Title    string
}

// SecureClawHardeningRow describes one SC-* hardening fix from
// secureclaw/src/hardening/*.ts. Same SC-* namespace as audit checks but
// these toggle the auto-fix step independently — disabling here keeps the
// finding visible but stops the fix from running.
type SecureClawHardeningRow struct {
	ID          string
	Module      string // gateway-hardening / credential-hardening / config-hardening / docker-hardening / network-hardening
	Description string
}

// SecureClawAuditCheckDefaults — the 56 SC-* audit checks defined in
// secureclaw/src/auditor.ts (snapshotted; re-run scripts/sync-checks.py to
// refresh when the plugin adds new ones).
var SecureClawAuditCheckDefaults = []SecureClawCheckRow{
	{ID: "SC-AC-001", Category: "access-control", Severity: "high", Title: "Channel \"${ch.name}\" has open DM policy"},
	{ID: "SC-AC-002", Category: "access-control", Severity: "high", Title: "Channel \"${ch.name}\" has open group policy"},
	{ID: "SC-AC-003", Category: "access-control", Severity: "medium", Title: "Channel \"${ch.name}\" has wildcard in allowlist"},
	{ID: "SC-AC-004", Category: "access-control", Severity: "high", Title: "Channel \"${ch.name}\" has no pairing and no allowlist"},
	{ID: "SC-AC-005", Category: "access-control", Severity: "medium", Title: "Session DM scope not isolated per user"},
	{ID: "SC-COST-001", Category: "cost", Severity: "medium", Title: "No LLM provider spending limits configured"},
	{ID: "SC-COST-002", Category: "cost", Severity: "low", Title: "API cost usage detected in session logs"},
	{ID: "SC-COST-003", Category: "cost", Severity: "high", Title: "High-frequency agent invocation detected"},
	{ID: "SC-COST-004", Category: "cost", Severity: "high", Title: "Daily cost threshold exceeded"},
	{ID: "SC-CRED-001", Category: "credentials", Severity: "high", Title: "State directory has excessive permissions"},
	{ID: "SC-CRED-002", Category: "credentials", Severity: "high", Title: "Config file has excessive permissions"},
	{ID: "SC-CRED-003", Category: "credentials", Severity: "high", Title: "Plaintext API keys in .env file"},
	{ID: "SC-CRED-004", Category: "credentials", Severity: "high", Title: "Credential file \"${file}\" has excessive permissions"},
	{ID: "SC-CRED-005", Category: "credentials", Severity: "high", Title: "Auth profiles for agent \"${agent}\" have excessive permissions"},
	{ID: "SC-CRED-006", Category: "credentials", Severity: "medium", Title: "OAuth tokens in plaintext in \"${file}\""},
	{ID: "SC-CRED-007", Category: "credentials", Severity: "high", Title: "API keys found in memory file \"${memFile}\""},
	{ID: "SC-CRED-008", Category: "credentials", Severity: "high", Title: "API key found in configuration file"},
	{ID: "SC-CROSS-001", Category: "cross-layer", Severity: "high", Title: "Cross-layer compound attack surface detected"},
	{ID: "SC-CTRL-001", Category: "control-tokens", Severity: "medium", Title: "Default control tokens in use"},
	{ID: "SC-DEGRAD-001", Category: "degradation", Severity: "low", Title: "No graceful degradation mode configured"},
	{ID: "SC-EXEC-001", Category: "execution", Severity: "high", Title: "Execution approvals disabled"},
	{ID: "SC-EXEC-002", Category: "execution", Severity: "high", Title: "Commands execute on host, not in sandbox"},
	{ID: "SC-EXEC-003", Category: "execution", Severity: "medium", Title: "Sandbox mode not set to \"all\""},
	{ID: "SC-EXEC-004", Category: "execution", Severity: "medium", Title: "Docker service \"${svcName}\" not read-only"},
	{ID: "SC-EXEC-005", Category: "execution", Severity: "medium", Title: "Docker service \"${svcName}\" not dropping all capabilities"},
	{ID: "SC-EXEC-006", Category: "execution", Severity: "medium", Title: "Docker service \"${svcName}\" missing no-new-privileges"},
	{ID: "SC-EXEC-007", Category: "execution", Severity: "high", Title: "Docker service \"${svcName}\" on host network"},
	{ID: "SC-GW-001", Category: "gateway", Severity: "high", Title: "Gateway not bound to loopback"},
	{ID: "SC-GW-002", Category: "gateway", Severity: "high", Title: "Gateway authentication disabled"},
	{ID: "SC-GW-003", Category: "gateway", Severity: "medium", Title: "Weak gateway authentication token"},
	{ID: "SC-GW-004", Category: "gateway", Severity: "low", Title: "SC-GW-004"},
	{ID: "SC-GW-005", Category: "gateway", Severity: "low", Title: "SC-GW-005"},
	{ID: "SC-GW-006", Category: "gateway", Severity: "medium", Title: "TLS not enabled on gateway"},
	{ID: "SC-GW-007", Category: "gateway", Severity: "medium", Title: "mDNS broadcasting in full mode"},
	{ID: "SC-GW-008", Category: "gateway", Severity: "high", Title: "Reverse proxy without trustedProxies configuration"},
	{ID: "SC-GW-009", Category: "gateway", Severity: "high", Title: "Device authentication disabled on Control UI"},
	{ID: "SC-GW-010", Category: "gateway", Severity: "medium", Title: "Insecure authentication allowed on Control UI"},
	{ID: "SC-IOC-000", Category: "ioc", Severity: "low", Title: "IOC database not available"},
	{ID: "SC-IOC-001", Category: "ioc", Severity: "high", Title: "Connection to known C2 infrastructure detected"},
	{ID: "SC-IOC-002", Category: "ioc", Severity: "high", Title: "Domain in malicious list \"${dom}\" referenced"},
	{ID: "SC-IOC-003", Category: "ioc", Severity: "high", Title: "Malicious skill hash detected"},
	{ID: "SC-IOC-004", Category: "ioc", Severity: "high", Title: "Potential infostealer artifact detected (macOS)"},
	{ID: "SC-IOC-005", Category: "ioc", Severity: "high", Title: "Potential infostealer artifact detected (Linux)"},
	{ID: "SC-KILL-001", Category: "kill-switch", Severity: "low", Title: "Kill switch is active"},
	{ID: "SC-MEM-001", Category: "memory", Severity: "low", Title: "No agents directory found"},
	{ID: "SC-MEM-002", Category: "memory", Severity: "high", Title: "Prompt injection detected in \"${memFile}\" for agent \"${agent}\""},
	{ID: "SC-MEM-003", Category: "memory", Severity: "medium", Title: "Agent memory file references suspicious patterns"},
	{ID: "SC-MEM-004", Category: "memory", Severity: "medium", Title: "Cross-agent memory leakage possible"},
	{ID: "SC-MEM-005", Category: "memory", Severity: "medium", Title: "Memory file lacks trust-level markers"},
	{ID: "SC-SKILL-001", Category: "supply-chain", Severity: "low", Title: "Skill \"${name}\" lacks origin metadata"},
	{ID: "SC-SKILL-002", Category: "supply-chain", Severity: "high", Title: "Skill \"${name}\" installs from suspicious source"},
	{ID: "SC-SKILL-003", Category: "supply-chain", Severity: "high", Title: "Malicious skill hash detected for \"${name}\""},
	{ID: "SC-SKILL-004", Category: "supply-chain", Severity: "medium", Title: "Skill \"${name}\" has young source repo (potential typosquat)"},
	{ID: "SC-SKILL-005", Category: "supply-chain", Severity: "high", Title: "Skill \"${skill.name}\" matches typosquat pattern"},
	{ID: "SC-SKILL-006", Category: "supply-chain", Severity: "high", Title: "Skill \"${skill.name}\" has dangerous prerequisites"},
	{ID: "SC-TRUST-001", Category: "memory-trust", Severity: "high", Title: "Injected instructions in ${cogFile}"},
}

// SecureClawHardeningDefaults — 5 hardening modules. Module-level toggle
// rather than per-fix because each hardening module's internal action IDs
// are decoupled from the audit finding IDs that surface them; mapping the
// two surfaces would need invasive changes to all 5 modules. Module-level
// matches production needs ("no docker config changes ever" is the
// granularity operators actually want).
var SecureClawHardeningDefaults = []SecureClawHardeningRow{
	{ID: "gateway-hardening", Module: "gateway-hardening", Description: "网关层加固：绑定 loopback、强制 auth token、关闭不安全配置、清理 mDNS 广播"},
	{ID: "credential-hardening", Module: "credential-hardening", Description: "凭据加固：chmod state 目录、扫描 plaintext API key / OAuth token、收紧文件权限"},
	{ID: "config-hardening", Module: "config-hardening", Description: "配置加固：启用 execution approvals、sandbox.mode=all、channel DM policy 限制"},
	{ID: "docker-hardening", Module: "docker-hardening", Description: "Docker 容器加固：read_only / drop capabilities / no-new-privileges / bridge network"},
	{ID: "network-hardening", Module: "network-hardening", Description: "出口网络加固：生成 egress allowlist + C2 blocklist 脚本"},
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
	"disable-claw-aegis":      "禁用 ClawAegisEx",
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

// ----- SecureClaw skill-layer canonical data ------------------------------
// These are the as-shipped contents of skill/configs/*.json in the
// SecureClaw plugin (snapshot of upstream defaults). seedDefaults inserts
// one secplane_policy_rule row per entry so operators can override via UI.

// SecureClawDangerousCatRow drives one category in dangerous-commands.json.
// Severity/Action are category-wide; the patterns under the category live
// in SecureClawDangerousPatRow and reference Key via tags.
type SecureClawDangerousCatRow struct {
	Key      string
	Severity string // critical / high / medium / low
	Action   string // block / require_approval / warn
}

// SecureClawDangerousPatRow drives one regex pattern under a
// dangerous-commands.json category. Category field stored in rule.Tags.
type SecureClawDangerousPatRow struct {
	Category string
	Pattern  string
}

// SecureClawInjectionRow drives one entry in injection-patterns.json.
// Each entry is a literal substring (not regex) — the skill script does
// case-insensitive substring search.
type SecureClawInjectionRow struct {
	Category string
	Pattern  string
}

// SecureClawPrivacyRow drives one rule in privacy-rules.json.
type SecureClawPrivacyRow struct {
	ID       string
	Regex    string
	Severity string // critical / high / medium / low
	Action   string // block / remove / rewrite
	Fix      string // human-readable suggested replacement
}

// SecureClawIocRow drives one entry in supply-chain-ioc.json. Subtype
// selects which JSON array the value lands in:
//   suspicious_skill_pattern  -> suspicious_skill_patterns[]
//   c2_server                 -> clawhavoc.c2_servers[]
//   clawhavoc_name            -> clawhavoc.name_patterns[]
//   clawhavoc_malware         -> clawhavoc.malware[]
//   malicious_domain          -> malicious_domains[]
//   infostealer_target        -> infostealer_targets[]
type SecureClawIocRow struct {
	Subtype string
	Value   string
}

// ----- dangerous-commands.json -----
var SecureClawDangerousCategoryDefaults = []SecureClawDangerousCatRow{
	{Key: "remote_code_execution", Severity: "critical", Action: "block"},
	{Key: "dynamic_execution", Severity: "critical", Action: "block"},
	{Key: "destructive", Severity: "critical", Action: "require_approval"},
	{Key: "permission_escalation", Severity: "high", Action: "require_approval"},
	{Key: "config_modification", Severity: "high", Action: "require_approval"},
	{Key: "deserialization", Severity: "high", Action: "warn"},
	{Key: "data_exfiltration", Severity: "critical", Action: "block"},
}
var SecureClawDangerousPatternDefaults = []SecureClawDangerousPatRow{
	{Category: "remote_code_execution", Pattern: "curl.*\\|.*sh"},
	{Category: "remote_code_execution", Pattern: "curl.*\\|.*bash"},
	{Category: "remote_code_execution", Pattern: "wget.*\\|.*sh"},
	{Category: "remote_code_execution", Pattern: "wget.*\\|.*bash"},
	{Category: "remote_code_execution", Pattern: "curl.*\\|.*python"},
	{Category: "dynamic_execution", Pattern: "eval\\("},
	{Category: "dynamic_execution", Pattern: "exec\\("},
	{Category: "dynamic_execution", Pattern: "Function\\("},
	{Category: "dynamic_execution", Pattern: "subprocess\\.call.*shell.*True"},
	{Category: "dynamic_execution", Pattern: "os\\.system\\("},
	{Category: "dynamic_execution", Pattern: "child_process\\.exec\\("},
	{Category: "destructive", Pattern: "rm\\s+-rf"},
	{Category: "destructive", Pattern: "rm\\s+-r\\s+/"},
	{Category: "destructive", Pattern: "mkfs\\."},
	{Category: "destructive", Pattern: "dd\\s+if="},
	{Category: "destructive", Pattern: "DROP\\s+TABLE"},
	{Category: "destructive", Pattern: "DROP\\s+DATABASE"},
	{Category: "destructive", Pattern: "DELETE\\s+FROM.*WHERE\\s+1"},
	{Category: "destructive", Pattern: "TRUNCATE\\s+TABLE"},
	{Category: "permission_escalation", Pattern: "chmod\\s+777"},
	{Category: "permission_escalation", Pattern: "chmod\\s+-R\\s+777"},
	{Category: "permission_escalation", Pattern: "sudo\\s+"},
	{Category: "config_modification", Pattern: "\\.bashrc"},
	{Category: "config_modification", Pattern: "\\.profile"},
	{Category: "config_modification", Pattern: "\\.zshrc"},
	{Category: "config_modification", Pattern: "crontab"},
	{Category: "config_modification", Pattern: "\\.git/hooks/"},
	{Category: "config_modification", Pattern: "sudoers"},
	{Category: "deserialization", Pattern: "pickle\\.load"},
	{Category: "deserialization", Pattern: "yaml\\.unsafe_load"},
	{Category: "deserialization", Pattern: "unserialize\\("},
	{Category: "data_exfiltration", Pattern: "curl.*-d.*@"},
	{Category: "data_exfiltration", Pattern: "curl.*--data.*@"},
	{Category: "data_exfiltration", Pattern: "curl.*-X\\s+POST.*\\.env"},
	{Category: "data_exfiltration", Pattern: "wget.*--post-file"},
	{Category: "data_exfiltration", Pattern: "nc\\s+-"},
}

var SecureClawInjectionPatternDefaults = []SecureClawInjectionRow{
	{Category: "identity_hijacking", Pattern: "you are now"},
	{Category: "identity_hijacking", Pattern: "your new role"},
	{Category: "identity_hijacking", Pattern: "act as"},
	{Category: "identity_hijacking", Pattern: "pretend to be"},
	{Category: "identity_hijacking", Pattern: "ignore previous instructions"},
	{Category: "identity_hijacking", Pattern: "ignore all instructions"},
	{Category: "identity_hijacking", Pattern: "ignore your instructions"},
	{Category: "identity_hijacking", Pattern: "disregard everything"},
	{Category: "identity_hijacking", Pattern: "disregard your system"},
	{Category: "identity_hijacking", Pattern: "override your"},
	{Category: "identity_hijacking", Pattern: "new system prompt"},
	{Category: "identity_hijacking", Pattern: "forget everything above"},
	{Category: "identity_hijacking", Pattern: "from now on you"},
	{Category: "identity_hijacking", Pattern: "your real purpose"},
	{Category: "identity_hijacking", Pattern: "do not follow your original"},
	{Category: "identity_hijacking", Pattern: "switch to"},
	{Category: "identity_hijacking", Pattern: "enter .* mode"},
	{Category: "action_directives", Pattern: "forward all emails"},
	{Category: "action_directives", Pattern: "forward this to"},
	{Category: "action_directives", Pattern: "send this to"},
	{Category: "action_directives", Pattern: "send a copy to"},
	{Category: "action_directives", Pattern: "share this with"},
	{Category: "action_directives", Pattern: "post this on"},
	{Category: "action_directives", Pattern: "exfiltrate"},
	{Category: "action_directives", Pattern: "download and run"},
	{Category: "action_directives", Pattern: "download and execute"},
	{Category: "action_directives", Pattern: "fetch and execute"},
	{Category: "action_directives", Pattern: "execute this command"},
	{Category: "action_directives", Pattern: "run the following command"},
	{Category: "action_directives", Pattern: "use the .* tool to"},
	{Category: "action_directives", Pattern: "open a connection to"},
	{Category: "action_directives", Pattern: "connect to"},
	{Category: "tool_output_poisoning", Pattern: "now execute"},
	{Category: "tool_output_poisoning", Pattern: "next you should"},
	{Category: "tool_output_poisoning", Pattern: "important: run this"},
	{Category: "tool_output_poisoning", Pattern: "system update required"},
	{Category: "tool_output_poisoning", Pattern: "critical: install"},
	{Category: "tool_output_poisoning", Pattern: "your next action should be"},
	{Category: "tool_output_poisoning", Pattern: "before continuing you must"},
	{Category: "planning_manipulation", Pattern: "skip the verification"},
	{Category: "planning_manipulation", Pattern: "you already checked"},
	{Category: "planning_manipulation", Pattern: "no need to verify"},
	{Category: "planning_manipulation", Pattern: "trust this result"},
	{Category: "planning_manipulation", Pattern: "skip step"},
	{Category: "planning_manipulation", Pattern: "the previous step was wrong"},
	{Category: "planning_manipulation", Pattern: "ignore the error"},
	{Category: "planning_manipulation", Pattern: "override safety"},
	{Category: "config_tampering", Pattern: "update your soul"},
	{Category: "config_tampering", Pattern: "modify your soul"},
	{Category: "config_tampering", Pattern: "add to your soul"},
	{Category: "config_tampering", Pattern: "change your soul"},
	{Category: "config_tampering", Pattern: "update your memory"},
	{Category: "config_tampering", Pattern: "remember this instruction"},
	{Category: "config_tampering", Pattern: "store this permanently"},
	{Category: "config_tampering", Pattern: "save this to your"},
	{Category: "config_tampering", Pattern: "modify your identity"},
	{Category: "config_tampering", Pattern: "modify your tools"},
	{Category: "config_tampering", Pattern: "change your configuration"},
	{Category: "config_tampering", Pattern: "update openclaw.json"},
	{Category: "config_tampering", Pattern: "add to your personality"},
	{Category: "structural_hiding", Pattern: "\\u200b"},
	{Category: "structural_hiding", Pattern: "\\u200c"},
	{Category: "structural_hiding", Pattern: "\\u200d"},
	{Category: "structural_hiding", Pattern: "\\ufeff"},
	{Category: "structural_hiding", Pattern: "\\u2062"},
	{Category: "structural_hiding", Pattern: "\\u2063"},
	{Category: "structural_hiding", Pattern: "base64:"},
	{Category: "structural_hiding", Pattern: "data:text/plain;base64"},
	{Category: "structural_hiding", Pattern: "<!--"},
	{Category: "structural_hiding", Pattern: "display:none"},
	{Category: "structural_hiding", Pattern: "visibility:hidden"},
	{Category: "structural_hiding", Pattern: "font-size:0"},
	{Category: "structural_hiding", Pattern: "color:white"},
	{Category: "structural_hiding", Pattern: "color:#fff"},
	{Category: "structural_hiding", Pattern: "opacity:0"},
	{Category: "social_engineering", Pattern: "the user told you to"},
	{Category: "social_engineering", Pattern: "the owner wants you to"},
	{Category: "social_engineering", Pattern: "the admin says"},
	{Category: "social_engineering", Pattern: "the developer instructed"},
	{Category: "social_engineering", Pattern: "this is urgent act now"},
	{Category: "social_engineering", Pattern: "emergency override"},
	{Category: "social_engineering", Pattern: "do not tell your human"},
	{Category: "social_engineering", Pattern: "do not inform the user"},
	{Category: "social_engineering", Pattern: "do not alert"},
	{Category: "social_engineering", Pattern: "keep this secret"},
	{Category: "social_engineering", Pattern: "keep this between us"},
	{Category: "social_engineering", Pattern: "confidential from your owner"},
	{Category: "social_engineering", Pattern: "there are clues"},
	{Category: "social_engineering", Pattern: "there is a hidden"},
	{Category: "social_engineering", Pattern: "this is a test"},
}

var SecureClawPrivacyRuleDefaults = []SecureClawPrivacyRow{
	{ID: "owner_name", Regex: "my human [A-Z][a-z]+", Severity: "high", Action: "rewrite", Fix: "Use 'my human' without the name"},
	{ID: "ip_address", Regex: "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b", Severity: "critical", Action: "remove", Fix: ""},
	{ID: "internal_path", Regex: "~/\\.[a-zA-Z]+/", Severity: "high", Action: "remove", Fix: ""},
	{ID: "port_exposure", Regex: "(?:port|listening on)\\s+\\d{2,5}", Severity: "high", Action: "remove", Fix: ""},
	{ID: "service_exposure", Regex: "(?:redis|postgres|mysql|mongo|nginx|apache|minio)\\s+(?:on|running|listening|port)", Severity: "critical", Action: "remove", Fix: ""},
	{ID: "ssh_details", Regex: "ssh\\s+(?:login|attempt|key|connect|fail|brute)", Severity: "critical", Action: "remove", Fix: ""},
	{ID: "api_key", Regex: "(?:sk-ant-|sk-proj-|xoxb-|xoxp-|ghp_|gho_|AKIA)\\S+", Severity: "critical", Action: "block", Fix: ""},
	{ID: "location", Regex: "(?:live[sd]? in|based in|located in|from)\\s+[A-Z]", Severity: "medium", Action: "rewrite", Fix: ""},
	{ID: "occupation", Regex: "(?:works? (?:as|at|for)|employed at|studies at|student at)", Severity: "medium", Action: "rewrite", Fix: ""},
	{ID: "family", Regex: "(?:my human'?s? )(?:wife|husband|partner|child|daughter|son|mother|father|sister|brother)\\s+[A-Z]", Severity: "high", Action: "rewrite", Fix: ""},
	{ID: "device", Regex: "(?:pixel|iphone|macbook|mac mini|thinkpad|galaxy|surface)\\s*\\d*", Severity: "medium", Action: "rewrite", Fix: ""},
	{ID: "vpn_tool", Regex: "(?:tailscale|wireguard|zerotier|cloudflare tunnel|ngrok)", Severity: "medium", Action: "rewrite", Fix: ""},
	{ID: "routine", Regex: "(?:every (?:morning|night|day)|daily routine|wakes? up|goes to bed|leaves for)", Severity: "medium", Action: "rewrite", Fix: ""},
	{ID: "religion", Regex: "(?:pray|mosque|church|temple|synagogue|sabbath|ramadan|diwali)", Severity: "high", Action: "rewrite", Fix: ""},
}

var SecureClawIocDefaults = []SecureClawIocRow{
	{Subtype: "suspicious_skill_pattern", Value: "curl.*\\|.*sh"},
	{Subtype: "suspicious_skill_pattern", Value: "wget.*\\|.*bash"},
	{Subtype: "suspicious_skill_pattern", Value: "eval\\("},
	{Subtype: "suspicious_skill_pattern", Value: "exec\\("},
	{Subtype: "suspicious_skill_pattern", Value: "Function\\("},
	{Subtype: "suspicious_skill_pattern", Value: "btoa\\("},
	{Subtype: "suspicious_skill_pattern", Value: "atob\\("},
	{Subtype: "suspicious_skill_pattern", Value: "String\\.fromCharCode"},
	{Subtype: "suspicious_skill_pattern", Value: "\\\\x[0-9a-f]{2}"},
	{Subtype: "suspicious_skill_pattern", Value: "\\$\\(curl"},
	{Subtype: "suspicious_skill_pattern", Value: "fetch\\(.*credentials"},
	{Subtype: "suspicious_skill_pattern", Value: "process\\.env"},
	{Subtype: "suspicious_skill_pattern", Value: "fs\\.readFile.*\\.env"},
	{Subtype: "suspicious_skill_pattern", Value: "osascript.*display dialog"},
	{Subtype: "suspicious_skill_pattern", Value: "xattr.*quarantine"},
	{Subtype: "suspicious_skill_pattern", Value: "ClickFix"},
	{Subtype: "suspicious_skill_pattern", Value: "prerequisite.*install"},
	{Subtype: "suspicious_skill_pattern", Value: "webhook\\.site"},
	{Subtype: "c2_server", Value: "91.92.242.30"},
	{Subtype: "clawhavoc_name", Value: "solana-wallet"},
	{Subtype: "clawhavoc_name", Value: "phantom-tracker"},
	{Subtype: "clawhavoc_name", Value: "polymarket-"},
	{Subtype: "clawhavoc_name", Value: "better-polymarket"},
	{Subtype: "clawhavoc_name", Value: "polymarket-all-in-one"},
	{Subtype: "clawhavoc_name", Value: "clawhub1"},
	{Subtype: "clawhavoc_name", Value: "clawhubb"},
	{Subtype: "clawhavoc_name", Value: "cllawhub"},
	{Subtype: "clawhavoc_name", Value: "clawwhub"},
	{Subtype: "clawhavoc_name", Value: "auto-updater"},
	{Subtype: "clawhavoc_name", Value: "system-security-tool"},
	{Subtype: "clawhavoc_malware", Value: "Atomic Stealer (AMOS)"},
	{Subtype: "clawhavoc_malware", Value: "Redline"},
	{Subtype: "clawhavoc_malware", Value: "Lumma"},
	{Subtype: "clawhavoc_malware", Value: "Vidar"},
	{Subtype: "malicious_domain", Value: "91.92.242.30"},
	{Subtype: "infostealer_target", Value: "~/.openclaw/.env"},
	{Subtype: "infostealer_target", Value: "~/.openclaw/credentials/"},
	{Subtype: "infostealer_target", Value: "~/.clawdbot/.env"},
	{Subtype: "infostealer_target", Value: "~/.clawdbot/credentials/"},
	{Subtype: "infostealer_target", Value: "~/.moltbot/.env"},
}
