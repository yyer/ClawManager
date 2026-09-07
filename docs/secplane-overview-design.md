# Secplane 概要设计文档

本文档是对 ClawManager `secplane` 子模块的概要设计,描述其当前功能边界、模块划分、数据模型、API、关键流程与约束。文档基于 2026-07-22 代码状态;与 [`secplane-aegis-rule-dispatch.md`](./secplane-aegis-rule-dispatch.md) 互补--后者深入"规则下发与告警上报链路"的实现细节,本文聚焦系统级结构与新引入的规则类型。

---

## 1. 背景与定位

**secplane** 是 ClawManager 后端内置的安全策略控制平面,负责把管理员在 UI 上配置的安全规则编译成两个运行时插件 (`clawaegisex` / `secureclaw`) 的 `user_config.json`,通过 k8s exec 下发到每个 openclaw 实例,并接收 Pod 端回传的防御事件入库展示。

定位要点:
- **配置层而非检测层**:secplane 自身不做任何 regex 检测或载荷拦截,只负责"规则存储 → 编译 → 下发 → 告警汇总"四件事。真正的检测逻辑在 Pod 内的 ClawAegis / SecureClaw 插件里。
- **单租户全局策略**:当前所有规则全平台共享,没有 per-user / per-team 策略隔离。协同治理 (collab) 虽然按 `teamId` 过滤,但策略本体仍是单例。
- **热重载而非重启**:常规策略编辑通过 `DispatchAegisApply` 写 `user_config.json` 即生效 (≤1s mtime hot-reload),仅首次安装或插件源码升级需 `pkill openclaw` 重启 gateway。

---

## 2. 系统架构

```
┌──────────────────────────── ClawManager backend ────────────────────────────┐
│                                                                             │
│  HTTP /api/v1/secplane/* (admin)                                            │
│    ├── policy/rules CRUD + test + collab/policy + alerts                    │
│    ├── dispatch/{aegis, aegis-apply, secureclaw}                            │
│    ├── instances/:id/{effective-config, aegis/live-config}                  │
│    ├── outbound/trusted CRUD + probe + reprobe                              │
│    ├── kill-switch GET/enable/disable                                       │
│    └── agent/sec_events/batch  (Pod 端 ingest, igt_* token)                 │
│                                                                             │
│  Module: internal/secplane/                                                 │
│    router.go     ─── NewModule + Register                                   │
│    policy/       ─── Rule/Alert 模型 + Service + Handler + Repository       │
│    compiler/     ─── aegis/ + secureclaw/ (Compile + PackageSkill)          │
│    dispatch/     ─── Service (DispatchAegis / Apply / SecureClaw) + Handler │
│    ingest/       ─── Handler (Pod 端事件接入,写 secplane_alert)             │
│    outbound/     ─── 出站白名单 + TLS 指纹巡检 watcher                       │
│    killswitch/   ─── 单行应急熔断状态                                        │
│    aegis_assets/ ─── go:embed clawaegisex-base.zip + secureclaw-base.zip    │
│                                                                             │
│  DB tables: secplane_policy_rule, secplane_alert,                           │
│             secplane_outbound_trusted, secplane_kill_switch,                │
│             secplane_instance_runtime_config                                │
└─────────────────────────────────────────────────────────────────────────────┘
                     │                              ▲
   k8s exec (SPDY)   │ dispatch 配置                 │ HTTP POST sec_events/batch
                     ▼                              │  (Bearer igt_* instance token)
┌──────────────────────────── Pod 内 openclaw runtime ────────────────────────┐
│  extensions/clawaegisex/   ←──── DispatchAegis / DispatchAegisApply         │
│    user_config.json        (mtime hot-reload, ≤1s 生效)                     │
│    src/*.ts                (仅 DispatchAegis 全量替换;Apply 不动源码)        │
│  extensions/secureclaw/    ←──── DispatchSecureClaw (install_skill 通道)    │
│    user_config.json                                                         │
│    skill/configs/*.json   (dangerous/injection/privacy/ioc 4 个数据文件)    │
│                                                                             │
│  ClawAegis / SecureClaw hook → defense-events.jsonl + fire-and-forget POST │
└─────────────────────────────────────────────────────────────────────────────┘
```

关键依赖方向:`dispatch ← killswitch`(避免循环依赖,通过 `KillSwitchProvider` 接口注入);`team_collab.go → policy.Service`(读 collab 策略,运行时拦截 XADD);`secplane → services.{SkillService, InstanceCommandService, InstanceAgentService}`(复用既有 skill 上传 + 命令调度 + agent 鉴权)。

---

## 3. 核心模块

### 3.1 policy (`internal/secplane/policy/`)

规则的存储与 CRUD 基座。核心数据结构是 `Rule` (DB 表 `secplane_policy_rule` 一行),通过 `kind` 字段区分 11 种规则类型:

| kind | 用途 | 编译去向 |
|---|---|---|
| `defense_toggle` | 16 个 ClawAegis 防御模块的总开关+模式 | `cfg.<X>Enabled` + `cfg.<X>Mode` |
| `user_risk_flag` | 7 个用户输入风险 flag 三态开关 | `disabledUserRiskFlags` / `observeOnlyUserRiskFlags` |
| `tool_result_flag` | 12 个工具结果风险 flag 三态开关 | `disabledToolResultFlags` / `observeOnlyToolResultFlags` |
| `protected_path` / `protected_skill` / `protected_plugin` | 受保护资源白名单 | `ProtectedPaths/Skills/Plugins` |
| `collab_policy` | 协同治理单例策略 (Pattern 存完整 JSON) | `CollabGuard*` 字段族 |
| `secureclaw_config` | SecureClaw 18 个旋钮 | `secureclaw.UserConfig.*` |
| `secureclaw_audit_check` | 56 个 SC-* 审计项三态 | `disabledAuditChecks` / `observeOnlyAuditChecks` |
| `secureclaw_hardening` | 5 个加固模块开关 | `disabledHardenings` |
| `secureclaw_dangerous_cat`/`_pat` | 7 类危险命令 + 35 regex | `skill/configs/dangerous-commands.json` |
| `secureclaw_injection_pat` | 65 条注入字符串 | `skill/configs/injection-patterns.json` |
| `secureclaw_privacy_rule` | 14 条 PII regex | `skill/configs/privacy-rules.json` |
| `secureclaw_ioc` | ~20 条 IOC (C2/恶意域名/hash) | `skill/configs/supply-chain-ioc.json` |

`RuleRepository.NewRuleRepository` 在构造时调 `seedDefaults()`,把所有内置 flag/defense/check 的默认行插入空库;已存在的 `rule_id` 跳过,保证运维 UI 编辑不被重启覆盖。

Service 层 (`policy/service.go`) 暴露 `List/Save/Delete/BulkSetEnabled/Test/ListAlerts/RecordExternalAlert/GetByRuleID`。`Test` 是后端本地 regex 试跑接口,仅消费 `prompt_filter` 类规则--这类规则当前**不参与下发**,Pattern 字段在运行时无效,是已知设计限制。

### 3.2 compiler (`internal/secplane/compiler/`)

把 `[]Rule` 翻译成插件 `user_config.json` 的无状态编译器,分两个子包:

- **aegis.Compile(rules, revision)**:产出 `Bundle{Revision, Sha256, UserConfig}`。`UserConfig` 结构体 1:1 映射 ClawAegis 的 `ClawAegisPluginConfig` (字段名 JSON tag 必须字节一致,改字段需同步 ClawAegis/src/config.ts + 重打 base zip)。
- **secureclaw.Compile(rules, revision)**:产出 `Bundle` + `SkillConfigs map[string][]byte`。后者是 4 个重建后的 `skill/configs/*.json` 文件字节,打包时随 user_config 一起注入 install zip。

两个子包都有 `PackageSkill` 函数,从 `aegis_assets/` 下的 embedded base zip 读出模板,替换 `user_config.json` (和 secureclaw 的 4 个 configs),重新打 zip 字节返回。

编译默认值:**全防御 ON + enforce 模式**,缺规则时安全降级到"全防护";`collab_guard` 默认 ON 但 mode=observe (只记录不阻断),避免新部署直接拦阻业务。

### 3.3 dispatch (`internal/secplane/dispatch/`)

下发执行器,三条路径:

| API | 函数 | 场景 | 副作用 |
|---|---|---|---|
| `POST /dispatch/aegis` | `DispatchAegis` | 全量:重建 zip + 上传 skill + k8s exec 解压 + pkill openclaw | 每次都重启 gateway;用于首次安装或插件源码升级 |
| `POST /dispatch/aegis-apply` | `DispatchAegisApply` | 增量:只写 `user_config.json`,mtime 热重载 | ≤1s 生效,不重启;首次安装时 fallback 到全量路径 |
| `POST /dispatch/secureclaw` | `DispatchSecureClaw` | SecureClaw:走 install_skill 命令队列 | agent 异步拉取,300s 超时 |

关键设计:
- **idempotency_key 含 revision**:key 形如 `secplane.aegis.<key>.v<verNo>.<cfgSha16>.r<revision>`。revision 是每次 dispatch 的时间戳,必须进 key 否则同内容 dispatch 会被去重不写新命令,Pod 永远收不到更新。
- **k8s exec 双模式** (`execInDesktop`):支持 Pro 模式 (per-instance pod, container=desktop, `/config`) 和 Lite 模式 (共享 `openclaw-runtime` pod, container=runtime, workspace_path+/home),通过 `instance_runtime_bindings` 表自动判别。
- **runtime_config 表快照**:每次成功 dispatch 后 upsert `secplane_instance_runtime_config` (PK: instance_id + skill_name),`GetLiveAegisConfig` 优先读此表,避免依赖 agent 上报 skill_blob (插件 auto-discover 安装路径下 agent 不上报 blob)。
- **kill switch 注入**:`injectKillSwitch` 在编译完后把 `secplane_kill_switch` 表的状态注入 `cfg.KillSwitchEnabled/Reason`,启用后 ClawAegis 在 `before_tool_call` 无条件 block 所有工具调用。
- **outbound 注入**:`injectOutboundEntries` 把 `secplane_outbound_trusted` 表 active 条目注入 `cfg.OutboundTrustedEndpoints`。

### 3.4 ingest (`internal/secplane/ingest/`)

Pod 端事件入口。`POST /api/v1/secplane/agent/sec_events/batch` 接收 ClawAegis/SecureClaw 批量事件,鉴权支持两种 token:
- `agt_sess_*` (agent session,Python reference agent 走的路径)
- `igt_*` (instance access token,openclaw 镜像的 `CLAWMANAGER_INSTANCE_TOKEN` env,ClawAegis 直接用这个)

事件按 `source` (aegis/secureclaw/...) 落 `secplane_alert` 表,`buildAlert` 做字段归一化 (severity/action/timestamp/subject/evidence)。`accepted/rejected` 计数返回给调用方。Pod 端是 fire-and-forget,失败静默,本地 `defense-events.jsonl` 是兜底 source of truth。

### 3.5 outbound (`internal/secplane/outbound/`)

出站可信端点白名单 + 证书指纹漂移检测。

- 表 `secplane_outbound_trusted`:domain_pattern + 可选 fingerprint_sha256 + label/channel/scope/expires_at。
- `Probe(host)` 拨号 443 抓 leaf cert 摘要 (添加前预览,不写库);`Reprobe(id)` 比对现有条目,指纹变化时更新并返回 `drift=true`。
- `Watcher` (`StartBackgroundWorkers` 启动,默认 1h 间隔) 周期重探所有 pinned 条目,drift 时写 `secplane_alert` (source=aegis, rule_id=defense.outboundTrust, severity=high) 并把基线更新为最新指纹。

通配条目 (`*`/`?`) 一律跳过 probe/reprobe。

### 3.6 killswitch (`internal/secplane/killswitch/`)

应急熔断单行状态 (表 `secplane_kill_switch`, id=1 固定行)。
- `Enable(reason, by)` / `Disable()` 切换 `enabled` 字段。
- **Enable/Disable 后立即自动调 `DispatchAegisApply(nil)`** (空 instance_ids = 全实例),让熔断状态秒级生效,无需管理员再手动点"下发"。
- 通过 `killSwitchAdapter` 实现 `dispatch.KillSwitchProvider` 接口,避免 dispatch → killswitch 循环依赖。

### 3.7 team_collab (`internal/services/team_collab.go`)

非 secplane 包内文件,但属于协同治理防御的运行时侧。`teamService.DispatchTask` 在 XADD 投递前调 `checkCollabTask`,按 `collab_policy` 规则的 4 个子模式 (identity/schema/quota/approval) 评估 envelope:
- 任一规则 mode=enforce 且命中 → 返回 `CollabViolationError` → HTTP 403 拦阻 XADD
- mode=observe 命中 → 写 `secplane_alert` (source=`collab_governance`),不拦阻
- policy teamId 与当前 team.ID 不匹配 → 放行 (默认值 "12" 不会拦真实 team)

policy 加载带 10s TTL 缓存,避免热路径每次 DB 读。

---

## 4. 数据模型

5 张表,全部 `secplane_` 前缀,无 FK 到 ClawManager 核心表 (保持松耦合,便于后续拆分):

### 4.1 `secplane_policy_rule` (migration 100)
```sql
id, rule_id (UNIQUE), kind, display_name, description, pattern (TEXT),
target, severity, action, mode (enforce/observe/off), is_enabled,
sort_order, tags, created_at, updated_at
INDEX: (kind, is_enabled), (target), (sort_order)
```
所有规则类型共用此表,`kind` 是判别字段。

### 4.2 `secplane_alert` (migration 100)
```sql
id, trace_id, source, rule_id, rule_name, severity, action,
agent_id, subject, evidence, raw_payload (MEDIUMTEXT), ts
INDEX: ts, severity, source, rule_id, trace_id
```
多源汇聚:aegis (Pod 端 ClawAegis)、secureclaw、collab_governance、platform (后端 Test 接口)、external。

### 4.3 `secplane_outbound_trusted` (migration 101)
```sql
id, domain_pattern (UNIQUE), fingerprint_sha256, label, channel, scope,
status (active/...), expires_at, created_at, updated_at
INDEX: status
```

### 4.4 `secplane_kill_switch` (migration 102)
单行表 (id=1 固定),字段:enabled, reason, set_by, set_at, created_at, updated_at。

### 4.5 `secplane_instance_runtime_config` (migration 103)
```sql
PK: (instance_id, skill_name)
revision, sha256, config_sha256, user_config (MEDIUMTEXT JSON),
source (dispatch_aegis/apply/secureclaw), command_id,
status, dispatched_at, created_at, updated_at
INDEX: (skill_name, dispatched_at)
```
每实例每 skill 一行,新 dispatch 覆盖旧。`GetLiveAegisConfig` 主路径读此表,skill_blob 解压是 fallback。

---

## 5. API 接口

全部挂在 `/api/v1/secplane/*` 下,分两组鉴权:

### 5.1 Admin 组 (middleware: Auth + SetUserInfo + AdminAuth)

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/policy/rules?kind=` | 列规则 (可选 kind 过滤) |
| PUT | `/policy/rules` | upsert 单条规则 |
| DELETE | `/policy/rules/:rule_id` | disable (软删) |
| POST | `/policy/rules/bulk-status` | 批量启停 |
| POST | `/policy/rules/test` | 后端本地 regex 试跑 (仅 prompt_filter) |
| GET | `/alerts` | 列告警 (filter: source/severity/rule_id/limit) |
| POST | `/dispatch/aegis` | 全量下发 (zip + pkill) |
| POST | `/dispatch/aegis-apply` | 增量下发 (仅 user_config,热重载) |
| POST | `/dispatch/secureclaw` | SecureClaw 下发 (install_skill) |
| GET | `/instances/:id/effective-config` | 最近一次下发意图 |
| GET | `/instances/:id/aegis/live-config` | Pod 实际生效配置 (runtime_config 表) |
| GET/PUT | `/collab/policy` | 协同治理单例策略 |
| GET/POST/DELETE | `/outbound/trusted[/:id]` | 出站白名单 CRUD |
| POST | `/outbound/trusted/probe` | 添加前 TLS 预览 |
| POST | `/outbound/trusted/:id/reprobe` | 重探 + drift 检测 |
| GET/POST | `/kill-switch[/enable\|/disable]` | 应急熔断状态 |

### 5.2 Agent 组 (middleware: ingest.AuthMiddleware)

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/agent/sec_events/batch` | Pod 端批量事件上报 |

请求体:`{source:"aegis", events:[{event_id, ts, hook, defense, rule_id, severity, result, reason, evidence, trace_id, agent_id, subject, raw_payload}]}`。响应:`{accepted, rejected}`。

---

## 6. 关键流程

### 6.1 常规策略编辑 → 生效

```
[Admin UI] 编辑某 user_risk_flag 规则 mode=enforce→observe
  → PUT /policy/rules  (upsert)
  → [Admin UI] 点"下发"
  → POST /dispatch/aegis-apply {instance_ids:[]}
     ↓ policyService.List() 读全部规则
     ↓ aegis.Compile(rules, revision) → Bundle
     ↓ injectOutboundEntries + injectKillSwitch
     ↓ aegis.PackageSkill (为 fallback 全量路径准备,便宜)
     ↓ for each target instance:
         extensionsMissing? → installClawaegisexViaExec (首次安装)
         else → writeUserConfigDirect (base64 → user_config.json)
         ↓ recordRuntimeConfig (upsert secplane_instance_runtime_config)
         ↓ markCommandTerminal (succeeded/failed)
[Pod] mtime hot-reload ≤1s → 下次 hook 用新 liveConfig
```

### 6.2 应急熔断

```
[Admin UI] POST /kill-switch/enable {reason:"被攻击"}
  → killswitch.Enable(reason, username)
  → autoDispatch: DispatchAegisApply(nil) 全实例
     ↓ injectKillSwitch 把 killSwitchEnabled=true 注入 cfg
     ↓ 同 6.1 后续路径
[Pod] ClawAegis before_tool_call hook 读到 killSwitchEnabled=true
  → 无条件 block 所有工具调用,返回 KillSwitchReason
[Admin UI] POST /kill-switch/disable → 同链路把 false 推下去恢复
```

### 6.3 Pod 端事件上报

```
[Pod ClawAegis hook] 检测到 user_risk 命中
  → fs.appendFile defense-events.jsonl (本地兜底)
  → fetch POST ${CLAWMANAGER_AGENT_BASE_URL}/api/v1/secplane/agent/sec_events/batch
       headers: Authorization: Bearer ${CLAWMANAGER_INSTANCE_TOKEN}
       body: {source:"aegis", events:[...]}
       timeout: 30s, fire-and-forget (失败静默)
[backend ingest] AuthMiddleware 验 igt_* token → buildAlert → INSERT secplane_alert
[Admin UI] GET /alerts 拉展示
```

### 6.4 协同治理拦截

```
[teamService.DispatchTask] 准备 XADD envelope
  → checkCollabTask(team, member, envelope)
     ↓ loadCollabPolicy (10s 缓存)
     ↓ teamId mismatch → 放行
     ↓ evalCollabRules 4 条子规则
     ↓ observe 违规 → recordCollabAlert
     ↓ enforce 违规 → 返回 CollabViolationError
  → 若 error: HTTP 403, XADD 不执行
  → 否则: 继续执行 XADD
```

---

## 7. 前端页面

路由全部在 `/admin/secplane/*` 下 (router/index.tsx L349-448):

**主框架页**:
- `SecurityProtectionPage` (`/secplane`) -- 安全防护总览,7 个分类卡片 (cat-1~cat-7) + 4 层 (runtime/host/audit/control) + 15 场景气泡 + 24h 告警统计。
- `SecurityEventsPage` (`/secplane/events`) -- 告警事件表。

**按场景分类页** (CategoryPage 复用,通过 `catId` prop 区分):
- `cat-1` 运行时 / `cat-2` 身份 / `cat-3` 通信 / `cat-4` 信任 / `cat-5` 治理 / `cat-6` 隔离 / `cat-7` 策略

**runtime 子页** (prototype 原型对齐的 5 个风险面):
- `/runtime/input` 输入面 / `/runtime/state` 状态面 / `/runtime/decision` 决策面 / `/runtime/output` 输出面 / `/runtime/asset` 资产面

**scenario 子页** (按 KSecForAI Demo 原型 1:1 迁移):
- `ApprovalPage` 审批 / `OutboundPage` 出站白名单 / `BreakerPage` 熔断 / `AuditPage` 审计 / `ContainerPage` 容器隔离 / `HostHardeningPage` 主机加固 / `PolicyPage` 策略治理 / `CollaborationGovernancePage` 协同治理 / `CollaborationQuotaPage` 协同配额

**独立页**:
- `InputDetectionPage` (`/secplane/input-detection`) -- 旧版输入检测规则 CRUD (prompt_filter, 当前 Pattern 不下发)。
- `SecureClawPage` (`/secplane/secureclaw`) -- SecureClaw 18 旋钮 + 56 审计项 + 5 加固模块 + 4 数据文件编辑。

---

## 8. 部署与集成

**后端**:secplane 是 ClawManager backend 内嵌模块,不独立部署。`main.go` L143-147 构造 `secplaneModule` + `StartBackgroundWorkers` (启动 outbound watcher),L156 把 `PolicyService` 注入 `teamService` 作为 `TeamCollabService` (协同治理运行时依赖),L556-557 注册路由。

**Pod 端依赖**:
- `CLAWMANAGER_AGENT_BASE_URL` env:Pod 内 ClawAegis 用此 URL POST 事件到 backend。
- `CLAWMANAGER_INSTANCE_TOKEN` env:`igt_*` token,作为 Bearer 鉴权。
- `extensions/clawaegisex/` 目录:首次 `DispatchAegis` 创建,后续 `Apply` 增量更新 `user_config.json`。
- `openclaw.json` 的 `plugins.entries.clawaegisex.hooks.allowConversationAccess=true`:dispatch 脚本会自动 patch,否则 openclaw 2026.5.4+ 的 `shouldConsiderForGatewayStartup` 不加载 clawaegisex (无 activation.onStartup,无 channels/contracts),gateway 启动时跳过该插件。

**镜像**:无需独立镜像,clawaegisex/secureclaw base zip 通过 `go:embed` 打进 backend 二进制。修改插件源码需重打 zip + 重 build backend + 重 deploy。

**与 secplane-aegis-rule-dispatch.md 的关系**:后者是规则下发链路的深度实现文档 (14 章节,覆盖物理拓扑、idempotency 设计、热重载 mtime 缓存、已知陷阱 10 条);本文是系统级概要,新增内容包括 collab_policy、secureclaw 8 种 kind、outbound watcher、killswitch、runtime_config 表、lite/pro 双模式 exec。两者互补,不重复。

---

## 9. 已知约束与边界

1. **`prompt_filter` Pattern 不下发**:后端 Test 接口能跑 regex,但 Pod 端 ClawAegis 消费的是硬编码 `USER_RISK_RULES`,rule 表的 `pattern` 字段在运行时无效。这是已知设计限制 (参见 `secplane-aegis-rule-dispatch.md` §13)。

2. **enforce 不是硬拦截**:ClawAegis 的 enforce 模式依赖 prompt-guard 提醒让 LLM 自己拒绝,不是 `message_received` short-circuit。LLM 不通时安全 prompt 没意义。

3. **单租户全局策略**:所有 secplane 规则全平台共享。collab_policy 虽然 `teamId` 字段存在,但策略本体仍是单例,不同 team 无法配不同协同策略。

4. **idempotency_key 必须含 revision**:否则同内容 dispatch 会被去重不写新 cmd,Pod 收不到更新。已修复但约束仍在。

5. **DispatchAegis 会 pkill openclaw**:全量路径重启 gateway,业务瞬断。常规编辑应走 `aegis-apply` (热重载)。

6. **Pod 端事件上报 fire-and-forget**:网络抖动时事件丢,本地 `defense-events.jsonl` 是 source of truth 但后端不主动拉,需运维 k8s exec 手动查。

7. **lite/pro 双模式 exec 路径不同**:Pro = per-instance pod (`desktop` container, `/config`),Lite = 共享 `openclaw-runtime` pod (`runtime` container, `workspace_path/home`)。dispatch 自动判别,但 Lite 模式下多实例共享 pod 的隔离语义需要 `redis-team` ACL 等机制兜底。

8. **base zip 必须含 SKILL.md**:`skill_service.ImportArchiveBytes` 自 commit 95d6faa 起强制校验每个 skill 根目录有 `SKILL.md`。重打 zip 时务必带上 (`ClawAegis/SKILL.md` → `clawaegisex/SKILL.md`)。

9. **user_config schema 变更需要全链路同步**:`aegis.UserConfig` 字段 JSON tag 必须 byte-identical 于 `ClawAegis/src/config.ts` 的 `ClawAegisPluginConfig`。改字段需:Go struct → ClawAegis config.ts → 重打 base zip → 重 build backend → 重 dispatch。

---

## 10. 文档维护

代码变更涉及以下场景时,请同步更新本文:
- 新增/删除 `policy.Kind*` 常量 → §3.1 表格 + §4.1 kind 列表
- `aegis.UserConfig` / `secureclaw.UserConfig` 字段变更 → §3.2 + §9.9
- 新增 dispatch 路径或改 idempotency_key 格式 → §3.3 + §6
- 新增 DB migration → §4
- 新增 admin API 路由 → §5.1
- 新增前端 secplane 页面 → §7
- outbound watcher 间隔或 kill switch 自动 dispatch 行为变更 → §3.5 / §3.6

深度实现细节 (映射表、热重载机制、已知陷阱清单) 仍由 `secplane-aegis-rule-dispatch.md` 维护,本文不重复。
