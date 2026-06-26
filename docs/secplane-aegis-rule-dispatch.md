# Secplane → ClawAegis 规则下发与告警上报：设计文档

本文档描述 ClawManager 控制平面（secplane 模块）与 OpenClaw 实例内 ClawAegis
插件之间的规则下发链路、运行时告警上报链路、热重载机制以及每条规则的开关/模式
语义。覆盖所有环节的实现细节、当前已知的工程约束与避坑提醒。

---

## 0. 术语

| 名词 | 含义 |
|---|---|
| **ClawManager** | Go + Gin 写的控制平面后端，部署在 `clawreef-system` 命名空间 |
| **secplane** | ClawManager 内部的安全策略子模块（`internal/secplane/`），负责规则 CRUD、编译、下发、告警 ingest |
| **OpenClaw 实例** | 业务侧的 desktop-runtime pod，每个用户实例一个；命名空间 `clawreef-user-<userID>`；内部跑 openclaw-gateway + 插件 |
| **ClawAegis 插件** | 嵌入式 Node.js 插件，由 openclaw-gateway 进程加载，提供安全防御 hook（`message_received`、`before_prompt_build` 等） |
| **openclaw-agent** | 跟 ClawManager 通信的 sidecar 进程，负责拉取并执行命令（install_skill / restart_openclaw 等）和心跳上报；**不**负责告警上报 |
| **flag** | ClawAegis 内置的检测分类标签，例如 `jailbreak-bypass`、`role-takeover`、`policy-bypass`；硬编码在 `ClawAegis/src/security-strategies.ts` 的 `USER_RISK_RULES` 中 |
| **rule** | ClawManager 里用户可见的策略条目（`secplane_policy_rule` 表）；每条 rule 通过映射表对应到 1 个或多个 ClawAegis flag |
| **bundle** | 一次 dispatch 编译出的 `UserConfig` JSON + 元数据，由 secplane.aegis.Compile 生成，最终写到 Pod 的 `user_config.json` |
| **defense event** | ClawAegis 在 hook 内检测到风险时产生的事件记录；既落本地 jsonl 文件，又通过 HTTP POST 给后端 ingest 接口 |

---

## 1. 目标与非目标

### 目标
1. ClawManager UI 上对策略规则做的任何变更（启用/禁用、调 mode、改 pattern），**点"下发"后**就能在 OpenClaw 实例的下次用户请求中生效，**无需重启 openclaw-gateway**。
2. 每条 rule 的开关（`is_enabled`）能精确控制对应 ClawAegis 内置 flag 是否在 Pod 上生效。
3. 每条 rule 的 mode（`enforce` / `observe`）有可观察的运行时差别：`enforce` 注入 prompt-guard 提醒让 LLM 自己拒绝，`observe` 只记录告警不影响 LLM 行为。
4. Pod 内 ClawAegis 触发的每个 defense event 都能写回 ClawManager 的 `secplane_alert` 表，UI 上可查。
5. UI 不能误导：disable 状态下，severity/action/mode 三列灰显，避免"看起来还在生效"的错觉。
6. 给运维提供 `GET /api/v1/secplane/instances/:id/effective-config` 端点，直接查看某 Pod 上**实际生效**的 bundle，定位"为什么我下发了却没生效"。

### 非目标
1. **强拦截**消息（在 `message_received` 直接 short-circuit 把请求 drop）—— OpenClaw plugin API 当前不支持，靠的是 prompt-guard 软拦截 + LLM 自觉拒绝。
2. **用户 UI 里写的 regex pattern 直接下发到 Pod 上跑** —— 当前 ClawAegis 内置 flag 是硬编码 regex 集合，rule 的 `pattern` 字段在运行时**不被消费**。这是已知设计限制。
3. **多副本一致性 / 高可用** —— 单 backend 副本，PVC 单挂载。

---

## 2. 物理拓扑与组件总览

```
┌────────────────────────────────────── minikube / k3s 节点 ──────────────────────────────────────┐
│                                                                                                 │
│  Namespace clawreef-system                                                                       │
│  ┌────────────────────────────────────────────────────────────────────────────────┐             │
│  │ mysql Deployment                                                                │             │
│  │   - schema: secplane_policy_rule, secplane_alert, instance_commands,            │             │
│  │             skills, skill_versions, skill_blobs, llm_models, instances, users   │             │
│  └────────────────────────────────────────────────────────────────────────────────┘             │
│  ┌────────────────────────────────────────────────────────────────────────────────┐             │
│  │ clawmanager-app Deployment (Go binary, FROM-scratch + alpine CA bundle)         │             │
│  │   ┌──────────────────────────────────────────────────────────────────┐         │             │
│  │   │ HTTP Server (Gin) :9001                                          │         │             │
│  │   │   /api/v1/secplane/policy/rules         CRUD                     │         │             │
│  │   │   /api/v1/secplane/policy/rules/test    单条规则测试             │         │             │
│  │   │   /api/v1/secplane/dispatch/aegis       触发 dispatch            │         │             │
│  │   │   /api/v1/secplane/instances/:id/effective-config  查询 Pod 现配 │         │             │
│  │   │   /api/v1/secplane/alerts               读 secplane_alert        │         │             │
│  │   │   /api/v1/secplane/agent/sec_events/batch  Pod 端 ingest 告警    │         │             │
│  │   │   /api/v1/agent/commands/next           agent 拉命令             │         │             │
│  │   │   /api/v1/agent/heartbeat               agent 心跳               │         │             │
│  │   └──────────────────────────────────────────────────────────────────┘         │             │
│  │   ┌──────────────────────────────────────────────────────────────────┐         │             │
│  │   │ Object Storage (/app/.data/object-storage, PVC 5Gi)              │         │             │
│  │   │   skills/<userID>/<skill_key>/<contentMD5>.zip                   │         │             │
│  │   └──────────────────────────────────────────────────────────────────┘         │             │
│  └────────────────────────────────────────────────────────────────────────────────┘             │
│        clawmanager-gateway Svc NodePort :9001 → :30901                                           │
│                                                                                                 │
│  Namespace clawreef-user-1                                                                       │
│  ┌────────────────────────────────────────────────────────────────────────────────┐             │
│  │ clawreef-2-openclaw-cluster-1 Pod (lsio webtop-style image)                     │             │
│  │   - s6-supervised: openclaw-agent, svc-selkies, svc-xorg, svc-de, ...           │             │
│  │   - openclaw-agent (Go) → poll commands, install skills, heartbeat              │             │
│  │   - openclaw → openclaw-gateway (Go + embedded Node.js v22)                     │             │
│  │       - 嵌入式 V8 加载 ClawAegis 插件 (~/extensions/claw-aegis/index.ts)        │             │
│  │   - Xvfb + xfce + selkies + chromium kiosk (WebUI 流式桌面)                     │             │
│  │   - PVC /config 持久化：.openclaw/{extensions,workspace/skills,plugins}         │             │
│  └────────────────────────────────────────────────────────────────────────────────┘             │
│        clawreef-2-...-svc ClusterIP :3001 → Pod                                                  │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 数据模型

### 3.1 `secplane_policy_rule` (DB)
| 列 | 含义 |
|---|---|
| `id` | 自增主键 |
| `rule_id` | 业务键，例如 `prompt_injection_ignore_previous`；映射表用这个 |
| `kind` | `prompt_filter` / `tool_control` / `memory_guard` / `file_protect` |
| `display_name` / `description` | UI 展示 |
| `pattern` | 用户写的 regex（**当前未下发到 Pod 端**，仅 `/policy/rules/test` 接口用） |
| `target` | `user_input` / `rag_result` / `web_content` / ... |
| `severity` | low / medium / high |
| `action` | block / redact / observe（当前未下发到 Pod 端） |
| `mode` | enforce / observe / off |
| `is_enabled` | 主开关 |
| `sort_order` | UI 排序 |

**关键约束**：`is_enabled` 和 `mode`、`action` 是**正交字段**——禁用一条规则不会自动把 `mode` 也清零。UI 因此对 disabled 行做了灰显。

### 3.2 `aegis.UserConfig` (Go, internal/secplane/compiler/aegis/compile.go)
```go
type UserConfig struct {
    AllDefensesEnabled       bool     `json:"allDefensesEnabled"`
    DefaultBlockingMode      string   `json:"defaultBlockingMode"`
    UserRiskScanEnabled      bool     `json:"userRiskScanEnabled"`
    UserRiskScanMode         string   `json:"userRiskScanMode"`
    CommandBlockEnabled      bool     `json:"commandBlockEnabled"`
    CommandBlockMode         string   `json:"commandBlockMode"`
    EncodingGuardEnabled     bool     `json:"encodingGuardEnabled"`
    EncodingGuardMode        string   `json:"encodingGuardMode"`
    MemoryGuardEnabled       bool     `json:"memoryGuardEnabled"`
    MemoryGuardMode          string   `json:"memoryGuardMode"`
    SelfProtectionEnabled    bool     `json:"selfProtectionEnabled"`
    SelfProtectionMode       string   `json:"selfProtectionMode"`
    SkillScanEnabled         bool     `json:"skillScanEnabled"`
    ProtectedPaths           []string `json:"protectedPaths,omitempty"`
    ProtectedSkills          []string `json:"protectedSkills,omitempty"`
    ProtectedPlugins         []string `json:"protectedPlugins,omitempty"`
    DisabledUserRiskFlags    []string `json:"disabledUserRiskFlags,omitempty"`
    ObserveOnlyUserRiskFlags []string `json:"observeOnlyUserRiskFlags,omitempty"`
}
```

### 3.3 `instance_commands` (DB)
| 列 | 用途 |
|---|---|
| `id` / `instance_id` / `command_type` | 基本 |
| `payload_json` | `install_skill` 类型时含 `aegis_user_config`、`aegis_revision`、`aegis_sha256`，作为 effective-config 的"权威源" |
| `idempotency_key` | `secplane.aegis.claw-aegis.v<versionNo>.<cfgSha16>.r<revision>` — **revision 必须在 key 里**，否则下发会被误 dedup |
| `status` | pending → running → succeeded / failed |
| `result_json` / `error_message` | agent 上报 |

### 3.4 `secplane_alert` (DB)
| 列 | 用途 |
|---|---|
| `source` | `aegis` (Pod 端 ClawAegis 上报) / `platform` (后端测试接口) |
| `rule_id` | aegis 上报时填 ClawAegis 内部的 defense 名（例如 `user_risk_scan`） |
| `severity` / `action` | aegis 端根据 enforce/observe 计算得到 |
| `subject` / `evidence` / `raw_payload` | 上下文 |

### 3.5 ClawAegis `user_config.json`
落地路径优先级（[ClawAegis/src/config.ts](../../ClawAegis/src/config.ts) 的 `userConfigCandidatePaths`）：
1. `~/.openclaw/workspace/skills/claw-aegis/user_config.json` — **install_skill 落地处，最高优先级**
2. `<rootDir>/user_config.json` — 开发者 local override（`<rootDir>` 是插件源所在目录）
3. `~/.openclaw/skills/claw-aegis/user_config.json` — 兼容遗留

`findUserConfigPath` 取第一个存在的。

---

## 4. 规则下发链路

### 4.1 一次 dispatch 全流程

```
[UI] 点"下发"
   ↓ POST /api/v1/secplane/dispatch/aegis  { instance_ids:[2] }

[secplane.dispatch.Service.DispatchAegis]
   ↓ 1) policyService.List() — 读所有 enabled / mode!=off 的 rules
   ↓ 2) aegis.Compile(rules, revision)
        ├─ 初始化 disabledFlagSet = allKnownAegisUserRiskFlags()  // {jb-bypass, role-takeover, policy-bypass, sp-exfil, sp-leak}
        ├─ 遍历 enabled prompt_filter rules:
        │     for each flag in ruleIDToAegisUserRiskFlags[r.RuleID]:
        │       delete(disabledFlagSet, flag)
        │       if mode == enforce → flagHasEnforceRule[flag] = true
        │       if mode == observe → flagHasObserveRule[flag] = true
        ├─ observeOnlyFlagSet = { flag | flagHasObserveRule[flag] && !flagHasEnforceRule[flag] }
        └─ 返回 Bundle{ Revision, Sha256, UserConfig{ DisabledUserRiskFlags, ObserveOnlyUserRiskFlags, ... } }
   ↓ 3) aegis.PackageSkill(bundle.UserConfig)
        ├─ 从 //go:embed claw-aegis-base.zip 取原始插件 zip
        ├─ 把 claw-aegis/user_config.json 替换成新 bundle JSON
        └─ 重新打包成 zip 字节
   ↓ 4) skillService.ImportArchiveBytes(adminUserID, fname, zipBytes)
        ├─ 计算 contentHash
        ├─ if GetBlobByContentHash != nil:  return existing skill version (DEDUP)
        ├─ else: PutObject(.../skills/<userID>/<skill_key>/<contentHash>.zip)
        │        CreateBlob(); CreateSkill(); CreateVersion()
        └─ 返回 skill 元数据（含 versionExtID = "ver_<id>"）
   ↓ 5) for each instanceID in resolveTargets(instanceIDs):
        ├─ idemKey = secplane.aegis.<skillKey>.v<versionNo>.<cfgSha16>.r<revision>
        ├─ cmdService.Create(instanceID, ..., {
        │      CommandType: "install_skill",
        │      Payload: { skill_id, skill_version, target_name, content_md5,
        │                 aegis_revision, aegis_sha256, aegis_user_config },
        │      IdempotencyKey: idemKey, TimeoutSeconds: 300
        │  })
        │   ├─ GetByInstanceIdempotencyKey(instanceID, idemKey)
        │   │    若已存在 → 直接返回（短时间重复点击防抖）
        │   └─ 否则 INSERT 新行（status=pending）
        └─ Targets[i] = { CommandID, Status }
   ↓ HTTP 200 {revision, sha256, user_config, targets:[{command_id, status:"pending"}]}

[openclaw-agent in Pod] (long-poll 模式)
   循环 GET /api/v1/agent/commands/next
   拿到 cmd → 解析 install_skill payload → status=running
   ↓ HTTP GET /api/v1/agent/skills/download?skill_version=ver_X
        backend 通过 ObjectStorage 读 skills/<userID>/<skill_key>/<md5>.zip 返回 zip
        ↑ **若 PVC 是 emptyDir + backend 重启过 → 文件丢失但 DB 记录还在 → 500**
   ↓ unzip 到 /config/.openclaw/workspace/skills/claw-aegis/
        ├─ 覆写 user_config.json (mtime 更新)
        └─ 覆写 src/*.js 等插件源（替换 ClawAegis 自身代码也走这条路）
   ↓ 调 inventory sync 上报
   ↓ POST 命令完成 → status=succeeded

[Pod 端 ClawAegis 插件] (热重载)
   下次任意一次 message_received hook 触发时:
   ├─ getLiveConfig() 调 fs.statSync(user_config.json).mtimeMs
   ├─ if mtimeMs > liveConfigMtimeMs:
   │      liveConfig = resolveClawAegisPluginConfig(api)  // 重新解析
   │      liveConfigMtimeMs = mtimeMs
   │      logger.info("user_config_hot_reload", ...)
   └─ 用 liveConfig 走后续检测
```

### 4.2 关键函数 / 文件

| 环节 | 文件 |
|---|---|
| HTTP 路由 | `backend/internal/secplane/router.go` |
| Dispatch handler | `backend/internal/secplane/dispatch/handler.go` |
| Dispatch service | `backend/internal/secplane/dispatch/service.go` |
| 编译器 | `backend/internal/secplane/compiler/aegis/compile.go` |
| Skill zip 打包 | `backend/internal/secplane/compiler/aegis/packager.go` |
| 嵌入式 base zip | `backend/internal/secplane/aegis_assets/{embed.go, claw-aegis-base.zip}` |
| Skill 导入 / 对象存储 | `backend/internal/services/skill_service.go`, `object_storage_service.go` |
| 命令调度 | `backend/internal/services/instance_command_service.go` |
| ClawAegis 配置解析 + 热重载 | `ClawAegis/src/config.ts` (+ `.js` 编译产物) |
| 钩子 + 检测 + 上报 | `ClawAegis/src/handlers.ts` (+ `.js`) |
| Pattern 表 | `ClawAegis/src/{rules.ts,security-strategies.ts}` |

---

## 5. 规则 ↔ Aegis flag 映射（核心数据）

定义在 `compile.go`：

```go
var ruleIDToAegisUserRiskFlags = map[string][]string{
    "prompt_injection_ignore_previous": {"jailbreak-bypass"},
    "prompt_injection_role_override":   {"role-takeover"},
    "jailbreak_dan":                    {"policy-bypass"},
    "system_prompt_extraction":         {"system-prompt-exfiltration", "system-prompt-leak"},
}
```

**设计约束**：1-to-1 / 非重叠。每个 flag 只能被一条 rule 拥有。否则会出现"我 disable 了一条 rule 但 flag 不被关"的反直觉行为：
- compile.go 的逻辑是"从 disabledFlagSet 中**删除**任何被 active rule 持有的 flag"
- 若 flag F 被 rule A 和 rule B 共同持有，仅 disable A 但 B 还 enabled → F 不会进 disabledFlagSet → 仍生效

`encoded_payload_marker` / `tool_misuse_shell_pipe` / `rag_external_instruction` 等其他 rule **不在 user_risk 映射表里**——它们驱动的是 `encodingGuard` / `commandBlock` / `toolResultScan` 等独立的 defense 开关。

---

## 6. 三态语义（disabled / observe / enforce）

| rule 状态 | bundle 输出 | Pod 行为 |
|---|---|---|
| `is_enabled=false` 或 `mode=off` | flag 进入 `disabledUserRiskFlags` | `detectUserRiskFlags()` 过滤掉这个 flag，**不产生**告警、**不**注入 prompt guard |
| `is_enabled=true && mode=observe` | flag 进入 `observeOnlyUserRiskFlags` | 检测到时：emit defense event with `result="observed"`，**不**调用 `state.noteUserRisk()`，所以下游 prompt guard **不**注入 |
| `is_enabled=true && mode=enforce` | flag 既**不**进 disabled 也**不**进 observe | 检测到时：emit defense event with `result="blocked"`，调用 `state.noteUserRisk()`，下游 `before_prompt_build` 注入 `userRisk` reminder → LLM 拒绝 |

注意 `result="blocked"` 是**alert label**，不代表请求被硬阻断。真正的"拒绝"是 LLM 在收到 prompt guard 提醒后自己回 `[AEGIS-REFUSED]...`。

---

## 7. 告警上报链路

```
[ClawAegis 插件，gateway 进程内嵌 V8]
   message_received(event, ctx) hook
   ↓ detectUserRiskFlags(text, liveCfg.disabledUserRiskFlags) → match.flags
   ↓ 按 liveCfg.observeOnlyUserRiskFlags 拆分 enforceFlags / observeFlags
   ↓ if enforceFlags.length > 0: state.noteUserRisk(session, enforceFlags)
   ↓ emitDefenseEvent({
        timestamp, defense:"user_risk_scan", result:"blocked"/"observed",
        reason, details:{flags, enforceFlags, observeFlags}, userInput:slice(500)
     })
        ├─ fs.appendFile(/config/.openclaw/plugins/claw-aegis/defense-events.jsonl)
        │      ★ source of truth：磁盘永远先有
        └─ postEventToSecplane(record)   ★ fire-and-forget
              ├─ baseURL = process.env.CLAWMANAGER_AGENT_BASE_URL
              ├─ token   = process.env.CLAWMANAGER_INSTANCE_TOKEN
              ├─ fetch POST ${baseURL}/api/v1/secplane/agent/sec_events/batch
              │     headers: { Authorization: Bearer ${token}, content-type: json }
              │     body: { source:"aegis", events:[{event_id, ts, hook, defense,
              │                                       rule_id, severity, result,
              │                                       reason, subject, evidence,
              │                                       raw_payload}] }
              │     timeout: AbortController 30s
              └─ .catch(swallow)         ★ 失败静默；jsonl 是兜底

[backend ingest 端]
   POST /api/v1/secplane/agent/sec_events/batch
   ↓ ingest.AuthMiddleware
        verify Authorization Bearer 跟 instance.access_token 匹配
   ↓ ingest.IngestBatch
        for each event: INSERT INTO secplane_alert(source, rule_id, severity, action, ...)
   ↓ 200 { data:{accepted, rejected} }
```

**关键不变量**：
- 告警上报**不通过 openclaw-agent**。agent 只管 install_skill / heartbeat / state report。
- 全过程靠 Pod 内 Go 进程嵌入的 V8 native fetch（Node 22 自带）直接调 backend HTTP。
- `defense-events.jsonl` 是 source of truth，HTTP POST 是 best-effort。

---

## 8. 热重载机制

### 设计前提
- ClawAegis 是 Go gateway 进程加载的 ESM 模块；`resolveClawAegisPluginConfig` 在插件初始化时被调一次。
- 不加热重载 → 改 `user_config.json` 必须重启 gateway 才能生效。

### 实现：mtime 缓存（`ClawAegis/src/handlers.ts` 的 `getLiveConfig`）
```ts
let liveConfig = resolveClawAegisPluginConfig(api);
let liveConfigMtimeMs = getUserConfigMtimeMs(api.rootDir);

const getLiveConfig = () => {
  const mt = getUserConfigMtimeMs(api.rootDir);  // fs.statSync(path).mtimeMs
  if (mt !== 0 && mt !== liveConfigMtimeMs) {
    try {
      liveConfig = resolveClawAegisPluginConfig(api);
      liveConfigMtimeMs = mt;
      logger.info("claw-aegis: user_config.json 已热重载", { ... });
    } catch (e) { logger.warn("热重载失败，沿用上次配置", { reason: e.message }); }
  }
  return liveConfig;
};
```

- 调用成本：一次 `fs.statSync` ≈ 微秒级
- 仅在 mtime 实际变化时才解析 JSON
- `message_received` hook 用 `getLiveConfig()` 替代闭包里的常量 `config`

### 设计权衡
- 不用 `fs.watch`：避免 inotify watcher 泄漏 + Linux/macOS 行为差异
- 不用 TTL：用户希望"下发即生效"，TTL 会引入感知延迟

---

## 9. effective-config 查询接口

`GET /api/v1/secplane/instances/:id/effective-config`

实现（`backend/internal/secplane/dispatch/service.go: GetEffectiveAegisConfig`）：
1. `cmdService.ListByInstanceID(id, 50)` 取该实例最近 50 条命令
2. 倒序找第一个 `command_type=install_skill && payload.target_name=="claw-aegis" && payload.aegis_user_config != nil`
3. 返回该 cmd 的 `aegis_user_config` + revision + sha + 命令时间戳

回答的是"**最近一次下发的意图**"，不是 Pod 上**真实生效**的配置——理论上 Pod 端 install_skill 失败 / 热重载失败时两者会有偏差。后续可加 agent 上报 effective-config 当前值（dump 真 user_config.json）做真实校验。

---

## 10. ClawManager 镜像与部署细节

### 10.1 ClawAegis 源 → backend embed
1. 修改 `ClawAegis/src/{config,rules,handlers}.{ts,js}`（**.ts 和 .js 都要改**，因为 index.ts import 的是 .js）
2. 重打 `claw-aegis-base.zip`：把整个 `ClawAegis/` 目录（除 node_modules / web / package.json 等）压缩，**顶层目录名为 `clawaegisex/`**
3. 替换 `backend/internal/secplane/aegis_assets/claw-aegis-base.zip`

> ⚠️ **base zip 必须含 `clawaegisex/SKILL.md`**：dispatch 走 `skill_service.ImportArchiveBytes`，自 commit 95d6faa 起导入强制校验每个 skill 目录根存在 `SKILL.md`，否则 `aegis-apply` 返回 500（`skill directory clawaegisex must contain SKILL.md`）。源文件在 `ClawAegis/SKILL.md`，重打包时务必带上。`secureclaw-base.zip` 同理含 `secureclaw/SKILL.md`。
4. `go build` backend，docker build 出新镜像
5. minikube：`minikube image load <image>` + `kubectl set image`
6. rollout 后下次 dispatch 会带新 plugin code

### 10.2 Dockerfile（关键点）
```dockerfile
# Stage 1: 拿 CA bundle，给 backend 调任何外部 HTTPS（DeepSeek / OpenAI / ...）用
FROM alpine:3.19 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
WORKDIR /
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY bin/server /server
EXPOSE 9001
ENTRYPOINT ["/server"]
```

**不能直接 FROM scratch**：无 CA bundle → Go HTTP 客户端调 HTTPS 全部 x509 失败。

### 10.3 Deployment yaml 关键约束
- `clawmanager-app` 用 PVC 持久化 `/app/.data`（object-storage），否则重启丢 skill zip 文件
- `serviceAccountName: clawmanager-app` + cluster-admin ClusterRoleBinding（开发环境简化；生产应做细化 RBAC）
- `initContainer wait-for-mysql`：避免冷启 crashloop
- Service `clawmanager-gateway` type=NodePort 30901，给 host vite 访问；type=ClusterIP 的 `clawmanager-egress-proxy:3128` 给 Pod 用作 egress proxy

---

## 11. 已知设计 / 工程陷阱（必读）

1. **idempotency_key 必须含 revision**：早期版本只用 `version + cfgSha`，导致 "bundle 内容碰巧跟历史一致" 时被 dedup 命中不写新 cmd → pod 不知道。修复后 key 是 `secplane.aegis.<key>.v<versionNo>.<cfgSha16>.r<revision>`。

2. **skill_blobs dedup by content_hash 不查 disk**：若 backend 重启后对象存储目录被清空（曾用 emptyDir），但 DB 中 blob 记录还在，下次 import 同内容直接 dedup 不重写文件 → agent 下载报 500。已通过 PVC 解决，但 dedup 逻辑本身仍可改进（先 `HeadObject` 检查文件存在）。

3. **`pattern` 字段是装饰性的**：rule 表的 regex 不会下发到 Pod 端跑。Pod 上跑的是 ClawAegis 硬编码的 `USER_RISK_RULES`。运维侧 `/policy/rules/test` 接口走的是 backend 内部 regex 匹配，跟 Pod 端是两套规则集合。

4. **enforce 不是硬拦截**：依赖 LLM 自觉拒绝。LLM 不通（dummy / 故障）时业务挂死但安全 prompt 没意义。

5. **shipper timeout 不能太短**：早期 3 秒 timeout + 嵌入式 V8 的 fetch + 集群 DNS 冷解析 → 第一个 POST 必被 AbortController 砍掉。现 30 秒。

6. **ClawAegis 插件加载路径与 install_skill 落地路径解耦**：
   - 插件 rootDir = `~/.openclaw/extensions/claw-aegis/`
   - install_skill 落 `~/.openclaw/workspace/skills/claw-aegis/`
   - 因此**plugin 源代码更新**（不只是 user_config）需要把 workspace/skills/ 的源同步到 extensions/，并 restart gateway。`user_config.json` 因为优先级是 workspace/skills 在前，热重载能跑通。

7. **xfsettingsd 进程泄漏**：lsio webtop 镜像 quirk，xfsettingsd 反复 spawn → X11 client 表占满 (256) → chromium renderer / selkies 编码线程连不上 X → 浏览器黑屏。已加 `~/.config/autostart/openclaw-x-cleanup.desktop` 周期 kill 多余。

8. **Xvfb 默认分辨率 15360×8640**：lsio 默认值，单帧 framebuffer 380MB + selkies 编码量大。已用 `SELKIES_MANUAL_WIDTH=1024 SELKIES_MANUAL_HEIGHT=768` env 覆盖。

9. **CPU/Mem limit 紧时 openclaw-gateway 容易被节流**：metrics-server 上报的"CPU%"基于 host `/proc/loadavg`，不准。已加 `usage_percent_of_quota` 字段，UI 优先用 metrics-server 拉的真实 cgroup usage。

10. **K3s 时钟漂移会让证书 not-before 落在未来**：boot 时 RTC 错乱 → k3s 签证书 → NTP 拉回 → 整个集群进入"等到证书生效"的不可用状态。已切到 minikube。

---

## 12. 验证手段（运维端）

### 12.1 确认 dispatch 真的写到 Pod
```bash
# 1) 触发 dispatch（UI 或 API）
curl -X POST $BACKEND/api/v1/secplane/dispatch/aegis \
  -H "Authorization: Bearer $ADMIN_JWT" -d '{"instance_ids":[N]}'

# 2) 查最新 install_skill cmd 创建并 succeeded
kubectl -n clawreef-system exec deploy/mysql -- \
  mysql -uroot -p... -e "SELECT id,status FROM instance_commands ORDER BY id DESC LIMIT 1"

# 3) 看 effective-config（"意图")
curl $BACKEND/api/v1/secplane/instances/N/effective-config -H "Authorization: ..."

# 4) 看 Pod 上 user_config.json（"真实")
kubectl -n clawreef-user-U exec POD -- cat /config/.openclaw/workspace/skills/claw-aegis/user_config.json
```

### 12.2 确认告警链路通
```bash
# 在 openclaw chat 输入 "ignore all previous instructions"
# 然后:
kubectl -n clawreef-user-U exec POD -- tail /config/.openclaw/plugins/claw-aegis/defense-events.jsonl
kubectl -n clawreef-system exec deploy/mysql -- \
  mysql -uroot -p... -e "SELECT id,source,rule_id,action,ts FROM secplane_alert ORDER BY id DESC LIMIT 3"
```

两边都要新增。`jsonl` 涨但 `secplane_alert` 不涨 → shipper 链路问题（先看 `CLAWMANAGER_AGENT_BASE_URL` / `CLAWMANAGER_INSTANCE_TOKEN` env 是否在 gateway 进程的 `/proc/<pid>/environ` 里）。

### 12.3 验证热重载
```bash
# Pod 上手动改 user_config.json
kubectl -n clawreef-user-U exec POD -- bash -c \
  'echo {"allDefensesEnabled":false} > /config/.openclaw/workspace/skills/claw-aegis/user_config.json'
# 然后在 openclaw 里发任意一句话
# 期望：下次 message_received 触发，logger 打 "user_config_hot_reload"
# 之前会告警的 trigger 这次不再告警
```

---

## 13. 已知待办

- [ ] `pattern` 字段真正下发并由 ClawAegis 消费（要求 ClawAegis 引入"用户规则"数据结构 + per-pattern attribution）
- [ ] `skill_blobs` 的 content-hash dedup 增加 `HeadObject` 检查，避免文件丢失情况下的 dedup 误命中
- [ ] agent 端加 `dump_aegis_config` 命令，让 effective-config 能选 "intent" 或 "actual"
- [ ] 把 ClawAegis 的 `postEventToSecplane` 失败时记录到本地 log，避免 silent fail（当前只能靠 inject debug 排查）
- [ ] backend 启动时校验 `aegis_assets/claw-aegis-base.zip` 与 host source code 的版本一致性
- [ ] CPU 节流监控接入 UI：`cpu_quota_usage_percent` 已经在 backend 算出来了，但前端只是优先用了它，缺超阈告警
- [ ] OpenClaw lsio 镜像 fork 修 xfsettingsd 泄漏，去掉运维 cleanup loop 依赖

---

## 14. 文档维护

代码变更涉及以下文件时，请同步更新本文：
- `backend/internal/secplane/compiler/aegis/compile.go`（映射表、bundle 字段）
- `backend/internal/secplane/dispatch/service.go`（idempotency、payload 形状）
- `ClawAegis/src/{config,handlers}.{ts,js}`（user_config schema、shipper、热重载）
- `backend/internal/secplane/aegis_assets/claw-aegis-base.zip`（重打后版本号 / sha 写入"已知问题"或 changelog 章节）
