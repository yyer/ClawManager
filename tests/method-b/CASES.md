# ClawAegis Method-B 真链路 e2e 用例清单

位置：`ClawManager/tests/method-b/cases/`
运行：`METHOD_B_COOLDOWN_S=6 bash ClawManager/tests/method-b/run.sh [filter]`

- 共 13 case（4 分类）
- 每条 case 跑 5 步：PUT rule → dispatch → fake-llm queue → WS chat.send → assert jsonl/alert/log
- 真链路依赖：minikube + ClawManager dev34 + test10 实例 + fake-llm + vite 9002

---

## message_received (user_risk_scan)

| # | case | 一句话 |
|---|---|---|
| 1 | `01_message_received_jailbreak` | Case 01: jailbreak-bypass enforce → blocked event + alert。 |
| 2 | `02_message_received_system_prompt_exfil` | Case 02: system-prompt-exfiltration enforce → blocked event + alert。 |
| 3 | `03_message_received_observe_mode` | Case 03: jailbreak-bypass observeOnly → observed event (不 blocked), 不 emit alert (action=observed)。 |
| 4 | `04_message_received_disabled_flag` | Case 04: jailbreak-bypass is_enabled=false → 该 flag 进 disabledUserRiskFlags，不产 event 不产 alert。 |
| 5 | `05_message_received_scan_off` | Case 05: defense.userRiskScan is_enabled=false → user_config.userRiskScanEnabled=false → message_received 早 return, 无 ev |
| 6 | `06_message_received_clean` | Case 06: 普通内容（无任何 risk pattern）→ message_received 跑但 result=clear, 无 event 无 alert。 |

### `01_message_received_jailbreak`

```
Case 01: jailbreak-bypass enforce → blocked event + alert。

镜像 method-a 的 "user_risk_scan — jailbreak 触发 enforce → blocked event"。
```

### `02_message_received_system_prompt_exfil`

```
Case 02: system-prompt-exfiltration enforce → blocked event + alert。
```

### `03_message_received_observe_mode`

```
Case 03: jailbreak-bypass observeOnly → observed event (不 blocked), 不 emit alert (action=observed)。

method-a 的 "jailbreak 在 observeOnly 集合里 → observed event 不 blocked"。
```

### `04_message_received_disabled_flag`

```
Case 04: jailbreak-bypass is_enabled=false → 该 flag 进 disabledUserRiskFlags，不产 event 不产 alert。

method-a 的 "jailbreak 在 disabled 集合里 → 无 event"。
```

### `05_message_received_scan_off`

```
Case 05: defense.userRiskScan is_enabled=false → user_config.userRiskScanEnabled=false → message_received 早 return, 无 event 无 alert。

method-a 的 "userRiskScanEnabled=false → 无 event"。
```

### `06_message_received_clean`

```
Case 06: 普通内容（无任何 risk pattern）→ message_received 跑但 result=clear, 无 event 无 alert。

method-a 的 "普通内容无命中 → 无 event"。
```

## output_redaction (before_message_write assistant)

| # | case | 一句话 |
|---|---|---|
| 1 | `07_output_redaction_bearer` | Case 07: before_message_write (assistant) - Bearer token in assistant text → output_redaction observed event。 |
| 2 | `08_output_redaction_api_key` | Case 08: api_key 赋值在 assistant text → output_redaction observed event。 |
| 3 | `09_output_redaction_clean` | Case 09: 普通 assistant text → 不脱敏，无 output_redaction event。 |
| 4 | `10_output_redaction_off` | Case 10: defense.outputRedaction is_enabled=false → user_config.outputRedactionEnabled=false |

### `07_output_redaction_bearer`

```
Case 07: before_message_write (assistant) - Bearer token in assistant text → output_redaction observed event。

fake-llm 返带 Bearer 的 assistant text → openclaw 收完 LLM 响应后跑 before_message_write
→ ClawAegis output_redaction 命中 SENSITIVE_OUTPUT_BEARER_RE → emit observed event。
```

### `08_output_redaction_api_key`

```
Case 08: api_key 赋值在 assistant text → output_redaction observed event。

测的是 SENSITIVE_OUTPUT_QUOTED_ASSIGNMENT_RE 路径（api_key/secret/token 等 keyword + 引号值）。
```

### `09_output_redaction_clean`

```
Case 09: 普通 assistant text → 不脱敏，无 output_redaction event。
```

### `10_output_redaction_off`

```
Case 10: defense.outputRedaction is_enabled=false → user_config.outputRedactionEnabled=false
→ before_message_write 早 return, 即便 assistant text 含 Bearer 也不脱敏不 emit。
```

## prompt_guard (before_prompt_build)

| # | case | 一句话 |
|---|---|---|
| 1 | `12_prompt_guard_static_only` | Case 12: before_prompt_build - promptGuard enabled + 干净 session → 静态 system context 注入。 |
| 2 | `13_prompt_guard_off` | Case 13: promptGuard off → before_prompt_build 早 return disabled。 |

### `12_prompt_guard_static_only`

```
Case 12: before_prompt_build - promptGuard enabled + 干净 session → 静态 system context 注入。

期望 pod log 出现:
  defense_check_result hook=before_prompt_build mechanism=prompt_guard result=static_only_injected

不验 jsonl/alert，因为 static-only 不 emit defense event（只有 dynamic context
才 emit prompt_guard observed）。
```

### `13_prompt_guard_off`

```
Case 13: promptGuard off → before_prompt_build 早 return disabled。

pod log 期望:
  defense_check_result hook=before_prompt_build mechanism=prompt_guard result=disabled
```

## agent_end (state clear)

| # | case | 一句话 |
|---|---|---|
| 1 | `14_agent_end_state_clear` | Case 14: agent_end 在 turn 结束时 fire + 清 state. |

### `14_agent_end_state_clear`

```
Case 14: agent_end 在 turn 结束时 fire + 清 state.

简化版：只验单 turn agent_end log 出现且 sessionKey 匹配。
agent_end hook 在 embedded runner 末尾被调（已实证），这条 case 是个最小烟雾测试。
```

---

## 期望分类对应的断言路径

| Hook 类 | 验证方式 | 用到的工具 |
|---|---|---|
| `message_received` user_risk_scan | jsonl 含 `defense=user_risk_scan` + alert 表新行 | `DefenseEventsTail` + `SecplaneAlerts` |
| `before_message_write` output_redaction | jsonl 含 `defense=output_redaction` + alert 表新行 | 同上 |
| `before_prompt_build` prompt_guard | static-only / disabled 不写 jsonl，验 pod log | `PodLogTail.wait_for` |
| `agent_end` | 不写 jsonl，验 pod log `agent_runtime_state_cleared` | `PodLogTail.wait_for` |

## embedded runner 不可达 hook (留 method-a 覆盖)

- `before_dispatch` / `before_agent_reply` — chat.send 不走 dispatchReplyFromConfig
- `before_tool_call` / `after_tool_call` — embedded 跳过工具 dispatch 路径
- `llm_output` — embedded 代码会调 runLlmOutput 但 ClawAegis prompt_self_block 实测不 emit；行为待深入诊断
- `gateway_start` — 只 pod 启动时；要测必须重启
- `session_end` — 需 sessions.reset RPC

生成时间：自动