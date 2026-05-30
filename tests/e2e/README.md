# E2E 测试骨架 — Approach B (Mock LLM Gateway)

最小可运行的端到端测试骨架。让 fake LLM 在测试中返回可控的工具调用，沿
"openclaw → ClawAegis → secplane 告警表"这条真链路 assert 防御命中。

## 组成

```
tests/e2e/
├── README.md                      # 本文件
├── fake_llm.py                    # OpenAI 兼容的假 LLM + 测试控制 API
├── deploy-fake-llm.yaml           # k8s 部署清单 (clawreef-system/Service:8080)
├── harness.py                     # 后端 admin API 包装 + 告警轮询 + fake LLM 控制
└── cases/
    └── outbound_trust_block.py    # 示例 case
```

## 已经能跑的

- ✅ fake LLM 服务（OpenAI 兼容 + `/__test__/next` 排响应）
- ✅ harness.Backend: login / set_defense_mode / outbound CRUD / kill switch / dispatch / wait_for_alert
- ✅ FakeLLMClient: reset / expect_tool_call / expect_text / log
- ✅ 一条样板 case，跑完两次 dispatch + 一次告警断言

## 还没自动化的（手工补一下就跑通）

1. **WebChat 输入注入** — `harness.send_user_message()` 当前是 `manual` 模式：把消息打到 stderr，让你手动粘到 webchat。两种自动化思路：
   - Playwright 驱浏览器（贴近 + 慢）
   - 直接 WebSocket 接 `:18789`（更快，但需实现 connect.challenge 握手）

2. **实例的 LLM gateway 指到 fake LLM** — 当前需要先在 ClawManager UI 里
   配一个 model 指向 `http://fake-llm.clawreef-system.svc.cluster.local:8080/v1`，
   并把测试实例切到这个 model；后续应该写脚本一键配置。

## 跑 outbound_trust_block 这个 case

### 1. 把 fake_llm.py 部署到集群

```bash
cd tests/e2e
kubectl -n clawreef-system create configmap fake-llm-src \
    --from-file=fake_llm.py=./fake_llm.py \
    --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy-fake-llm.yaml
kubectl -n clawreef-system rollout status deployment/fake-llm
```

### 2. 把测试实例的 LLM 切到 fake-llm

ClawManager UI → Models → 新建 model：

- name: `e2e-fake-llm`
- base URL: `http://fake-llm.clawreef-system.svc.cluster.local:8080/v1`
- API Key: 任意，假 LLM 不校验

测试实例 → 设置 → 选 `e2e-fake-llm` model。

### 3. host 端 port-forward fake LLM 到本机（便于 harness 控制）

```bash
kubectl -n clawreef-system port-forward svc/fake-llm 8080:8080 &
```

### 4. 跑 case

```bash
export CLAWMANAGER_URL=http://$(minikube ip):30901
export INSTANCE_ID=9                              # test10 的 id
export AGENT_ID=instance-9-aegis                  # 看 alert 里实际形态
export FAKE_LLM_URL=http://127.0.0.1:8080

python3 cases/outbound_trust_block.py
```

预期输出：

```
[1/7] 登录 OK → http://...
[2/7] fake LLM 队列已清 → http://127.0.0.1:8080
[3/7] 策略: outboundTrust=enforce, requireHttps=off, 白名单=[api.openai.com]
[4/7] dispatch_apply OK → revision=... targets=1
[5/7] fake LLM 已排入 tool_call → https://api.evil.com/exfil
  >>> 请在 instance 9 的 webchat 里粘贴这条消息（按 Enter）:
      请用 http_get 工具访问 https://api.evil.com/exfil
      [harness 正在等待告警…]
[6/7] 等待 defense.outboundTrust 告警 (timeout 60s) …
[7/7] PASS — alert.id=... severity=high action=blocked
       evidence: 未在出站白名单：api.evil.com (https://api.evil.com/exfil)
```

## 后续要补的 cases（顺手能写）

| case | 验证点 | 大致脚本 |
|---|---|---|
| `require_https_block.py` | 工具调用参数里 http:// 必须被 enforce 拦下 | fake LLM 排 tool_call(url=http://evil) |
| `outbound_trust_allow.py` | 白名单内的 https 必须放行 | fake LLM 排 tool_call(url=https://api.openai.com/...) + assert 无 outbound_trust 告警 |
| `kill_switch_block.py` | 启用熔断后所有工具调用都被拒 | kill_switch=on + fake LLM 排任意 tool_call + assert kill_switch 告警 |
| `wildcard_match.py` | `*.example.com` 通配生效 | 白名单加 `*.openai.com` + tool_call(url=https://api.openai.com/...) |
| `fingerprint_drift.py` | 后台 watcher 在指纹漂移时告警 | mock 一个 host 指纹手工塞错 + 等 watcher 巡检 |

## 维护建议

- fake_llm.py 改了之后要重做 configmap 并 rollout restart deployment：

  ```bash
  kubectl -n clawreef-system create configmap fake-llm-src \
      --from-file=fake_llm.py=./fake_llm.py \
      --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n clawreef-system rollout restart deployment/fake-llm
  ```

- harness.py 是纯 stdlib，不用装依赖。Python 3.10+。
- 多条 case 跑同一个实例时记得在每个 case 开头 reset 状态，避免污染。

## 实测踩坑清单（2026-05-29，第一次端到端）

下面这些坑是真实摸出来的，下次再跑前先逐项确认，免得重复花时间。

### 1. openclaw → fake-llm 路径的 6 层阻碍

| # | 问题 | 现象 | 已经修法 | 是否会复发 |
|---|---|---|---|---|
| 1 | NetworkPolicy 没开 8080 端口 | openclaw 直连 fake-llm timeout (curl 28) | `kubectl patch netpol clawreef-N-test-netpol` 加 8080 egress | ✅ pod 重建会丢，每次得重打 |
| 2 | pod resolv.conf `ndots:5` 让 `*.svc.cluster.local` FQDN 解析慢 6 秒 | curl `-m 4` 必 timeout | openclaw provider 的 `baseUrl` 改成 Service ClusterIP，或写 `/etc/hosts` 绕开 | ✅ 重建丢 |
| 3 | openclaw pod 强制 HTTP_PROXY → egress-proxy；fake-llm 不在 NO_PROXY | LLM 调用被劫持，走代理但代理也撞 #2 | egress-proxy 本身**不限白名单**，所以走它转发 OK；或者用 ClusterIP 让所有 hop 都不靠 DNS | 永久（这就是设计） |
| 4 | ClawManager `selectAutoModel` 按 `display_name` ASC 取第一个 active 非 secure | "auto" → `ds`，根本不路由到 `e2e-fake-llm` | DB UPDATE `is_active=0` 的 `ds`，让 fake-llm 成唯一非 secure active | 改 DB 即可，但要记得测完还原 |
| 5 | ClawManager 风险检测把含 evil URL 的请求判敏感 → 路由到 secure model，没有就 403 | "sensitive content requires an active secure model" | 把 `e2e-fake-llm` 也置 `is_secure=1`，敏感+非敏感都走它 | 同上 |
| 6 | openclaw 默认插件 loader 检 `extensions/<plugin>` 目录 owner == root，否则拒绝；ClawAegis 用 install_skill 落地后是 `abc:abc` | `defense-events.jsonl` 不再被写入，但 `user_config.json` 一切正常误以为生效 | `chown -R 0:0 /config/.openclaw/extensions/claw-aegis` + 在 `openclaw.json` 的 `plugins.entries` 显式加 `"claw-aegis": {"enabled": true}` + `openclaw gateway --force` | ✅ pod 重建后必复发 |

### 2. 仍未完全验证的最后一公里

| 问题 | 当前认知 |
|---|---|
| **SSE 流式响应** | openclaw 发 `stream=true`，ClawManager `StreamChatCompletions` 期望 SSE chunks。fake_llm.py 已加 `_send_sse()` 把一次性 JSON 切成 chunks (role → tool_calls → finish + `data: [DONE]`)，但 port-forward 反复掉线没成功端到端验通。下次先单独 `curl -sN -d '{"stream":true,...}'` 验 SSE 长得对。 |
| **incomplete turn / payloads=0** | gateway log 报 `incomplete turn detected: ... stopReason=stop payloads=0 — surfacing error to user`。可能是 SSE 解析失败（最有可能），也可能 openclaw 期望先把 `http_get` 注册成 tool 才接 tool_call，我们没注册。 |
| **defense-events.jsonl 没新增** | ClawAegis 是否真正进了 `before_tool_call`？尚未证实今天有 fire 过。 |

### 3. 下次接着搞的 1-2 小时 checklist

1. **fake-llm SSE 验通**：
   - 起 fake-llm + port-forward
   - `curl -sN -d '{"stream":true,...}'` 应该看到多条 `data: {...}` + `data: [DONE]`
   - 如果 openclaw 仍 incomplete，加 `tools=[{...}]` schema 到 request（或检查 fake-llm 返的 tool_call 字段对不对）
2. **dispatch 后自动 chown + plugins.entries 注入**：
   - 改 ClawManager backend 的 install_skill 实现：解 zip 后 `os.Chown(...)` 到 root；同时 patch openclaw.json `plugins.entries[plugin_id] = {enabled: true}`
   - 一次搞定 #1.6 复发问题
3. **harness pre-flight 自检**：
   - 跑测前先验证 fake-llm 队列 reset OK、netpol 已 patch、目标实例的 plugins.entries 有 claw-aegis、ClawAegis 目录 owner == root；不通过就立刻 FAIL，省排查时间
4. **测试机隔离**：
   - 用 `test-e2e` 命名 + 独立 user namespace，避免污染 test10（你已踩过这个坑）

### 4. 跟方法 A（直接钩子注入）的对比

方法 B 想跑真链路要解 6 层；方法 A `kubectl exec` 进 pod 跑 Node 调 `createClawAegisRuntime(api, ...)` 直接喂 `before_tool_call` 事件，**只测 ClawAegis 内部**，不经 openclaw/LLM/任何中间组件。30 分钟能写出来，CI 跑得稳。

如果只是要 ClawAegis 单元/逻辑回归，A 完全够用；如果要验"整条线"，才有必要继续打磨 B。两者**不互斥**，建议 A 优先做。
