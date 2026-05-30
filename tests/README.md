# ClawAegis 测试体系

两层测试，覆盖目的不同、跑法独立：

| 层 | 路径 | 跑法 | 时间 | 覆盖 |
|---|---|---|---|---|
| **method-a 单元** | `tests/method-a/` | `bash run.sh` | ~30s | 74 case · 12 hook · 直接驱 `createClawAegisRuntime` |
| **method-b 真链路** | `tests/method-b/` | `bash run.sh` | ~15-20 min | 13 case · 4 hook 类 · WS chat.send → openclaw → ClawAegis → defense-events.jsonl + secplane_alert 表 |

互补不互斥：
- method-a 跑得快、不依赖集群、可用作 PR 回归；74 case 覆盖每个 hook 的所有分支
- method-b 跑得慢、依赖真集群、验证"代码改对了"之外还能"部署+集成链路通"；约 30% method-a case 在真链路下可达（embedded runner 不 fire 部分 hook，结构性限制）

完整 case 清单：`method-a/CASES.md` · `method-b/CASES.md`

---

## 一句话跑法

```bash
bash ClawManager/tests/method-a/run.sh && bash ClawManager/tests/method-b/run.sh
```

method-b 全自治（prereq + setup + teardown 都包了），跑完集群状态自动还原。

---

## 跑前需要什么

**method-a**：
- node 22+
- ClawAegis 源码（`~/ClawManagerEx/ClawAegis/`）
- ClawManager 前端的 tsc（`ClawManager/frontend/node_modules/.bin/tsc` —— 即 `cd ClawManager/frontend && npm install` 跑过一次）

**method-b** 额外需要：
- minikube + docker
- ClawManager backend 镜像在 minikube 里（`clawmanager-secplane:dev34` 或更新）
- 三个常驻 deploy：`clawmanager-app` / `fake-llm` / `mysql`（命名空间 `clawreef-system`）
- vite dev server 可启动（自动，看下面）

冷启动机器要先做的（一次性 setup）：
```bash
# 装系统依赖（略）
git clone <repo> ~/ClawManagerEx
cd ~/ClawManagerEx/ClawManager/frontend && npm install

# minikube + backend 部署看 ClawManager/backend/deployments/minikube/
# 或参考 ~/start-clawmanager.sh
```

---

## method-b 自治细节

`run.sh` 按顺序自动检查/修复：

1. **prereq**
   - `minikube status` 不 Running → `minikube start`（除非 `METHOD_B_NO_MINIKUBE_START=1`）
   - `clawmanager-app` / `fake-llm` / `mysql` pod 不 Running → 报错（不自动修，因为可能是镜像没 build）
   - vite 9002 不在监听 → `cd frontend && nohup npm run dev`，等 ready
   - 后端 `/api/v1/auth/login` HTTP 200 验证

2. **setup**（Python harness 入口）
   - snapshot `llm_models` 当前状态 → `/tmp/method-b-llm-models-snapshot.json`
   - 改 `ds.is_active=0` + `e2e-fake-llm.is_secure=1`（让 auto/敏感都路由 fake-llm）
   - 看 instance pod 状态，不 Running 就调 `/api/v1/instances/N/start` API + 等 Running + 6s gateway grace

3. **run**：跑 case 套件，单 case flake 自动 retry 1 次（可调 `METHOD_B_MAX_ATTEMPTS`），case 间 4-6s 冷却

4. **teardown**（即使中途异常也会跑）
   - 从 snapshot 还原 `llm_models`，删 snapshot 文件
   - 若 instance 是 setup 起的 → 调 stop API

---

## env 覆盖速查

```bash
METHOD_B_API=http://localhost:9002        # 后端入口
METHOD_B_INSTANCE_ID=9                    # 目标 instance
METHOD_B_POD=clawreef-9-test10            # 实例 pod 名
METHOD_B_POD_NS=clawreef-user-1
METHOD_B_MYSQL_DEPLOY=deploy/mysql
METHOD_B_MYSQL_NS=clawreef-system
METHOD_B_MYSQL_PWD=123456
METHOD_B_FAKE_LLM_RELAY=deploy/mysql      # 跑 curl 的 cluster 内 pod
METHOD_B_FAKE_LLM_URL=http://fake-llm:8080
METHOD_B_COOLDOWN_S=4                     # case 间冷却
METHOD_B_MAX_ATTEMPTS=2                   # 每 case 最多尝试次数（1 = 不重试）
METHOD_B_SKIP_PREREQ=1                    # 跳 prereq 自检
METHOD_B_NO_MINIKUBE_START=1              # minikube 停了只报错
METHOD_B_NO_SETUP=1                       # 跳 setup（DB / instance 全自己 ready）
METHOD_B_NO_TEARDOWN=1                    # 跳 teardown（保留 DB 改动 + instance 跑）
METHOD_B_SNAPSHOT=/tmp/method-b-llm-models-snapshot.json
```

---

## 跑完怎么验"真的过了"

退出码 + 末行：
- method-a：末行 `74/74 passed`，退出码 0
- method-b：末行 `13/13 passed` + 紧跟 `[teardown] llm_models 已还原到 setup 前状态` + `[teardown] instance N stop API OK`，退出码 0

集群干净度（method-b 跑完应该这样）：
```bash
kubectl -n clawreef-user-1 get pods
# 期望: No resources found

kubectl -n clawreef-system exec deploy/mysql -- mysql -uroot -p123456 -D clawreef -e \
  "SELECT display_name, is_active, is_secure FROM llm_models WHERE display_name IN ('ds','e2e-fake-llm')"
# 期望: ds=1,0 / e2e-fake-llm=1,0（测试前的态）

ls /tmp/method-b-llm-models-snapshot.json
# 期望: No such file（snapshot 已删）
```

---

## 常见 fail 模式

| 现象 | 原因 | 修法 |
|---|---|---|
| method-a 个别 FAIL | ClawAegis `.ts` 改了但 `.js` 没同步 | method-a harness 自己 tsc 编译，应该不会发生；若发生，手动重跑 |
| method-b prereq 报"关键 pod 不 Running" | 集群挂了 / backend 镜像没 build | `kubectl -n clawreef-system get pods` 看；`docker images clawmanager-secplane` 看镜像；按冷启动步骤重做 |
| method-b 卡 setup 等 pod Running | 资源不足 / 镜像拉不下 | `kubectl -n clawreef-user-1 describe pod ...` 看 events；OOM 就加 `minikube --memory=` |
| 某 case 反复 retry 失败 | postEventToSecplane 拥塞 / openclaw 重启慢 | `METHOD_B_COOLDOWN_S=10 METHOD_B_MAX_ATTEMPTS=3 bash run.sh` 给更宽空间 |
| `fake-llm POST rc=7` 反复 | kubectl exec mysql 关 curl 拥塞 | client 已加 3 次重试；若仍挂，`kubectl describe pod -l app=mysql` 看 mysql |
| teardown 没跑（Ctrl-C 中断） | snapshot 留在 /tmp，DB 没还原 | 下次跑 run.sh 时 setup 会发现 snapshot 已存在跳过新 snapshot，但 teardown 仍能从它还原；或手动 `kubectl ... mysql -e "UPDATE ..."` 然后 `rm /tmp/method-b-llm-models-snapshot.json` |
| run.sh `| tail` 时假死 | `tail -N` 直到 pipeline 关才吐内容 | 别加 `\| tail`；直接看 stdout 或重定向到文件 |

---

## 不可达的 hook（method-b 测不了）

| Hook | 为什么 |
|---|---|
| `before_dispatch` / `before_agent_reply` | chat.send 走 embedded runner，不进 dispatchReplyFromConfig 路径 |
| `before_tool_call` / `after_tool_call` | embedded 跳过工具 dispatch |
| `llm_output` | embedded 调 runLlmOutput 但 ClawAegis 实测不 emit；行为待深入诊断（短期跳过）|
| `gateway_start` | 只 pod 启动时 fire；要测必须重启 |
| `session_end` | 需 sessions.reset RPC，没接 |

这些 hook 留 method-a 单元覆盖（method-a 全 12 hook 已覆盖 74 case）。

---

## 关联文档

- `tests/method-a/CASES.md` — 74 case 详细清单（含每条 case 的 docstring + 期望）
- `tests/method-b/CASES.md` — 13 case 详细清单
- 设计/工程坑：项目 memory 系统（`~/.claude/projects/-home-xuzheng-ClawManagerEx/memory/MEMORY.md` 索引）里搜 `project_method_a_harness` / `project_method_b_harness`
