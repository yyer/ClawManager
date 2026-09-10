# GitHub 增量同步规则（ClawManager）

## 1. 同步元数据

```yaml
upstream_repository: https://github.com/Yuan-lab-LLM/ClawManager.git
upstream_branch: main
target_branch: modelupdate
last_processed_upstream_commit: 378b58b1d5d28ca0125390a36a84d0a14ab7bdb8
last_reviewed_upstream_commit: 378b58b1d5d28ca0125390a36a84d0a14ab7bdb8
last_sync_date: 2026-09-09
```

- `last_processed_upstream_commit` 是同步检查点：从 GitHub `main` 的起点到该提交为止，每个同步单元都已经应用、适配或明确跳过。
- `last_reviewed_upstream_commit` 只表示已经完成功能分析，不能代替同步检查点。
- 仅执行 `fetch`、生成补丁或开始但未完成冲突处理时，不得推进同步检查点。
- 检查点必须使用完整的 40 位 GitHub commit SHA，不能记录本地改写后的 SHA。

## 2. 核心原则

1. 本仓库是包含 IEI、Northbound 和生产部署能力的下游分支，禁止直接将 GitHub `main` 全量 merge 到 `modelupdate`。
2. 每次只处理 `last_processed_upstream_commit..GitHub/main` 的增量。
3. 以 GitHub `main` 的 first-parent 提交为同步单元。一个 squash PR 或 merge PR 作为一个整体处理，不重复应用其中已经包含的内部提交。
4. 普通提交使用 `git cherry-pick --no-commit <SHA>` 提取变更；merge commit 使用 `git cherry-pick -m 1 --no-commit <SHA>`。检查、适配并测试后再创建本地提交。
5. 禁止对整个仓库或全部冲突统一使用 `ours`、`theirs`。冲突必须按业务和架构语义解决。
6. 每个同步单元只能有一种最终决策：
   - `applied`：按上游语义直接应用；
   - `adapted`：保留上游功能，但按本地架构进行了适配；
   - `skipped`：明确不引入，必须记录原因。
7. 只有同步单元完成测试并写入同步历史后，才可推进 `last_processed_upstream_commit`。

## 3. 标准同步流程

### 3.1 前置检查

- 必须位于本地 `modelupdate` 分支。
- 工作区和暂存区必须干净；用户未提交的文件不得混入同步提交。
- 确认不存在未完成的 merge、rebase 或 cherry-pick。
- fetch 必须使用本文记录的 GitHub 地址，不能把内部 GitLab 的 `origin`、`upstream` 或 `yuanchat` 当作 GitHub 来源。

建议使用独立的临时跟踪引用：

```text
git fetch https://github.com/Yuan-lab-LLM/ClawManager.git +refs/heads/main:refs/remotes/github-sync/main
```

### 3.2 计算增量

1. 从本文读取 `last_processed_upstream_commit`。
2. 验证该 SHA 仍是 `refs/remotes/github-sync/main` 的祖先；如果不是，说明 GitHub 历史可能被改写，必须停止并人工确认新的基线。
3. 使用 first-parent 顺序列出待处理单元：

```text
git log --first-parent --reverse <last_processed_upstream_commit>..refs/remotes/github-sync/main
```

4. 对每个单元先阅读提交说明、文件清单和 diff，形成 `applied`、`adapted` 或 `skipped` 决策后再修改代码。

### 3.3 应用和提交

- 按 first-parent 顺序逐个处理，不能把多个大型 PR 压成一个无法追溯的提交。
- 本地提交信息应保留上游主题，并增加以下 trailer：

```text
Upstream-Repository: Yuan-lab-LLM/ClawManager
Upstream-Commit: <完整 GitHub SHA>
Upstream-PR: #<编号或 N/A>
Sync-Decision: applied|adapted|skipped
```

- `skipped` 单元不创建空代码提交，但必须在本文同步历史中记录原因。
- 所有单元处理完并验证通过后，再更新本文的检查点和同步历史。

## 4. 冲突处理规则

### 4.1 必须保留的本地能力

- `backend/internal/northbound/`、Northbound gateway、API、文档和部署资源。
- IEI SSO、IEI 系统实例及对应前端页面。
- `deployments/k8s/sites/nine-node-production/` 下的九节点生产部署、备份、证书和运维脚本。
- 本地运行时类型、模型目录、配额、镜像配置和管理页面。
- 本地数据库 migration 及其已上线编号和执行顺序。

上游没有某个本地文件不等于要求删除该文件。默认保留本地实现；只有上游新功能明确替代旧实现、依赖方完成迁移且测试通过时，才允许删除。

### 4.2 默认接收并适配的上游内容

- 安全修复、代理隔离、认证边界和敏感信息脱敏。
- 新运行时契约、API 字段、前后端配套逻辑和测试。
- OpenCode 独立 Origin、Lite Web UI 和 Hermes Desktop 能力。

### 4.3 专项冲突规则

- 数据库 migration 不覆盖、不复用已有编号。发生编号冲突时，按本地最新编号重新编号，同时更新 migration 测试和运行时清单。
- 上游 Kubernetes、Nginx、域名、TLS、镜像地址和资源参数只移植新能力，不覆盖本地生产值。
- OpenCode 独立 Origin 必须与本地 ingress、Northbound 代理、共享实例和证书方案共同验证。
- Lite 禁止 TUI shell 是产品行为变更，必须验证不会影响 Pro、IEI 和其他运行时的 shell 入口。
- Hermes Desktop 的认证、WebSocket、代理策略需适配本地认证和 Northbound 架构，不能整体覆盖现有服务文件。
- Hermes Desktop Web 源码必须位于前端目录 `frontend/hermes-desktop-web/`；对外访问路径仍固定为 `/hermes-desktop-web/`。`package-lock.json` 和 `upstream.lock.json` 应整体采用明确版本或由规定工具重新生成，不能手工拼接。

## 5. 跨仓库依赖门槛

ClawManager 的 Hermes Desktop 同步依赖 AgentsRuntime。处理 PR #198 前必须确认：

- AgentsRuntime 已处理 PR #31 和 PR #32；
- AgentsRuntime 的同步检查点至少为 `9f4e3965b157ed45a347bfa2dc1469beb45e9b0a`；
- Hermes Lite/Pro 镜像、能力接口、健康检查和 Desktop 启动契约与 ClawManager 预期一致。

推荐顺序：AgentsRuntime PR #31 → AgentsRuntime PR #32 → ClawManager PR #196 → PR #197 → PR #198。

## 6. 验证门槛

至少完成以下检查；因环境限制无法执行的项目必须写入同步历史：

```text
cd backend && go test ./...
cd frontend && npm run lint && npm run build
```

引入或更新 `frontend/hermes-desktop-web/` 后还需执行该目录定义的测试和构建脚本，并运行相关 E2E 或定向 smoke test。此外必须：

- 检查代码库中不存在冲突标记。
- 检查数据库 migration 编号唯一且顺序正确。
- 验证本地 IEI、Northbound 和九节点生产部署文件未被意外删除或覆盖。
- 验证 OpenCode Lite/Pro 路由、shell 策略及 Hermes Desktop 代理路径。
- 记录对应的 AgentsRuntime 检查点和镜像版本。

## 7. 已处理的 GitHub 提交

| GitHub 单元 | GitHub commit | 对应本地 commit | 决策 | 说明 |
|---|---|---|---|---|
| PR #195 | `3216a4f34f0a49f700d328ee1a4013df1b0b98c6` | `938b9489b118bbf5d0eaee0ec935d38b55b215a9` | adapted | DSH remote UI 已按本地下游架构导入 |
| PR #196 | `a38322f2278bb9e0b4425f0966bf675c239b1294` | `f84d532e93f74086a14a98f3c9d9eb49bfb05f3f` | adapted | 引入 OpenCode 独立 Origin 与 nip.io 部署支持，保留本地 IEI、证书刷新、DeepSeek Origin 和长连接代理行为 |
| PR #197 | `8fd5de44d19a37d105da63d3cf23015b9b402ab5` | `1b7f627b3a005cbd348d5dd4259bfc266ebb912f` | adapted | OpenCode Lite 改用 Web UI 并禁用 Lite TUI；保留 Pro 和其他运行时 shell 行为 |
| PR #198 | `378b58b1d5d28ca0125390a36a84d0a14ab7bdb8` | `f2cb86b9b87d4c0a20396c8d78aead99ce8b3fe1` | adapted | 引入托管 Hermes Desktop、BFF/WS 鉴权、renderer 与 E2E；适配本地 IEI/Northbound、Origin 安全和无固定代理超时；当前同步检查点 |

## 8. 当前待同步单元

当前没有已知的待同步单元。下次同步从 `378b58b1d5d28ca0125390a36a84d0a14ab7bdb8` 之后开始。

## 9. 同步历史

| 日期 | 上游范围 | 处理结果 | 本地提交 | 验证结果 | 备注 |
|---|---|---|---|---|---|
| 2026-09-09 | `3216a4f34f0a49f700d328ee1a4013df1b0b98c6..378b58b1d5d28ca0125390a36a84d0a14ab7bdb8` | 完成功能分析，未执行代码同步 | N/A | N/A | PR #196、#197、#198 待处理；PR #198 依赖 AgentsRuntime PR #31、#32 |
| 2026-09-09 | `3216a4f34f0a49f700d328ee1a4013df1b0b98c6..378b58b1d5d28ca0125390a36a84d0a14ab7bdb8` | PR #196、#197、#198 均按本地架构适配完成 | `f84d532e93f74086a14a98f3c9d9eb49bfb05f3f`, `1b7f627b3a005cbd348d5dd4259bfc266ebb912f`, `f2cb86b9b87d4c0a20396c8d78aead99ce8b3fe1` | 后端 `go test ./...`；前端构建、变更文件 ESLint、11 项定向测试；Hermes Desktop Web 34 项测试、typecheck、15064 模块构建；E2E proxy 7 项与 fixture Go 测试均通过 | AgentsRuntime 检查点为 `9f4e3965b157ed45a347bfa2dc1469beb45e9b0a`；前端全库 lint 仍有 210 个既有问题，变更文件无 lint 错误；未执行 Docker 镜像构建、真实集群和 live-browser smoke |

## 10. 测试集群验证记录

### 2026-09-09：`10.130.14.23` / `clawmanager-system`

- 验证本地提交：`73730df0ec458162a87e7eaa2e84dbb3736debba`；对应 GitHub 检查点仍为 `378b58b1d5d28ca0125390a36a84d0a14ab7bdb8`。
- ClawManager 部署镜像固定为 `10.130.14.23:5000/clawmanager@sha256:dea4369fa1c0be8520e2181ecc93a2dcadb4d3f8b4ee6a27b8fc95458e0472f9`。Deployment revision 32，3/3 Ready、3/3 Available、Pod 重启数均为 0；其中一个 Pod 在 `node1` 成功拉取并运行该 digest。
- `/`、`/healthz`、`/api/v1/version`、`/hermes-desktop-web/` 和 `/hermes-desktop-web/build-info.json` 均返回 HTTP 200；版本接口返回提交 `73730df0ec458162a87e7eaa2e84dbb3736debba`。
- `e2e/hermes-desktop-smoke.mjs` 完成 26 项路由/认证检查；新建后运行的 Hermes Lite 实例 36 在 generation 4 上完成 live-browser 验证：12/12 BFF API 为 200、配置 schema 785 个字段、Artifacts 和 Skill Hub 正常、18/18 设置页签通过，浏览器错误与网络失败均为 0。
- `system_image_settings` 中 Hermes Lite 默认镜像已由浮动 `latest` 更新为 AgentsRuntime 的不可变 digest，保证后续新实例使用本次验证镜像。
- 候选运行时健康声明为 `artifacts_verified=true`、`release_accepted=false`；这表示构建产物已验证，但本次测试不替代正式发布接受流程。
- 基础设施遗留：`redis-data` 已请求由 1Gi 扩至 4Gi，但 Longhorn 卷处于 `degraded` 且文件系统仍为 1Gi，PVC 保持 `Resizing`。为继续测试，Redis 仅在当前进程内临时设置 `stop-writes-on-bgsave-error=no`、`save=""`；AOF 保持启用且写入状态正常。Redis Pod 重启会恢复原配置，在扩容完成前可能再次阻断 Hermes Desktop ticket 写入。
- 集群单节点 etcd 在测试期间出现过间歇性超时；最终 `/readyz` 通过，但 controller-manager 和 scheduler 存在约 2600 次历史重启。该问题属于测试集群基础设施风险，不能据此认定生产环境已通过验收。

### 2026-09-09：Hermes Lite 实例详情页纠正

- 纠正提交：`ef243b47a22ddb74848e1b54d02343b00733deb1`。同步适配曾遗漏向 `InstanceServiceFrame` 传递 `instance_mode`，导致 Hermes Lite 详情页错误进入传统 desktop access URL 流程；现已在 Lite 和 Pro 两个调用点恢复上游属性，并补充回归断言。
- 新镜像固定为 `10.130.14.23:5000/clawmanager@sha256:6ab3dc770f44030b3f20bf83a6fbe5fae5b6266731b661cd3f89e63a12cb36a4`。Deployment revision 34，3/3 Ready、3/3 Available、Pod 重启数均为 0，覆盖 `k8s-master` 和 `node1`。
- 不可变 digest 配合 `imagePullPolicy=IfNotPresent`，避免测试集群 kubelet 对本地已完整缓存镜像的重复拉取卡住；镜像内容和 registry manifest digest 已分别校验。
- 定向 contract test、Hermes Desktop 7 项单测和完整前端构建通过；定向 ESLint 仅命中 `InstanceDetailPage.tsx` 中 6 个既有 React Hooks 问题，本次变更在排除这两条既有规则后无新增 lint 错误。
- 对实例 `112233`（ID 36、generation 4）从真实 `/instances/36` 详情页复测通过：错误文案消失，Hermes iframe 正确加载 `/hermes-desktop-web/?instance_id=36`，capability probe/bootstrap 均为 HTTP 200，旧 `/api/v1/instances/36/access` 请求为 0，浏览器错误为 0。

### 2026-09-09：Hermes Lite Share Link 纠正

- 纠正提交：`51d76b11a460338fd9208f12376ae3fcb9d0871c`。PR #198 的本地适配仍让 Share Link 依赖传统 `GetProxyURLForInstance`；Hermes Lite/gateway 按设计不开放该代理入口，因此 `/s/<code>/` 在进入共享页面前返回 `Unable to generate access URL`。
- 共享入口现在为 Hermes Lite 生成同源 `/hermes-desktop-web/?instance_id=<id>` renderer 路径，并在共享 session 中签发 10 分钟、仅限 `/api/v1/instances/<id>/hermes-desktop/` 的 HttpOnly BFF Cookie。任何 Runtime 密码、访问令牌和 BFF 票据都不会进入浏览器 URL。
- Hermes BFF 会话绑定当前 Share Link 凭据版本；禁用分享、重置分享 URL、重置分享密码或分享过期后，旧会话的后续请求会被拒绝。普通实例拥有者的 Hermes Desktop 会话不受影响。
- 新镜像固定为 `10.130.14.23:5000/clawmanager@sha256:a582eb9daa24b87a8fd14a8fbffddf589645b4be746442af594b5f5ab242fe79`。Deployment revision 35，3/3 Ready、3/3 Available、3/3 Updated，Pod 重启数均为 0，覆盖 `k8s-master` 和 `node1`；版本接口返回提交 `51d76b11a460338fd9208f12376ae3fcb9d0871c`、构建时间 `2026-09-09T14:10:01Z`。
- 后端 `go test ./...`、共享页面和实例详情 contract test、完整前端生产构建、Hermes Desktop Web 34 项测试均通过。对真实 Share Link（实例 ID 42，Hermes Lite/gateway）进行全新未登录浏览器验收：入口 303 到共享页面，iframe 加载 `/hermes-desktop-web/?instance_id=42`，共享 session、workspace、renderer、Desktop session 和 Runtime API 均为 HTTP 200，浏览器异常与控制台错误均为 0。
- 此项是 GitHub PR #198 同步后的下游纠正，不代表新增 GitHub 同步单元，`last_processed_upstream_commit` 继续保持 `378b58b1d5d28ca0125390a36a84d0a14ab7bdb8`。

### 2026-09-09：Hermes 传统 Dashboard/TUI 清理

- 本地功能提交：`0f199a1f8ac9899ebee47583401b8eb67c2f7612`；配套 AgentsRuntime 提交：`c0a8eb837ab9637ad5f725d569d731b5d0ad1145`。
- 删除已废弃的 `deployments/hermes-runtime/Dockerfile.tui-dist`、controller 中的 `HERMES_TUI_DIR` 注入，以及 K8s/K3s 静态清单中的同名环境变量；历史数据库 migration 保持不变。
- 新 Hermes Lite Runtime 上报 `backend_mode=serve`。ClawManager 在滚动升级期间同时接受 `serve` 与旧 `dashboard` 能力值，避免尚未替换的运行时实例丢失 Desktop、Share Link、BFF 或 WebSocket 能力；新运行时自身只启动 headless `hermes serve`。
- 验证通过：后端 `go test ./...`、runtime deployment 定向测试，以及配套 AgentsRuntime 的完整镜像 smoke。九节点生产清单中用户已有的存储扩容修改与 README 修改未包含在功能提交中。
- 此项是本地下游清理，不是新的 GitHub 同步单元；`last_processed_upstream_commit` 继续保持 `378b58b1d5d28ca0125390a36a84d0a14ab7bdb8`。本记录不表示新镜像已部署到测试集群。

### 2026-09-10：modelupdate Hermes Desktop 功能验收与测试集群修复

- 本次验证代码提交：ClawManager `5577a45581b6933ab3ddc405faf55c0df4b6afee`；配套 AgentsRuntime `fd666f20a0ed750211a63506b116abebc054af97`。两者均已推送到各自 GitLab `modelupdate` 分支；本次没有新增 GitHub 上游同步单元，`last_processed_upstream_commit` 仍为 `378b58b1d5d28ca0125390a36a84d0a14ab7bdb8`。
- 测试集群 `10.130.14.23`、namespace `clawmanager-system` 已部署不可变镜像：ClawManager `10.130.14.23:5000/clawmanager@sha256:08376679168023043914278ce149680a212c055e26f40aea7833ca5b7a50edee`，Hermes Lite `10.130.14.23:5000/hermes-lite@sha256:b93b109f0d8eac4e55cff64250c9f8f029d88c1a4a82f382c0f5694421a12779`。`/api/v1/version` 返回 `modelupdate`、提交 `5577a45581b6933ab3ddc405faf55c0df4b6afee`。
- Hermes Lite 实例 45、46 的 Bootstrap GET/POST、实例 Session 均为 HTTP 200 且 `available=true`。未认证部署 smoke 完成 26 项检查（200×19、401×4、403×2、404×1）；renderer commit 为 `29112bef099274229cadff79cdff7bf7b99c4b77`，build input 为 `7a1ae777877befa8790913609ca76e7c0de4b8b976192e4d0aeabff3a610b565`。
- 真实 BFF WebSocket 闭环通过：Bootstrap cookie、ws-ticket、BFF WS、`ping`、`profiles.list` 均成功；按 Desktop 参数执行 `profiles.create`（默认 profile 克隆）、`session.create/activate`、`config.set`（`gpt-5.5/openai-api`）、`projects.create/list/delete` 全部成功。验证确认 Bot 创建、模型切换、项目创建不是 BFF 白名单问题；模型切换必须等待 session 从 `starting` 完成 Runtime agent hydration。
- Recent Logs 通过 `/api/v1/instances/45/hermes-desktop/api/logs` 返回 HTTP 200；`/api/profiles`、`/api/model/options?refresh=true` 返回 HTTP 200。IEI 使用实例实际 owner `chenqingshan@ieisystem.com` 的有效 SSO 会话后，实例列表、实例详情和 `/access` 均返回 HTTP 200，Hermes renderer 地址为同源 `/hermes-desktop-web/?instance_id=<id>`。
- Share Link 新建测试链接后，`/s/<code>/` 重定向到共享页面，shared session、Hermes Desktop session、Recent Logs、Profiles、Model Options 均为 HTTP 200。旧截图中的实例 42 已不存在（接口返回 404），不能用旧链接判断当前实现。
- 测试集群 Redis 曾因 `redis-data` 文件系统实际仍为 1Gi 且 `clawmanager:runtime-events` 累积约 236 万条导致 AOF 写满、Desktop ticket store 不可用。已在测试集群清理该 stream、压缩 AOF，设置 `save ""`、`stop-writes-on-bgsave-error no`，并将 Redis Deployment 改为 `Recreate`、固定 `node1` 以处理 RWO Longhorn 多挂载。当前 Redis `PING=PONG`、AOF write status 为 `ok`、`/data` 约 31% 使用率。该项是测试集群运维修复，未改变 GitHub 同步检查点；生产环境仍应完成 PVC 扩容并制定 stream 保留策略。
