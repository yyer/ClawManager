# GitHub 增量同步规则（ClawManager）

## 1. 同步元数据

```yaml
upstream_repository: https://github.com/Yuan-lab-LLM/ClawManager.git
upstream_branch: main
target_branch: modelupdate
last_processed_upstream_commit: 3216a4f34f0a49f700d328ee1a4013df1b0b98c6
last_reviewed_upstream_commit: 378b58b1d5d28ca0125390a36a84d0a14ab7bdb8
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
- 新增 `hermes-desktop-web/` 时优先保留上游目录结构；`package-lock.json` 和 `upstream.lock.json` 应整体采用明确版本或由规定工具重新生成，不能手工拼接。

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

引入 `hermes-desktop-web/` 后还需执行该目录定义的测试和构建脚本，并运行相关 E2E 或定向 smoke test。此外必须：

- 检查代码库中不存在冲突标记。
- 检查数据库 migration 编号唯一且顺序正确。
- 验证本地 IEI、Northbound 和九节点生产部署文件未被意外删除或覆盖。
- 验证 OpenCode Lite/Pro 路由、shell 策略及 Hermes Desktop 代理路径。
- 记录对应的 AgentsRuntime 检查点和镜像版本。

## 7. 已处理的 GitHub 提交

| GitHub 单元 | GitHub commit | 对应本地 commit | 决策 | 说明 |
|---|---|---|---|---|
| PR #195 | `3216a4f34f0a49f700d328ee1a4013df1b0b98c6` | `938b9489b118bbf5d0eaee0ec935d38b55b215a9` | adapted | DSH remote UI 已按本地下游架构导入；当前同步检查点 |

## 8. 当前待同步单元

| 顺序 | GitHub 单元 | GitHub commit | 功能摘要 | 状态 |
|---|---|---|---|---|
| 1 | PR #196 | `a38322f2278bb9e0b4425f0966bf675c239b1294` | OpenCode 实例独立 Origin、Nginx 路由及 nip.io TLS | reviewed / pending |
| 2 | PR #197 | `8fd5de44d19a37d105da63d3cf23015b9b402ab5` | Lite 使用 Web UI，并禁用 Lite TUI shell | reviewed / pending |
| 3 | PR #198 | `378b58b1d5d28ca0125390a36a84d0a14ab7bdb8` | 托管 Hermes Desktop、代理鉴权、前端和 E2E | reviewed / pending |

完成本轮同步后，应把检查点推进到 `378b58b1d5d28ca0125390a36a84d0a14ab7bdb8`，补充对应本地提交和测试结果，并清空或更新本节。

## 9. 同步历史

| 日期 | 上游范围 | 处理结果 | 本地提交 | 验证结果 | 备注 |
|---|---|---|---|---|---|
| 2026-09-09 | `3216a4f34f0a49f700d328ee1a4013df1b0b98c6..378b58b1d5d28ca0125390a36a84d0a14ab7bdb8` | 完成功能分析，未执行代码同步 | N/A | N/A | PR #196、#197、#198 待处理；PR #198 依赖 AgentsRuntime PR #31、#32 |
