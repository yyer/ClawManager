# Hermes Lite Web 能力修复设计

## 背景

测试集群中的 Hermes Lite Desktop Web 当前有五类问题：Recent Logs 在浏览器 Bridge 被拒绝；Hermes Lite 实例通过 IEI 生成访问地址失败；模型切换被 `--global`/`--session` 策略拒绝；Bots 和 Create Project 被 Web 适配层及 Runtime RPC 策略禁用；部分会话请求还会因模型 Provider 网络不可达而失败。

本设计只修复 ClawManager 与 AgentsRuntime 中由 Web 安全边界、实例会话和 Lite RPC 策略造成的问题。Provider 地址 `172.16.5.24:8000` 的路由故障属于集群/Provider 配置，不由本变更伪装成应用层成功。

## 目标与非目标

### 目标

1. Hermes Lite 实例通过 IEI 生成可用的实例级 Desktop Web 地址。
2. Recent Logs 支持只读查看、筛选和搜索，并保持实例隔离与日志脱敏。
3. Desktop Web 支持实例内可用的 Hermes API；不再维护会阻止正常功能的静态“功能白名单”。
4. 模型切换、Bots 和项目操作在当前实例工作区内可用。
5. 所有跨边界输入仍经过认证、实例授权、路径格式、大小/类型和敏感信息校验。

### 非目标

1. 不开放任意实例、任意 Profile、任意主机文件系统或任意绝对路径。
2. 不让 Desktop Web 改变 ClawManager 的用户/实例授权模型。
3. 不修复外部 Provider 的路由或模型服务本身。
4. 不恢复已删除的传统 Hermes TUI/Dashboard。

## 设计

### 1. Desktop Web API 代理

前端 Bridge 和后端 BFF 不再按 endpoint 名称维护功能白名单。二者改为通用的安全代理规则：

- 只接受规范化的 `/api/...` 路径，拒绝编码路径、反斜杠、片段、重复查询键和超长请求。
- GET/POST/PUT/PATCH/DELETE 等方法由 Runtime 处理；BFF 仍要求有效 Hermes Desktop 会话和当前实例授权。
- 去掉 `profile`/`connectionId` 对当前实例 Web Bridge 的外部路由能力；Runtime 请求只能落到已认证的实例工作区。
- 请求体、查询参数和响应大小受限；响应统一经过现有敏感字段和实例凭据脱敏。
- `/api/logs` 作为普通只读 Runtime API 通过通用路径；前端日志组件仍限制 `file`、`level`、`lines`、`component`、`search` 的格式与大小，避免无限读取。

这样既满足“全部 API 支持”的功能要求，也不会把当前实例的代理边界变成任意主机代理。

### 2. IEI Hermes Lite 访问

`GenerateInstanceAccess` 对 Hermes Lite 不再调用空的原始代理 URL。它复用 `HermesDesktopService.Activate(userID, instanceID)`：

1. 保留 IEI 的登录、实例归属、运行状态和生命周期检查。
2. 激活实例级 Hermes Desktop 会话。
3. 写入路径限定为该实例 Desktop Web 前缀的 HttpOnly、SameSite Cookie。
4. 返回 `/hermes-desktop-web/?instance_id=<id>` 及过期时间。

传统 DSH/代理型 Runtime 保留现有 token bootstrap 行为。

### 3. Model Switch

Web Desktop 对当前会话的模型切换统一生成 `--session` 配置，不把浏览器请求转换成全局 Runtime 配置。后端和 Lite Runtime 对模型/provider/catalog 继续做实际可用性校验，避免把 Provider 不可达伪装成切换成功。

### 4. Bots

Bots 只使用当前实例内的命名 Profile：

- Profile 名称限制为小写字母/数字开头，后续仅允许小写字母、数字、下划线和连字符，长度有限。
- 支持 Profiles 的 list/describe/create/configure/asset RPC，以及 Bot Chat 所需的 session list/create/title/open/resume 路由。
- Profile home 由 Runtime 固定解析到当前实例的 Hermes home；请求不能传入任意工作区或主机路径。
- 前端不暴露外部连接切换。

### 5. Create Project

项目只绑定当前实例的整个 workspace：项目记录可以在 workspace 内创建和列出，但创建、扫描、更新和文件选择不能指定 workspace 外的路径。Web 端去掉“不可用”占位；目录选择返回当前 workspace 的相对项或 workspace 根，不接受任意绝对路径。Runtime 的项目 API 需要把路径解析后校验为 workspace 的子路径，并拒绝路径穿越。

## 错误处理

- 未认证/会话过期：401。
- 当前实例不可用或 Runtime 不可达：503/502，保持现有错误语义。
- 不符合安全边界的路径、参数、Profile 或 workspace 路径：403/400。
- Provider 无路由：返回真实 Runtime 上游错误，并在 UI 保持可重试/切换 Provider 的提示。

## 测试策略

测试先行，至少覆盖：

1. Bridge 和 BFF 接受 `/api/logs` 及其他合法 Runtime API，拒绝编码路径、重复键、超长参数和外部 Profile/connection 路由。
2. 日志响应中不出现实例 token、Cookie、password、authorization、API key 等敏感字段。
3. IEI Lite 访问返回 Desktop Web URL 并设置实例 Cookie；非 Lite 路径保持原 token URL。
4. Model switch 使用 `--session`，错误 Provider 仍失败。
5. Profile RPC 使用合法命名 Profile；跨 Profile/路径穿越被拒绝。
6. Project 只能在当前 workspace 根及其子目录内操作，`..`、绝对路径和符号链接逃逸被拒绝。
7. 两个仓库的现有测试、构建和容器 smoke test 通过后，才更新测试集群。

## 发布与回滚

先在本地完成 ClawManager 单测、前端单测、AgentsRuntime Lite 单测和镜像 smoke test；再构建带唯一 tag 的 backend/frontend/runtime 镜像，在 `clawmanager-system` 部署并执行功能回归。保留现有部署清单和镜像 tag，出现问题时只回滚本次新 tag，不触碰用户已有生产 YAML/README 改动。
