# 个人项目交接（2026-09-14）

## 1. 先确认工作目录，不能混用个人与团队项目

| 用途 | 路径 | 本次核实分支 |
| --- | --- | --- |
| **个人 ClawManager，后续主要工作位置** | `D:/test/gitlab/clawmanager` | `codex/northbound-all-pro-runtime` |
| **个人 AgentsRuntime** | `D:/test/gitlab/agentsruntime` | `master` |
| 团队 ClawManager，只读参考，不在这里实施个人需求 | `D:/test/ClawManager-2` | `codex/team-upstream-20260909-clean` |
| 团队 AgentsRuntime，只读参考 | `D:/test/AgentsRuntime` | `codex/team-upstream-20260909-clean` |

桌面新对话可能仍默认 cwd 为 `D:/test/ClawManager-2`，这不是个人仓库！工具执行必须显式指定个人仓库 workdir。另有 `clawmanager-private` 目录，不要自行替代本表两个个人项目。

个人仓库 origin 是 GitLab `http://10.128.4.12:6880/hanxingchen/{clawmanager,agentsruntime}.git`；upstream 是同服务器 `yuanchat/{clawmanager,agentsruntime}.git`。

个人与团队分支是分别维护的代码线，不是可以随意互换的工作目录。团队版包含 Team 和其专用适配，不能整体合并到个人版。用户最近要求核查兼容问题时只比较“个人 upstream、合并前、合并后”，不要拿团队版代替上游证据。只有用户明确需要通用修复参考时才独立分析，不夹带 Team 功能。

## 2. Git 状态（必须再次检查）

- 个人 ClawManager 功能提交 `9326fd9`：包含本轮批量生命周期、Runtime 兼容和实例列表诊断改动（50 文件）。此前合并提交 `94487ab5867b6023ddcbf6c690a608e67a0d6ae5`，父提交为个人 `a0702b3`、upstream `fc34d46`。本文件随后以独立文档提交保存，实际 HEAD 请再读 Git。
- 个人 Runtime HEAD `7e49bcbcd3cf30be80af2bbd64b50ccf9d7aff48`，合并父提交：个人 `1f76acd`、upstream `8bdc192`。
- 2026-09-14：个人 Runtime 工作区干净；ClawManager 之前未提交的功能改动已纳入 `9326fd9`。后端全量测试、前端生产构建及差异格式检查通过；此前镜像标签中的 `94487ab` 指构建时的基准提交，其内容还包含当时工作区改动，不等于裸 `94487ab`。
- 不要 checkout/reset/clean/stash 覆盖现有改动，不要自动合并团队分支。其他对话可能同时工作，开始先输出两个个人仓库分支和 status。
- 本轮按用户要求只做本地 commit，尚未 push origin。后续提交仍需核查其他对话新增的改动，不能遗漏未跟踪实现和迁移。

## 3. 功能边界与已存在工作

### 北向与生命周期
- 已有北向 Lite/Pro、删除接口和可选 alias；alias 不传必须向后兼容，门户有别名优先显示，重置保留别名。
- 个人北向独立实例流程，不要扩展为 Team 流程。
- 重置保持“完全初始化并删除旧数据”的语义：先创建干净替代实例，准备好后再切换并清理旧实例；新建失败保留原实例和数据。历史 fallback/cleanup 逻辑不要无意改动。
- 多选仍只针对 Lite。批量重启/重置后台持久化执行，当前并发设计全局 5、重置最多 2、同 Runtime Pod 最多 1，首个试运行、失败暂停及页面恢复逻辑已在工作区。
- migration `060_add_instance_lifecycle_batches.sql` 属于此前批量功能；已在 32443 应用。最新列表功能没有新增迁移。
- 本地 500 条测试是隔离数据库的模拟任务，不是创建 500 个真实实例。用户反复强调不要创建大量实例，最新功能验收不涉及真实模型对话。

### OpenClaw/Hermes
- 个人 OpenClaw 保持上游稳定版 `2026.7.1-2`，不要引入 8.1 配置迁移或升级实验室。
- Runtime 滚动更新：实际 K8s 资源筛选、排除无效/实验池、逐池等待健康、任务进度恢复等修改已纳入 `9326fd9`。
- Hermes 上游新增 Web 模式要求不可变 `CLAWMANAGER_RUNTIME_IMAGE_REF`，这是 Runtime upstream `c41da68` 引入；个人合并前没有该检查。不是合并冲突改坏。
- ClawManager upstream 原滚动更新已同步 image 和该 env，但原样使用输入，不自动将 tag 转 digest。个人已补 `hermes_rollout_image.go`，在请求提交任务前固定 digest；digest 直接校验使用。解析失败不创建任务。没有新增表或改 Runtime 校验。
- 当前 resolver 支持显式 registry/repository:tag 或 @sha256；私有 IP 带端口仓库允许 HTTP，其他默认 HTTPS；限制重定向、超时、manifest 大小并核对摘要。暂未实现私有仓库凭据/Bearer challenge 流程；这类仓库可输入已核实的 digest。不要声称所有仓库认证场景都验收过。
- 新 Hermes 候选 `desktop_web_accepted=false`：没有上游签名验收私钥，不得绕过校验或宣称 Desktop Web 入口已经全功能验收。Pod Ready 与入口可用是两回事。

## 4. 最新实例列表需求及实现

用户已批准并实施的布局：`选择 | INSTANCE | TYPE | INFORMATION | AVAILABILITY | WORKSPACE | ACTIONS`。

- INFORMATION 占原 TEAM 列；团队链接简略移到 INSTANCE 创建时间下面，无团队不显示。
- 信息列显示实例 ID、最后在线；error 追加简短原因，悬停/聚焦显示完整脱敏错误。
- 最后在线复用 Lite binding `last_health_at`、Pro agent `last_heartbeat_at`，按当前页批量读取，未新增表。不是 `updated_at`、不是 Runtime Pod 心跳。记录被清理或缺失显示“暂无记录”；不是完整永久在线历史。
- 后端数字搜索同时匹配精确 ID 和现有文本；`#ID` 精确匹配。保留 owner/user 过滤，跨分页查询。
- URL 保存 q/type/mode/availability/page；详情通过路由 state 带回经过路径校验的列表地址。返回和刷新恢复；不恢复危险的批量勾选。
- 关键文件：`frontend/src/pages/instances/{InstanceListPage,InstanceDetailPage}.tsx`、`frontend/src/types/instance.ts`、`backend/internal/models/{instance,instance_information}.go`、`backend/internal/repository/instance_repository.go`。
- 通过：后端 `go test ./...`；前端构建；镜像实际启动；本地真实 API 的 ID/时间/脱敏；Headless Chrome 模拟数据的布局、hover、浏览器后退、刷新恢复 page=2 和组合筛选。
- 浏览器脚本 `.tmp/browser/information-test.cjs`，截图 `.tmp/information-list.png`，均为本地忽略文件。响应式布局有隐藏副本，测试应定位 visible 元素。
- 验收边界：真实环境最新页面验收尚未完成；不是所有异常消息脱敏、浏览器导航边缘情况和 SQL 性能都有完整测试。不要把已有检查扩大表述为全部生产验收通过。

## 5. 镜像与环境状态（不是新的操作授权）

唯一测试目标：`10.130.14.23`，namespace `clawmanager-hxc-system`，门户 `https://10.130.14.23:32443`；北向同租户端口 32555。不得触碰其他租户。正式 `10.130.15.40` 不得写入，需用户另行授权。

### 当前最后核实的 App / Gateway 运行镜像
`10.130.14.23:5000/clawmanager-hxc-app:runtime-compat-batch-20260911-r5-94487ab`

digest `sha256:cdc393034e1e229f0515870888a7e7f9e577f20a663db37a276dbb432ab81621`

### 最新列表候选（已构建、已 push，**尚未上线**）
`10.130.14.23:5000/clawmanager-hxc-app:instance-information-20260913-94487ab`

digest `sha256:01d49fe3fe1768960179f33bab723bf451942f1b49e1bc67f15f05f0489dcc37`

不要把“已推送”说成“已更新”；后续发布需重新预检。本交接不纳入节点问题及其排查任务。

### Hermes 个人 upstream 候选
`10.130.14.23:5000/agentsruntime/hermes-lite:personal-upstream-20260911-7e49bcb`

digest `sha256:2ac400ebb02a4ce69f325fe11b437c2b037f401ab3c8a21da456213fc1026013`

使用个人 Runtime `hermes/Dockerfile.lite` 构建，源码锁为 Hermes v2026.8.31 / 0.21.0。真实入口和协议 smoke 通过，签名接受仍 false。最近核实测试 Hermes Deployment 已采用该 digest；不要套回旧默认镜像。

## 6. 发布与安全约束

先完整阅读个人 ClawManager 根目录 `AGENTS.md`。遵守：先复现、查根因、补测试、最小修改、回归；不重构无关功能，不碰用户数据；遇到异常停下汇报，不能擅自清理或修复共享基础设施。

用户常用发布命令（仅明确授权更新时执行）：
```bash
cd /home/hxc/north
APP_IMAGE='<本次已验证镜像>' \
TENANT_SUFFIX=-hxc \
NODE_PORT=32443 \
bash ./clawmanager-apply.sh
```

该脚本不只是 set image：会 apply 租户清单、等待 Runtime、处理北向数据库账号并更新 Gateway。每次必须先检查当前脚本与清单，记录旧镜像/配置/迁移差异/PVC，再决定安全执行方式。不要回写旧 Runtime 或覆盖管理员配置。

2026-09-13 清单已保留四个基础 Runtime 的当时 live spec（固定当前镜像和 env），不是所有 Runtime 镜像还由脚本默认变量驱动。下次发布需再次核对，不照搬旧假设。部署留档目录 `/home/hxc/north/release-instance-information-20260913`。不需要为本次无迁移的列表功能复制全量用户数据。

测试 SSH 可使用本机已忽略文件 `D:/test/ClawManager-2/team-optimization-docs/serverPassCode.md` 中对应 14.23 的连接信息；只在任务需要时读取，绝不打印或写入交接。PuTTY 路径 `C:/Program Files (x86)/PuTTY/`，14.23 已核实指纹 `7e:f6:55:9c:bc:f3:6c:27:49:08:84:3b:20:80:bf:4a`。文件在团队目录仅是连接材料位置，不意味着允许修改团队代码。

本地构建 Docker Desktop amd64；本地 Node 22.11 有 Vite 版本警告，镜像 Node 24 构建通过。Python 可用个人 ClawManager `venv/Scripts/python.exe`，网络测试使用 `pip._vendor.requests`，关闭代理只限具体测试 Session。

## 7. 新对话开始时

1. 阅读本文件和 AGENTS.md，输出两个个人项目分支/HEAD/status。
2. 不切换团队仓库分支，不覆盖任何未提交修改。
3. 以用户新任务为准；没有授权不要自动部署、commit/push、创建实例或继续历史运维。
4. 若继续列表功能，先检查现有改动和测试证据，再补必要验收；最新镜像仍是候选，不是线上版本。
