# 批量生命周期功能：实现及验收记录（2026-09-11）

## 范围

- 个人 ClawManager：`codex/northbound-all-pro-runtime`，基线 `94487ab`。
- 不改变现有 Lite 多选范围、分页选择方式和批量创建/删除语义。
- 北向门户允许 `error` 状态重启；运行中生命周期操作仍互斥，进入实例仍需满足条件。
- 工作台新增持久化批量重启/重置；上限为所有批任务合计 5 个，其中重置最多 2 个。同 Runtime Pod 互斥；重置对同类型 Runtime 进一步串行保护，避免替代实例调度至不同 Pod 后冲突。
- 重置仍为破坏性初始化：先创建新实例、确认就绪，再切换身份、清理旧实例。不迁移旧工作区。创建失败保留旧实例；旧清理失败保留新实例并暂停剩余任务。
- 普通工作台实例没有北向 Owner 时也支持切换；拒绝将已交付的新实例当临时实例删除。
- 批任务支持刷新/切页后查询、逐项结果、暂停派发、继续剩余任务、取消未开始项。失败项不自动重试。
- 新增迁移 `060_add_instance_lifecycle_batches.sql`，仅 App/Core 使用新表，不需要增加 Gateway 权限。
- 普通单实例变更与批任务使用数据库互斥。直接同步变更若进程崩溃，保留 manual guard 供管理员核查，不在状态不明时自动重复操作。

## 验证结果

- `backend: go test ./...` 通过。
- `frontend: npm run build` 通过；本地 Node 版本提示低于 Vite 推荐版本，正式镜像构建使用 Dockerfile 固定的 Node 24，构建通过。
- 独立本地 MySQL 中模拟 500 项、8 个并发调度入口，完成全部任务并验证全局上限、重置上限、Pod 互斥、重复提交、暂停/继续、失败暂停、取消待执行项、权限隔离及直接变更互斥。
- 在实际测试环境发现旧 `northbound_operations` 使用 `utf8mb4_unicode_ci`，新表沿用数据库默认 `utf8mb4_0900_ai_ci`，关联查询失败。已回退 App，修复查询的显式排序规则兼容性，没有修改业务表排序规则。
- 增加混合排序规则故障复现：修复前测试失败并重现 MySQL 1267；修复后 500 项集成测试通过（141.733 秒）。
- r3 镜像验证：linux/amd64；入口 `["dumb-init","--"]`、命令 `["/app/start.sh"]`；实际启动应用和独立数据库，`/healthz` 与后端 `/api/v1/version` 均通过。

## 镜像

修正版候选镜像（尚未完成完整业务验收，不应发布正式环境）：

`10.130.14.23:5000/clawmanager-hxc-app:batch-lifecycle-20260911-r3-94487ab`

Registry digest：`sha256:c760f123cc4b8db6aa3c96f8eb598712a724cfb6c1cc59b6cb076251fbb69684`。

原稳定镜像：

`10.130.14.23:5000/clawmanager-hxc-app:northbound-delete-alias-20260910-d05aa05`

## 32443 环境实际检查

- 仅操作 `10.130.14.23` 的 `clawmanager-hxc-system` 及该租户资源；未操作正式环境。
- 按用户给定 `/home/hxc/north/clawmanager-apply.sh`、`TENANT_SUFFIX=-hxc`、`NODE_PORT=32443` 更新并检查了 App、Gateway 和 Runtime 的 rollout。
- 更新前后原有 27 个实例状态一致；其中原有 3 个 error 实例保持原状态，没有操作其数据。
- 备份与部署快照：服务器 `/home/hxc/north/release-batch-lifecycle-20260911-r2/`。
- 测试库备份约 198 MiB，gzip 校验通过，SHA-256：`46b57922becddee25d790dddc0c6d38a3cdde3aec1bd56a3c4791eb85d451917`。
- 新建了 4 个本次专用 Lite 实例，全部达到 running，并成功上传 `batch-persistence.txt`：

| 实例 | 类型 | 文件 SHA-256 |
|---|---|---|
| 230 | OpenClaw | `2980c4b20c9ad0f357eaf6cde8c8bf8f36f6a62901301d0729e1802f9bfe61ca` |
| 231 | Hermes | `571d278cde04ebade9f60b66ea51e1f73f92b4a843e6cf7e0ad82baa6a3ff384` |
| 232 | OpenCode | `b905e2b58edf20554dc517aab511b5d48e98c21eaa15ae5b0e70d80daffc5beb` |
| 233 | DeepSeek Harness | `231e35ef86328be7adb34caa37c6f33ea798937232ca1170a0d8623b1f382009` |

## 尚未完成的验收与阻碍

**没有完成真实对话、批量重启/重置/删除验收，不能宣称验收完成。** 发现入口问题后停止了这些操作，4 个测试实例和文件保留。

1. 此前合并的上游 Hermes Desktop 代码主动禁止 Hermes Lite 的旧 raw proxy 路径。测试环境新 Desktop 的 bootstrap 返回 `available=false, reason=feature_disabled`；通用 `/access` 返回 503。属于本次基线中的上游入口兼容问题，不是批调度 SQL 问题。不能为通过测试而直接绕开上游安全限制。
2. OpenClaw 测试实例 230 被调度至已有 `openclaw-runtime-u48` 升级池，其页面返回 `proxy_attribution_required`（要求可信代理和正确的 forwarded client headers）；旧镜像回退期间同样复现，需单独确认该环境已有升级池的协议兼容性。
3. 节点启动日志有 Nginx `io_setup() failed (11: Resource temporarily unavailable)` 告警，健康接口和登录正常；未修改节点 sysctl。

为保护现有使用，已将 App 与 Gateway 恢复原稳定镜像，两者均验证 1/1 Ready，32443 的 `/healthz` 返回正常。下一步需要用户确认是否将上述上游 Runtime/入口兼容性纳入范围，再继续最终业务验收。新增任务表保留，不做破坏性数据库回滚；没有向生产发布。

回退后再次下载了 4 个测试文件，SHA-256 均与上表一致。测试实例 231/232/233 为 running；230 后续变为 error，Runtime 报 `gateway start failed: exit status 78`（generation 2）。未对其做重启、重置或删除，保留现场。独立本地验收容器已停止，没有删除测试数据库容器。
