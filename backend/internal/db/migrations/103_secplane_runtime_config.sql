-- secplane_instance_runtime_config — 每个 openclaw 实例每个 skill 最近一次
-- 成功下发的 user_config 快照。dispatch 路径（DispatchAegis /
-- DispatchAegisApply / DispatchSecureClaw）在 target 成功分支 upsert 本表；
-- GetLiveAegisConfig 优先读本表，避免依赖 agent 上报的 skill_blob（plugin
-- auto-discover 安装路径下 agent 不上报 blob，老 live-config 会 404）。
--
-- PK (instance_id, skill_name) = 一个实例一个 skill 一行，新写入覆盖旧的。
-- user_config 以 JSON 字符串形式存储，与 instance_commands.payload_json 同模式。
CREATE TABLE IF NOT EXISTS secplane_instance_runtime_config (
  instance_id    INT          NOT NULL,
  skill_name     VARCHAR(64)  NOT NULL,
  revision       VARCHAR(64)  NOT NULL,
  sha256         VARCHAR(64)  NOT NULL,
  config_sha256  VARCHAR(64)  NOT NULL,
  user_config    MEDIUMTEXT   NOT NULL,
  source         VARCHAR(32)  NOT NULL,
  command_id     INT          NULL,
  status         VARCHAR(20)  NOT NULL DEFAULT 'succeeded',
  dispatched_at  DATETIME     NOT NULL,
  created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (instance_id, skill_name),
  INDEX idx_secplane_rc_dispatched (skill_name, dispatched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
