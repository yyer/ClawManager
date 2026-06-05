-- 应急熔断（kill switch）单行状态。
-- 启用后，dispatch 会把 killSwitchEnabled=true 注入到所有实例的 user_config，
-- ClawAegis 在 before_tool_call 中无条件 block 所有工具调用直到关闭。
CREATE TABLE IF NOT EXISTS secplane_kill_switch (
  id          INT          NOT NULL PRIMARY KEY,
  enabled     TINYINT(1)   NOT NULL DEFAULT 0,
  reason      VARCHAR(255) DEFAULT NULL,
  set_by      VARCHAR(64)  DEFAULT NULL,
  set_at      DATETIME     DEFAULT NULL,
  created_at  DATETIME     NOT NULL,
  updated_at  DATETIME     NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO secplane_kill_switch (id, enabled, created_at, updated_at)
VALUES (1, 0, NOW(), NOW())
ON DUPLICATE KEY UPDATE id=id;
