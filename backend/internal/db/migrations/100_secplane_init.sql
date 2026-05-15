-- secplane: independent schema for the security protection platform.
-- All tables prefixed with secplane_ and have no FK to ClawManager core tables
-- so the module stays loosely coupled and can later be split out.

CREATE TABLE IF NOT EXISTS secplane_policy_rule (
  id INT AUTO_INCREMENT PRIMARY KEY,
  rule_id VARCHAR(100) NOT NULL,
  kind VARCHAR(40) NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  pattern TEXT NOT NULL,
  target VARCHAR(40) NOT NULL DEFAULT 'user_input',
  severity VARCHAR(20) NOT NULL DEFAULT 'medium',
  action VARCHAR(40) NOT NULL DEFAULT 'observe',
  mode VARCHAR(20) NOT NULL DEFAULT 'enforce',
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order INT NOT NULL DEFAULT 0,
  tags VARCHAR(500) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_secplane_policy_rule_rule_id (rule_id),
  INDEX idx_secplane_policy_rule_kind (kind, is_enabled),
  INDEX idx_secplane_policy_rule_target (target),
  INDEX idx_secplane_policy_rule_sort (sort_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS secplane_alert (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  trace_id VARCHAR(64) NULL,
  source VARCHAR(40) NOT NULL,
  rule_id VARCHAR(100) NULL,
  rule_name VARCHAR(255) NULL,
  severity VARCHAR(20) NOT NULL DEFAULT 'low',
  action VARCHAR(40) NOT NULL DEFAULT 'observed',
  agent_id VARCHAR(64) NULL,
  subject VARCHAR(255) NULL,
  evidence TEXT NULL,
  raw_payload MEDIUMTEXT NULL,
  ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_secplane_alert_ts (ts),
  INDEX idx_secplane_alert_severity (severity),
  INDEX idx_secplane_alert_source (source),
  INDEX idx_secplane_alert_rule (rule_id),
  INDEX idx_secplane_alert_trace (trace_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
