-- secplane outbound trusted endpoints — 应用层域名/证书 fingerprint 白名单
-- ClawAegis before_tool_call 钩子读取该列表，URL host 不在表里 → block。
-- fingerprint_sha256 为空 = 仅做域名白名单；填了 = pin (Phase 2 用 pre-flight TLS 探针验证)。
CREATE TABLE IF NOT EXISTS secplane_outbound_trusted (
  id INT AUTO_INCREMENT PRIMARY KEY,
  domain_pattern VARCHAR(255) NOT NULL,
  fingerprint_sha256 VARCHAR(128) NULL,
  label VARCHAR(255) NULL,
  channel VARCHAR(60) NULL,
  scope VARCHAR(100) NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'active',
  expires_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_secplane_outbound_domain (domain_pattern),
  INDEX idx_secplane_outbound_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
