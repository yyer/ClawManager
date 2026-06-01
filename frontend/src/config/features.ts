// Frontend feature flags — flip to true when the backend / UX is real.
// Each flag should carry a one-line comment about what gets shown.
//
// Convention: types are widened to `boolean` (via the FeatureFlags shape) so
// flipping a flag never trips TS's "always-false condition" narrowing.

export interface FeatureFlags {
  // Output Surface scenario — "存量凭据巡检 / 本地存储明文凭据告警" panel.
  // Currently mock UI (CRED_ALERTS + 立即扫描 + 标记为已处理); no backend.
  credentialInventory: boolean;
}

export const FEATURES: FeatureFlags = {
  credentialInventory: false,
};
