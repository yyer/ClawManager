// Wire types for /api/host/* — must mirror ksec-bridge/src/types.ts exactly.
// See specs/001-clawmanager-hardening/prototypes (scenario-l-host) for UX context.

export interface BaitDir {
  dir: string;
}

export interface WhitelistEntry {
  path: string;
}

/**
 * Ransom protection policy. Field names use the on-disk KSec YAML schema
 * (kebab-case + nested objects) — keep aligned with ksec-bridge.
 */
export interface RansomPolicy {
  name: string;
  module: string;
  'switch-on': boolean;
  'kill-process': boolean;
  decoyFileDir?: BaitDir[];
  whiteList?: WhitelistEntry[];
}

export const DEFAULT_RANSOM_POLICY: RansomPolicy = {
  name: 'ransomware-protect-policy',
  module: 'ransomware',
  'switch-on': false,
  'kill-process': false,
  decoyFileDir: [],
  whiteList: [],
};

export interface LogEntry {
  // KSec SecLog passthrough (see KSecMain/types/types.go:215)
  time?: string;
  logType?: string;
  action?: string;
  hostName?: string;
  source?: string;
  path?: string;
  operation?: string;
  user?: string;
  pid?: number;
  ppid?: number;
  uid?: number;
  severity?: string;
  tags?: string[];
  message?: string;

  // bridge-derived display field "<source-or-path> (pid <n>)"
  process?: string;

  // raw line, always populated
  raw: string;
}

export interface AgentStatus {
  ready: boolean;
  ksecDaemonRunning: boolean;
  policyDirOK: boolean;
  logDirOK: boolean;
  ksecBinOK: boolean;
}
