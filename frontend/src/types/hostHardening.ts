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

/** Process protect or blacklist entry — ac.yaml processProtectList / processBlackList. */
export interface ProcRule {
  path: string;
  desc?: string;
}

/** File-protection custom rule — ac.yaml fileProtectList. */
export interface FileRule {
  objPath: string;
  mode?: string;
  fromSource?: Array<{ subPath: string }>;
}

/** Built-in pre-file rule — ac.yaml preFileList.rules. `mode` optional (e.g. /proc/kallsyms has none). */
export interface PreFileRule {
  path: string;
  mode?: string;
  desc?: string;
}

/**
 * Host file/process protection policy — mirrors bridge `FilePolicy`.
 * `switch-on` is the effective bridge-side master (AND of ac.yaml + KSec.yaml.access_control).
 */
export interface FilePolicy {
  name: string;
  module: string;
  'switch-on': boolean;
  action: 'Monitor' | 'Block';
  processBlackList?: ProcRule[];
  processProtectList?: ProcRule[];
  fileProtectList?: FileRule[];
  preFileList: {
    'switch-on': boolean;
    rules: PreFileRule[];
  };
}

export const DEFAULT_FILE_POLICY: FilePolicy = {
  name: 'access-control-policy',
  module: 'access_control',
  'switch-on': false,
  action: 'Monitor',
  processBlackList: [],
  processProtectList: [],
  fileProtectList: [],
  preFileList: { 'switch-on': false, rules: [] },
};

/**
 * Intrusion-detection policy — mirrors bridge `InvasionPolicy`.
 * 与 KSecGUI/components/Invasion.vue 对齐：
 *   - 'switch-on'            → KSec.yaml.intrusion_detection 主开关
 *   - whitelistProgram/File/IP → ids.yaml 中 3 个 list 块（whitelist_program_path 等）
 *   - enabledRuleNames        → ids.yaml 中存在的 `- rule: <name>` 名称集合
 *                              （前端 INVASION_RULES_TEMPLATE 据此勾选每条 Toggle）
 */
export interface InvasionPolicy {
  'switch-on': boolean;
  whitelistProgram: string[];
  whitelistFile: string[];
  whitelistIP: string[];
  enabledRuleNames: string[];
}

export const DEFAULT_INVASION_POLICY: InvasionPolicy = {
  'switch-on': false,
  whitelistProgram: [],
  whitelistFile: [],
  whitelistIP: [],
  enabledRuleNames: [],
};

export interface LogEntry {
  // KSec SecLog passthrough (ransom + access_control, see KSecMain/types/types.go:215)
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

  // Falco IdsLogEntry passthrough (invasion module, see KSecMain/types/types.go:766)
  rule?: string;
  output_fields?: Record<string, unknown>;

  // bridge-derived display field "<source-or-path-or-proc.name> (pid <n>)"
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
