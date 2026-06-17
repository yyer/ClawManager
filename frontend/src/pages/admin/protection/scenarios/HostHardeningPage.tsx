import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';
import { useI18n } from '../../../../contexts/I18nContext';
import {
  getBaselinePolicy,
  getBaselineStatus,
  getFilePolicy,
  getInvasionPolicy,
  getLogs,
  getRansomPolicy,
  getStatus,
  openLogStream,
  putFilePolicy,
  putInvasionPolicy,
  putRansomPolicy,
  repairBaseline,
  resetBaseline,
  rollbackBaseline,
  scanBaseline,
} from '../../../../services/hostHardening';
import {
  DEFAULT_FILE_POLICY,
  DEFAULT_INVASION_POLICY,
  DEFAULT_RANSOM_POLICY,
  type AgentStatus,
  type BaselineCategory,
  type BaselineReport,
  type FilePolicy,
  type FileRule as ServerFileRule,
  type InvasionPolicy,
  type LogEntry,
  type RansomPolicy,
} from '../../../../types/hostHardening';
import { BUILTIN_PREFILE_TEMPLATE } from '../../../../data/builtinPreFileRules';
import { INVASION_RULES_META, INVASION_PRISTINE_BODY } from '../../../../data/invasionPolicy';
import { enrichInvasionLog, type InvasionLogRow } from '../../../../data/invasionLogMap';

// 宿主加固 (scenario L) — 对齐 specs/001-clawmanager-hardening/prototypes/scenario-l-host.html
// 3 个 tab：主机防护 / 勒索防护 / 入侵检测
// 当前为原型态：本地 state 模拟交互，未接 host-side bridge

// ===========================
// 辅助：Toast / Modal 占位
// ===========================

type ToastKind = 'info' | 'success' | 'warning';
type ToastState = { message: string; kind: ToastKind } | null;

const Toast: React.FC<{ toast: ToastState; onClose: () => void }> = ({ toast, onClose }) => {
  React.useEffect(() => {
    if (!toast) return;
    const t = setTimeout(onClose, 2000);
    return () => clearTimeout(t);
  }, [toast, onClose]);
  if (!toast) return null;
  const bg =
    toast.kind === 'success' ? '#dcfce7' : toast.kind === 'warning' ? '#fef3c7' : '#dbeafe';
  const fg =
    toast.kind === 'success' ? '#166534' : toast.kind === 'warning' ? '#92400e' : '#1e40af';
  return (
    <div
      style={{
        position: 'fixed',
        bottom: 24,
        right: 24,
        zIndex: 100,
        padding: '10px 16px',
        background: bg,
        color: fg,
        borderRadius: 10,
        fontSize: 13,
        boxShadow: '0 8px 24px rgba(0,0,0,0.12)',
      }}
    >
      {toast.message}
    </div>
  );
};

const Modal: React.FC<{
  open: boolean;
  title: string;
  eyebrow?: string;
  onClose: () => void;
  children: React.ReactNode;
  footer: React.ReactNode;
}> = ({ open, title, eyebrow, onClose, children, footer }) => {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[rgba(44,30,22,0.48)] px-4"
      onClick={onClose}
    >
      <div
        className="panel"
        style={{ maxWidth: 560, width: '100%', maxHeight: '90vh', overflow: 'auto' }}
        onClick={(e) => e.stopPropagation()}
      >
        {eyebrow && <div className="eyebrow text-[10px] mb-1">{eyebrow}</div>}
        <h3 className="section-title-lg mb-4">{title}</h3>
        <div className="mb-5">{children}</div>
        <div className="flex justify-end gap-2">{footer}</div>
      </div>
    </div>
  );
};

const Toggle: React.FC<{ on: boolean; onChange: (v: boolean) => void }> = ({ on, onChange }) => (
  <div className={`toggle${on ? ' toggle-on' : ''}`} onClick={() => onChange(!on)}>
    <div className="toggle-thumb" />
  </div>
);

// Button-based radio. Avoids browser-native radio group sync issues with
// React-controlled `checked` (was causing both options to render unselected
// after click in some cases). Pure React state, no <input type="radio">.
const RadioBtn: React.FC<{ selected: boolean; onClick: () => void; label: string }> = ({
  selected,
  onClick,
  label,
}) => (
  <button
    type="button"
    onClick={onClick}
    className="flex items-center gap-1.5 cursor-pointer"
    style={{ background: 'transparent', border: 'none', padding: 0 }}
  >
    <span
      aria-hidden
      style={{
        display: 'inline-block',
        width: 14,
        height: 14,
        borderRadius: '50%',
        border: '2px solid #dc2626',
        background: selected ? '#dc2626' : 'transparent',
        boxShadow: selected ? 'inset 0 0 0 2px #fff' : 'none',
      }}
    />
    <span className="text-xs">{label}</span>
  </button>
);

// Inline CSS spinner — no extra dep. SVG inside an animate-spin wrapper.
// Color follows `currentColor` so it inherits the button's text color.
const Spinner: React.FC<{ size?: number }> = ({ size = 12 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    style={{ animation: 'ksecbridge-spin 0.8s linear infinite' }}
    aria-hidden="true"
  >
    <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.25" />
    <path
      d="M4 12a8 8 0 018-8"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      fill="none"
    />
  </svg>
);

// Inject keyframes once (vite's <style> de-dup is reliable across HMR).
const SpinnerStyle: React.FC = () => (
  <style>{`@keyframes ksecbridge-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
);

// ===========================
// 主机防护 — UI ↔ server FilePolicy 类型转换
// ===========================

// (mock 内置规则数据已删除，改为从 ksec-bridge 加载)

/** UI shape for file-protection custom rule. Converted to/from server's
 * FileRule on load/save (mode "rwxd" ↔ r/w/x/d flags; fromSource[] ↔ comma trust). */
type CustomFileRule = {
  path: string;
  trust: string;
  r: boolean;
  w: boolean;
  x: boolean;
  d: boolean;
};

// KSec mode tokens (与 KSecGUI/components/FileProtect.vue strModeToArr 保持一致)：
//   r   → 读
//   wcm → 写（KSec 把"写"扩展为 w+c+m：写/创建/移动或重命名 三种系统调用，作为一个整体 token）
//   x   → 执行
//   d   → 删除
//   all → 四种全部
function fileRuleFromServer(s: ServerFileRule): CustomFileRule {
  const m = s.mode ?? '';
  return {
    path: s.objPath,
    trust: (s.fromSource ?? []).map((f) => f.subPath).join(', ') || '-',
    r: m === 'all' || m.includes('r'),
    w: m === 'all' || m.includes('wcm'),
    x: m === 'all' || m.includes('x'),
    d: m === 'all' || m.includes('d'),
  };
}
/**
 * KSec SecLog.Operation i18n.
 */
function operationI18n(op: string | undefined, t: (key: string) => string): string {
  if (!op) return '-';
  const map: Record<string, string> = {
    chmod: t('secplane.protection.hostHardening.operation.chmod'),
    read: t('secplane.protection.hostHardening.operation.read'),
    write: t('secplane.protection.hostHardening.operation.write'),
    execute: t('secplane.protection.hostHardening.operation.execute'),
    delete: t('secplane.protection.hostHardening.operation.delete'),
    create: t('secplane.protection.hostHardening.operation.create'),
    kill: t('secplane.protection.hostHardening.operation.kill'),
    'move or rename': t('secplane.protection.hostHardening.operation.moveOrRename'),
  };
  return map[op] ?? op;
}

/** KSec SecLog.Action i18n. */
function actionI18n(action: string | undefined, t: (key: string) => string): string {
  if (!action) return '-';
  const key = action.toUpperCase();
  if (key === 'BLOCK') return t('secplane.protection.hostHardening.action.block');
  if (key === 'MONITOR') return t('secplane.protection.hostHardening.action.monitor');
  return action;
}

/**
 * KSec mode string i18n.
 */
function modeI18n(mode: string | undefined, t: (key: string) => string): string {
  if (!mode) return '-';
  if (mode === 'all') return t('secplane.protection.hostHardening.mode.all');
  const parts: string[] = [];
  if (mode.includes('r')) parts.push(t('secplane.protection.hostHardening.mode.read'));
  if (mode.includes('wcm')) parts.push(t('secplane.protection.hostHardening.mode.write'));
  if (mode.includes('x')) parts.push(t('secplane.protection.hostHardening.mode.execute'));
  if (mode.includes('d')) parts.push(t('secplane.protection.hostHardening.mode.delete'));
  return parts.length > 0 ? parts.join(' / ') : mode;
}

function fileRuleToServer(u: CustomFileRule): ServerFileRule {
  // 输出顺序与 KSecGUI 一致：r / wcm / x / d，"写"勾选时拼成 "wcm" 整体 token
  const parts: string[] = [];
  if (u.r) parts.push('r');
  if (u.w) parts.push('wcm');
  if (u.x) parts.push('x');
  if (u.d) parts.push('d');
  const mode = parts.join('');
  // Trust input is a textarea: split on newlines AND commas (CN 逗号 included),
  // emit each path as its own `- subPath: ...` entry to match KSec's
  // MatchSourceType { Path string `json:"subPath"` } schema.
  // Without newline-splitting, multi-line input gets serialized as a YAML
  // block scalar (|-), which KSec rejects with "cannot unmarshal array into string".
  const fromSource = u.trust && u.trust !== '-'
    ? u.trust
        .split(/[\n,，]/)
        .map((s) => s.trim())
        .filter(Boolean)
        .map((subPath) => ({ subPath }))
    : undefined;
  return { objPath: u.path, mode: mode || undefined, fromSource };
}

/** UI process rule: tagged variant of server's processBlackList + processProtectList. */
type ProcRule = { path: string; type: '进程保护' | '进程黑名单' };

/**
 * Falco 兼容的入侵检测白名单字段校验，与 KSecGUI/utils/check.js 对齐：
 *  - 路径（程序 / 文件）：绝对路径，段内只接受 [a-zA-Z0-9._-]
 *  - IP：dotted-quad IPv4 字面量（不接受 CIDR；Falco 的 fd.cip 不识别 /N，
 *        否则 Falco 加载 ids.yaml 时报 "unrecognized IPv4 address"）
 */
const IDS_PATH_RE = /^([/]|([/][a-zA-Z0-9._-]{1,255})+)$/;
const IDS_IPV4_RE = /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/;

function validateInvasionEntries(
  lines: string[],
  kind: 'path' | 'ip',
): { ok: string[]; bad: string[] } {
  const re = kind === 'ip' ? IDS_IPV4_RE : IDS_PATH_RE;
  const ok: string[] = [];
  const bad: string[] = [];
  for (const raw of lines) {
    const s = raw.trim();
    if (!s) continue;
    if (s.length > 255) bad.push(s);
    else if (!re.test(s)) bad.push(s);
    else ok.push(s);
  }
  return { ok, bad };
}

/**
 * 合并新行进白名单（与 KSecGUI Invasion.vue handleConfirm 一致）：
 * - 新行按出现顺序去重
 * - 旧值中已被新行包含的剔除，让新行排在最上面
 * - 超过 max 截断，返回 dropped 数量供 UI 提示
 */
function mergeUnique(prev: string[], lines: string[], max: number): { merged: string[]; dropped: number } {
  const fresh = Array.from(new Set(lines.map((s) => s.trim()).filter(Boolean)));
  const freshSet = new Set(fresh);
  const oldKept = prev.filter((v) => !freshSet.has(v));
  const combined = [...fresh, ...oldKept];
  const dropped = Math.max(0, combined.length - max);
  return { merged: combined.slice(0, max), dropped };
}


// 数据迁移：勒索防护 + 主机防护 + 入侵检测均已接 ksec-bridge
//   /api/host/policy/{ransome,file,invasion} + /api/host/logs/stream?module={ransome,file,invasion}

// ===========================
// 主页
// ===========================

type MainTab = 'file' | 'ransome' | 'invasion' | 'baseline';

// ===== 合规检测 / CIS baseline（与 KSecGUI/components/Compliance.vue 对齐） =====
// 注：KSec 实际扫的 ID 集合由 bridge 读 /opt/KSec/compliance/template/basic 得到，
// 前端不再硬编码白名单。getBaselinePolicy() 返回的就已经是过滤后的 29 条（Ubuntu 适配）。

/** UI 侧状态机；KSecGUI 同名（roolbacking 是上游拼写笔误，沿用以便对照） */
type BaselineUiStatus =
  | 'home'
  | 'scanning'
  | 'scanned'
  | 'repairing'
  | 'repaired'
  | 'roolbacking'
  | 'rollbacked';

/** repair / rollback result label i18n */
function baselineResultLabel(
  result: string,
  phase: 'scanned' | 'repaired' | 'rollbacked',
  t: (key: string) => string,
): { text: string; color: string } {
  const b = 'secplane.protection.hostHardening.baseline.';
  if (result === 'uncheck') {
    if (phase === 'repaired') return { text: t(`${b}safe`), color: '#00c63c' };
    if (phase === 'rollbacked') return { text: '-', color: '#6b7280' };
    return { text: t(`${b}notChecked`), color: '#989cb2' };
  }
  if (phase === 'scanned') {
    if (result === 'success' || result === 'security') return { text: t(`${b}safe`), color: '#00c63c' };
    return { text: t(`${b}atRisk`), color: '#ff830c' };
  }
  if (phase === 'repaired') {
    if (result === 'security') return { text: t(`${b}safe`), color: '#00c63c' };
    if (result === 'success') return { text: t(`${b}repaired`), color: '#0da3df' };
    if (result === 'fail') return { text: t(`${b}repairFailed`), color: '#ff830c' };
    if (result === '不支持') return { text: t(`${b}manualRepair`), color: '#6b7280' };
    return { text: result, color: '#6b7280' };
  }
  // rollbacked
  if (result === 'security') return { text: '-', color: '#6b7280' };
  if (result === 'success') return { text: t(`${b}rolledBack`), color: '#0da3df' };
  if (result === 'fail') return { text: t(`${b}rollbackFailed`), color: '#ff830c' };
  if (result === '不支持') return { text: t(`${b}notSupported`), color: '#6b7280' };
  return { text: result, color: '#6b7280' };
}
type FileSubTab = 'builtin' | 'fileprot' | 'procprot';
type RansomeSubTab = 'decoy' | 'whitelist';
type InvasionSubTab = 'rules' | 'wl-prog' | 'wl-file' | 'wl-ip';

const HostHardeningPage: React.FC = () => {
  const { t } = useI18n();
  // i18n key prefix shorthand
  const h = 'secplane.protection.hostHardening';
  const [mainTab, setMainTab] = useState<MainTab>('file');
  const [toast, setToast] = useState<ToastState>(null);
  const fireToast = (message: string, kind: ToastKind = 'info') => setToast({ message, kind });

  // bridge /agent/v1/status —— 驱动 hero 第 1 张卡（加固代理状态）
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);
  const [agentStatusErr, setAgentStatusErr] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    const fetchStatus = (): void => {
      getStatus()
        .then((s) => {
          if (cancelled) return;
          setAgentStatus(s);
          setAgentStatusErr(null);
        })
        .catch((err: Error) => {
          if (!cancelled) setAgentStatusErr(err.message);
        });
    };
    fetchStatus();
    const id = setInterval(fetchStatus, 15_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  // === 主机防护 state（接 ksec-bridge）===
  const [serverFilePolicy, setServerFilePolicy] = useState<FilePolicy | null>(null);
  const [fileDraft, setFileDraft] = useState<FilePolicy | null>(null);
  const [savingFile, setSavingFile] = useState(false);
  const effectiveFilePolicy: FilePolicy = fileDraft ?? serverFilePolicy ?? DEFAULT_FILE_POLICY;
  // Builtin (preFileList) rules: render the **stable template** (38 rules);
  // each row's Toggle = is this path currently included in
  // effectiveFilePolicy.preFileList.rules?
  // Off → save will drop the row from ac.yaml; On → save adds it back.
  const builtinTemplate = BUILTIN_PREFILE_TEMPLATE;
  const builtinEnabledPaths = new Set(effectiveFilePolicy.preFileList.rules.map((r) => r.path));
  const [fileSub, setFileSub] = useState<FileSubTab>('builtin');
  const [fileLogs, setFileLogs] = useState<LogEntry[]>([]);

  // === 勒索防护 state（已接 ksec-bridge）===
  // serverPolicy: 后端最近一次返回的策略；policyDraft: 用户改动但还没保存
  const [serverPolicy, setServerPolicy] = useState<RansomPolicy | null>(null);
  const [policyDraft, setPolicyDraft] = useState<RansomPolicy | null>(null);
  const [saving, setSaving] = useState(false);
  const effectivePolicy: RansomPolicy = policyDraft ?? serverPolicy ?? DEFAULT_RANSOM_POLICY;
  // SSE-fed log table
  const [liveLogs, setLiveLogs] = useState<LogEntry[]>([]);
  const [ransomSub, setRansomSub] = useState<RansomeSubTab>('decoy');

  // 初次加载策略
  useEffect(() => {
    let cancelled = false;
    getRansomPolicy()
      .then((p) => {
        if (!cancelled) setServerPolicy(p);
      })
      .catch((err: Error) => {
        if (!cancelled) fireToast(t(`${h}.toast.loadPolicyFailed`, { msg: err.message }), 'warning');
      });
    return () => {
      cancelled = true;
    };
    // fireToast 是稳定引用，依赖空数组只跑一次
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 初次拉日志 + 持续 SSE 推流
  useEffect(() => {
    let mounted = true;
    getLogs('ransome', 50)
      .then((rows) => {
        if (mounted) setLiveLogs(rows.reverse()); // 最新在前
      })
      .catch(() => undefined);
    const es = openLogStream('ransome');
    es.onmessage = (e) => {
      try {
        const entry = JSON.parse(e.data) as LogEntry;
        setLiveLogs((prev) => [entry, ...prev].slice(0, 200));
      } catch {
        /* ignore malformed */
      }
    };
    es.onerror = () => {
      // EventSource auto-reconnects; nothing to do
    };
    return () => {
      mounted = false;
      es.close();
    };
  }, []);

  // 派生 4 个 UI 变量
  const ransomMaster = effectivePolicy['switch-on'];
  const killProcess = effectivePolicy['kill-process'];
  const baits = (effectivePolicy.decoyFileDir ?? []).map((b) => b.dir);
  const ransomWhite = (effectivePolicy.whiteList ?? []).map((w) => w.path);

  // 帮 setter：所有改动落到 draft，不直接动 server state
  const patch = (next: Partial<RansomPolicy>): void => {
    setPolicyDraft({ ...effectivePolicy, ...next });
  };
  const setRansomMaster = (v: boolean): void => patch({ 'switch-on': v });
  const setKillProcess = (v: boolean): void => patch({ 'kill-process': v });
  const setBaits = (next: string[] | ((prev: string[]) => string[])): void => {
    const arr = typeof next === 'function' ? next(baits) : next;
    patch({ decoyFileDir: arr.map((dir) => ({ dir })) });
  };
  const setRansomWhite = (next: string[] | ((prev: string[]) => string[])): void => {
    const arr = typeof next === 'function' ? next(ransomWhite) : next;
    patch({ whiteList: arr.map((path) => ({ path })) });
  };

  // 保存 — 走 PUT /api/host/policy/ransome
  // 注意：当总开关 (switch-on) 翻转时 bridge 要走 daemon stop→改 KSec.yaml→start，
  // 整个 PUT 可能 3-5 秒；其余只改诱饵/白名单的情况通常 <500ms。
  const saveRansomPolicy = async (): Promise<void> => {
    if (!policyDraft) return;
    setSaving(true);
    // 立即弹一条 info，让用户知道点击已收到——尤其首次 master switch 翻转
    // 时 daemon 重启会让 PUT 拖到 3+ 秒。
    const isMasterFlip = policyDraft['switch-on'] !== serverPolicy?.['switch-on'];
    fireToast(isMasterFlip ? t(`${h}.toast.applying`) : t(`${h}.common.saving`), 'info');
    try {
      const res = await putRansomPolicy(policyDraft);
      setServerPolicy(policyDraft);
      setPolicyDraft(null);
      if (res.warning) fireToast(res.warning, 'warning');
      else fireToast(t(`${h}.toast.saved`), 'success');
    } catch (err) {
      fireToast(t(`${h}.toast.saveFailed`, { msg: (err as Error).message }), 'warning');
    } finally {
      setSaving(false);
    }
  };

  // === 主机防护：load + SSE + setters + save ===
  useEffect(() => {
    let cancelled = false;
    getFilePolicy()
      .then((p) => {
        if (cancelled) return;
        setServerFilePolicy(p);
      })
      .catch((err: Error) => {
        if (!cancelled) fireToast(t(`${h}.toast.loadFilePolicyFailed`, { msg: err.message }), 'warning');
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let mounted = true;
    getLogs('file', 50)
      .then((rows) => {
        if (mounted) setFileLogs(rows.reverse());
      })
      .catch(() => undefined);
    const es = openLogStream('file');
    es.onmessage = (e) => {
      try {
        const entry = JSON.parse(e.data) as LogEntry;
        setFileLogs((prev) => [entry, ...prev].slice(0, 200));
      } catch {
        /* malformed */
      }
    };
    return () => {
      mounted = false;
      es.close();
    };
  }, []);

  const filePatch = (next: Partial<FilePolicy>): void => {
    setFileDraft({ ...effectiveFilePolicy, ...next });
  };
  const fileMaster = effectiveFilePolicy['switch-on'];
  const defenseMode: 'block' | 'monitor' = effectiveFilePolicy.action === 'Block' ? 'block' : 'monitor';
  // Builtin (preFileList) rules are READ-ONLY: KSec has no per-rule switch, only
  // the single preFileList.switch-on master. We never mutate the rules array, so
  // saving never drops rules from ac.yaml.
  const customFileRules: CustomFileRule[] = (effectiveFilePolicy.fileProtectList ?? []).map(fileRuleFromServer);
  const procRules: ProcRule[] = [
    ...(effectiveFilePolicy.processProtectList ?? []).map((p) => ({ path: p.path, type: '进程保护' as const })),
    ...(effectiveFilePolicy.processBlackList ?? []).map((p) => ({ path: p.path, type: '进程黑名单' as const })),
  ];

  const setFileMaster = (v: boolean): void => filePatch({ 'switch-on': v });
  const setDefenseMode = (v: 'block' | 'monitor'): void =>
    filePatch({ action: v === 'block' ? 'Block' : 'Monitor' });
  const togglePreFileMaster = (v: boolean): void => {
    filePatch({
      preFileList: { ...effectiveFilePolicy.preFileList, 'switch-on': v },
    });
  };
  /** Per-rule include/exclude. Looks up rule definition from the stable template,
   * so disabled-then-re-enabled rules come back with original mode+desc. */
  const toggleBuiltinRule = (path: string, on: boolean): void => {
    const current = effectiveFilePolicy.preFileList.rules;
    if (on) {
      if (current.some((r) => r.path === path)) return; // already enabled
      const def = builtinTemplate.find((r) => r.path === path);
      if (!def) return; // not in template — shouldn't happen
      filePatch({
        preFileList: { ...effectiveFilePolicy.preFileList, rules: [...current, def] },
      });
    } else {
      filePatch({
        preFileList: {
          ...effectiveFilePolicy.preFileList,
          rules: current.filter((r) => r.path !== path),
        },
      });
    }
  };
  const addCustomFileRule = (rule: CustomFileRule): void => {
    const next = [...customFileRules, rule];
    filePatch({ fileProtectList: next.map(fileRuleToServer) });
  };
  const removeCustomFileRule = (i: number): void => {
    const next = customFileRules.filter((_, idx) => idx !== i);
    filePatch({ fileProtectList: next.map(fileRuleToServer) });
  };
  const addProcRule = (rule: ProcRule): void => {
    if (rule.type === '进程保护') {
      filePatch({
        processProtectList: [...(effectiveFilePolicy.processProtectList ?? []), { path: rule.path }],
      });
    } else {
      filePatch({
        processBlackList: [...(effectiveFilePolicy.processBlackList ?? []), { path: rule.path }],
      });
    }
  };
  const removeProcRule = (i: number): void => {
    const protectLen = (effectiveFilePolicy.processProtectList ?? []).length;
    if (i < protectLen) {
      filePatch({
        processProtectList: (effectiveFilePolicy.processProtectList ?? []).filter((_, idx) => idx !== i),
      });
    } else {
      filePatch({
        processBlackList: (effectiveFilePolicy.processBlackList ?? []).filter((_, idx) => idx !== i - protectLen),
      });
    }
  };

  const saveFilePolicy = async (): Promise<void> => {
    if (!fileDraft) return;
    setSavingFile(true);
    const isMasterFlip = fileDraft['switch-on'] !== serverFilePolicy?.['switch-on'];
    fireToast(isMasterFlip ? t(`${h}.toast.applying`) : t(`${h}.common.saving`), 'info');
    try {
      const res = await putFilePolicy(fileDraft);
      setServerFilePolicy(fileDraft);
      setFileDraft(null);
      if (res.warning) fireToast(res.warning, 'warning');
      else fireToast(t(`${h}.toast.filePolicySaved`), 'success');
    } catch (err) {
      fireToast(t(`${h}.toast.saveFailed`, { msg: (err as Error).message }), 'warning');
    } finally {
      setSavingFile(false);
    }
  };

  // === 入侵检测 state（接 ksec-bridge）===
  const [serverInvasion, setServerInvasion] = useState<InvasionPolicy | null>(null);
  const [invasionDraft, setInvasionDraft] = useState<InvasionPolicy | null>(null);
  const [savingInvasion, setSavingInvasion] = useState(false);
  const effectiveInvasion: InvasionPolicy = invasionDraft ?? serverInvasion ?? DEFAULT_INVASION_POLICY;
  const [invasionSub, setInvasionSub] = useState<InvasionSubTab>('rules');
  const [invasionLogs, setInvasionLogs] = useState<LogEntry[]>([]);
  const [invasionExpanded, setInvasionExpanded] = useState<Set<string>>(new Set());
  const toggleInvasionExpand = (key: string): void => {
    setInvasionExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  // === 合规检测 state（接 ksec-bridge baseline 路由）===
  const [baselineStatus, setBaselineStatus] = useState<BaselineUiStatus>('home');
  const [baselineCats, setBaselineCats] = useState<BaselineCategory[]>([]);
  const [baselineReport, setBaselineReport] = useState<BaselineReport | null>(null);
  const [baselineScannedIds, setBaselineScannedIds] = useState<Set<string>>(new Set());
  /** home 状态下勾选的大类（type 名集合）。其他状态下无意义。 */
  const [baselineChecked, setBaselineChecked] = useState<Set<string>>(new Set());
  const [baselineExpanded, setBaselineExpanded] = useState<Set<string>>(new Set());
  const toggleBaselineExpand = (catType: string): void => {
    setBaselineExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(catType)) next.delete(catType);
      else next.add(catType);
      return next;
    });
  };
  const toggleBaselineChecked = (catType: string): void => {
    setBaselineChecked((prev) => {
      const next = new Set(prev);
      if (next.has(catType)) next.delete(catType);
      else next.add(catType);
      return next;
    });
  };

  /** 初次加载策略 + 状态。Tab 切到 baseline 时也再拉一次，保持新鲜。
   *  bridge 已按 `/opt/KSec/compliance/template/basic` 过滤好 29 条，前端零硬编码。 */
  const refreshBaseline = async (): Promise<void> => {
    try {
      const [cats, st] = await Promise.all([getBaselinePolicy(), getBaselineStatus()]);
      setBaselineCats(cats);
      // 首次默认勾全部大类（KSecGUI 行为）
      setBaselineChecked((prev) => (prev.size === 0 ? new Set(cats.map((c) => c.type)) : prev));
      setBaselineStatus(st.status);
      setBaselineReport(st.report ?? null);
      setBaselineScannedIds(new Set(st.scannedItemIds ?? []));
    } catch (err) {
      fireToast(t(`${h}.toast.loadBaselinePolicyFailed`, { msg: (err as Error).message }), 'warning');
    }
  };

  useEffect(() => {
    void refreshBaseline();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (mainTab === 'baseline') void refreshBaseline();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mainTab]);

  /** 当前各 detail 的 id → BaselineDetail 索引（O(1) lookup） */
  const baselineDetailMap = new Map(
    (baselineReport?.details ?? []).map((d) => [d.id, d]),
  );

  // ====== 合规检测动作 ======
  const runBaselineScan = async (): Promise<void> => {
    const ids: string[] = [];
    for (const c of baselineCats) {
      if (!baselineChecked.has(c.type)) continue;
      for (const it of c.items) ids.push(it.id);
    }
    if (ids.length === 0) {
      fireToast(t(`${h}.toast.selectOneCategory`), 'warning');
      return;
    }
    setBaselineStatus('scanning');
    try {
      await scanBaseline(ids);
      await refreshBaseline();
      fireToast(t(`${h}.toast.baselineScanComplete`), 'success');
    } catch (err) {
      fireToast(t(`${h}.toast.baselineScanFailed`, { msg: (err as Error).message }), 'warning');
      await refreshBaseline();
    }
  };
  const runBaselineRepair = async (): Promise<void> => {
    setBaselineStatus('repairing');
    try {
      await repairBaseline();
      await refreshBaseline();
      fireToast(t(`${h}.toast.repairComplete`), 'success');
    } catch (err) {
      fireToast(t(`${h}.toast.repairFailed`, { msg: (err as Error).message }), 'warning');
      await refreshBaseline();
    }
  };
  const runBaselineRollback = async (): Promise<void> => {
    setBaselineStatus('roolbacking');
    try {
      await rollbackBaseline();
      await refreshBaseline();
      fireToast(t(`${h}.toast.rollbackSuccess`), 'success');
    } catch (err) {
      fireToast(t(`${h}.toast.rollbackFailed`, { msg: (err as Error).message }), 'warning');
      await refreshBaseline();
    }
  };
  const runBaselineReset = async (): Promise<void> => {
    try {
      await resetBaseline();
      await refreshBaseline();
    } catch (err) {
      fireToast(t(`${h}.toast.resetFailed`, { msg: (err as Error).message }), 'warning');
    }
  };

  // === 入侵检测：load + SSE + setters + save ===
  useEffect(() => {
    let cancelled = false;
    getInvasionPolicy()
      .then((p) => {
        if (!cancelled) setServerInvasion(p);
      })
      .catch((err: Error) => {
        if (!cancelled) fireToast(t(`${h}.toast.loadInvasionPolicyFailed`, { msg: err.message }), 'warning');
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let mounted = true;
    getLogs('invasion', 50)
      .then((rows) => {
        if (mounted) setInvasionLogs(rows.reverse());
      })
      .catch(() => undefined);
    const es = openLogStream('invasion');
    es.onmessage = (e) => {
      try {
        const entry = JSON.parse(e.data) as LogEntry;
        setInvasionLogs((prev) => [entry, ...prev].slice(0, 200));
      } catch {
        /* malformed */
      }
    };
    return () => {
      mounted = false;
      es.close();
    };
  }, []);

  const invasionPatch = (next: Partial<InvasionPolicy>): void => {
    setInvasionDraft({ ...effectiveInvasion, ...next });
  };
  const invasionMaster = effectiveInvasion['switch-on'];
  const wlProg = effectiveInvasion.whitelistProgram;
  const wlFile = effectiveInvasion.whitelistFile;
  const wlIP = effectiveInvasion.whitelistIP;
  const enabledRuleNames = new Set(effectiveInvasion.enabledRuleNames);
  const invasionRules = INVASION_RULES_META; // 17 条展示元数据
  const enabledRulesCount = invasionRules.filter((r) => enabledRuleNames.has(r.ruleName)).length;

  const setInvasionMaster = (v: boolean): void => invasionPatch({ 'switch-on': v });
  const toggleInvasionRule = (ruleName: string, on: boolean): void => {
    const next = on
      ? [...effectiveInvasion.enabledRuleNames, ruleName]
      : effectiveInvasion.enabledRuleNames.filter((n) => n !== ruleName);
    invasionPatch({ enabledRuleNames: Array.from(new Set(next)) });
  };
  const setWlProg = (next: string[]): void => invasionPatch({ whitelistProgram: next });
  const setWlFile = (next: string[]): void => invasionPatch({ whitelistFile: next });
  const setWlIP = (next: string[]): void => invasionPatch({ whitelistIP: next });

  /**
   * 构造完整 Falco YAML body —— ids-template.yaml 是 KSec 工作版镜像：
   *
   *   [3 个用户 whitelist 块]
   *   + INVASION_PRISTINE_BODY 中所有非 rule 块（macro / 其他 list，原样保留）
   *   + INVASION_PRISTINE_BODY 中按 enabledRuleNames 过滤后的 rule 块（原样保留）
   *
   * ids-template.yaml 已经是经 KSec 开发员验证、Falco 能正常 load 的版本——
   * container.* 字段早已从模板里删干净，前端不再做任何字段净化。
   */
  const buildInvasionYmlBody = (pol: InvasionPolicy): unknown[] => {
    const whitelistBlocks = [
      { list: 'whitelist_program_path', items: pol.whitelistProgram },
      { list: 'whitelist_file_path', items: pol.whitelistFile },
      { list: 'whitelist_ip_address', items: pol.whitelistIP },
    ];
    const enabled = new Set(pol.enabledRuleNames);
    const rest = INVASION_PRISTINE_BODY.filter((b) => {
      if (b && typeof b === 'object' && 'rule' in b && typeof (b as { rule: unknown }).rule === 'string') {
        return enabled.has((b as { rule: string }).rule);
      }
      return true; // macro / 其他 list 一律保留（出厂顺序）
    });
    return [...whitelistBlocks, ...rest];
  };

  const saveInvasionPolicy = async (): Promise<void> => {
    if (!invasionDraft) return;
    setSavingInvasion(true);
    const isMasterFlip = invasionDraft['switch-on'] !== serverInvasion?.['switch-on'];
    fireToast(isMasterFlip ? t(`${h}.toast.applying`) : t(`${h}.common.saving`), 'info');
    try {
      const ymlBody = buildInvasionYmlBody(invasionDraft);
      const res = await putInvasionPolicy({ 'switch-on': invasionDraft['switch-on'], ymlBody });
      setServerInvasion(invasionDraft);
      setInvasionDraft(null);
      if (res.warning) fireToast(res.warning, 'warning');
      else fireToast(t(`${h}.toast.invasionPolicySaved`), 'success');
    } catch (err) {
      fireToast(t(`${h}.toast.saveFailed`, { msg: (err as Error).message }), 'warning');
    } finally {
      setSavingInvasion(false);
    }
  };

  // === Hero stat cards 派生 ===
  const last24h = (logs: LogEntry[]): LogEntry[] => {
    const cutoff = Date.now() - 24 * 3600 * 1000;
    return logs.filter((l) => {
      if (!l.time) return true;
      const parsed = Date.parse(l.time);
      return Number.isNaN(parsed) ? true : parsed >= cutoff;
    });
  };

  const fileLogs24 = last24h(fileLogs);
  // KSec fileprotect.getActionForLog: kill → 进程拦截; 其他都算文件拦截
  const fileKill = fileLogs24.filter((l) => l.operation === 'kill').length;
  const fileFile = fileLogs24.length - fileKill;

  const ransomLogs24 = last24h(liveLogs);
  const ransomKill = ransomLogs24.filter((l) => (l.action ?? '').toUpperCase() === 'KILL').length;
  const ransomBlock = ransomLogs24.length - ransomKill;

  const invasionLogs24 = last24h(invasionLogs);
  // 用 ruleName → type 映射对入侵告警归类（INVASION_TEMPLATE.rules 已含 type）
  const ruleNameToType = new Map(invasionRules.map((r) => [r.ruleName, r.type]));
  const invasionByType = new Map<string, number>();
  for (const log of invasionLogs24) {
    if (typeof log.rule === 'string') {
      const t2 = ruleNameToType.get(log.rule) ?? 'Other';
      invasionByType.set(t2, (invasionByType.get(t2) ?? 0) + 1);
    }
  }
  const invasionTopTypes = [...invasionByType.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 2)
    .map(([t, n]) => `${t} ${n}`)
    .join(' · ');

  // 第 1 张卡：加固代理 (bridge) 状态
  const agentStatusView = ((): { value: string; tone: 'green' | 'orange' | 'red'; sub: string } => {
    if (agentStatusErr) {
      return { value: t(`${h}.agent.offline`), tone: 'red', sub: t(`${h}.agent.bridgeUnreachable`, { msg: agentStatusErr.slice(0, 28) }) };
    }
    if (!agentStatus) {
      return { value: t(`${h}.agent.loading`), tone: 'orange', sub: t(`${h}.agent.loadingSub`) };
    }
    if (agentStatus.ready) {
      return {
        value: t(`${h}.agent.ready`),
        tone: 'green',
        sub: agentStatus.ksecDaemonRunning ? t(`${h}.agent.readyDaemon`) : t(`${h}.agent.readyBridge`),
      };
    }
    const issues: string[] = [];
    if (!agentStatus.ksecDaemonRunning) issues.push(t(`${h}.agent.ksecNotRunning`));
    if (!agentStatus.ksecBinOK) issues.push(t(`${h}.agent.ksecBinMissing`));
    if (!agentStatus.policyDirOK) issues.push(t(`${h}.agent.policyDirError`));
    if (!agentStatus.logDirOK) issues.push(t(`${h}.agent.logDirError`));
    return {
      value: t(`${h}.agent.notReady`),
      tone: 'orange',
      sub: issues.length > 0 ? issues.join(' · ') : t(`${h}.agent.partialNotReady`),
    };
  })();

  // Modal state
  type ModalState =
    | { kind: 'batch-path'; title: string; placeholder: string; onConfirm: (lines: string[]) => void }
    | { kind: 'file-rule'; onConfirm: (rule: CustomFileRule) => void }
    | { kind: 'proc-rule'; onConfirm: (rule: ProcRule) => void }
    | null;
  const [modal, setModal] = useState<ModalState>(null);
  const closeModal = () => setModal(null);

  return (
    <AdminLayout>
      <SpinnerStyle />
      <div className="secp-scope space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">{t(`${h}.breadcrumb.secplane`)}</Link>
          <span>/</span>
          <Link to="/admin/secplane/cat-isolate">{t(`${h}.breadcrumb.isolate`)}</Link>
          <span>/</span>
          <span className="crumb-current">{t(`${h}.breadcrumb.current`)}</span>
        </div>

        {/* Hero */}
        <div className="panel">
          <div className="flex items-start justify-between gap-6 mb-5">
            <div className="hero-block flex-1">
              <div className="h-eyebrow">{t(`${h}.hero.eyebrow`)}</div>
              <h2 className="h-title">{t(`${h}.hero.title`)}</h2>
              <p className="h-subtitle">{t(`${h}.hero.subtitle`)}</p>
            </div>
          </div>
          <div className="grid grid-cols-4 gap-3">
            <div className="stat-card">
              <div className="stat-card-label">{t(`${h}.stats.agentStatus`)}</div>
              <div className={`stat-card-value tone-${agentStatusView.tone}`}>{agentStatusView.value}</div>
              <div className="stat-card-sub muted-strong">{agentStatusView.sub}</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">{t(`${h}.stats.fileAlerts`)}</div>
              <div className={`stat-card-value tone-${fileLogs24.length > 0 ? 'red' : 'green'}`}>{fileLogs24.length}</div>
              <div className="stat-card-sub muted-strong">
                {fileLogs24.length === 0 ? t(`${h}.stats.noFileLogs`) : t(`${h}.stats.fileIntercept`, { file: fileFile, proc: fileKill })}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">{t(`${h}.stats.ransomAlerts`)}</div>
              <div className={`stat-card-value tone-${ransomLogs24.length > 0 ? 'red' : 'green'}`}>{ransomLogs24.length}</div>
              <div className="stat-card-sub muted-strong">
                {ransomLogs24.length === 0 ? t(`${h}.stats.noRansomLogs`) : t(`${h}.stats.ransomIntercept`, { block: ransomBlock, kill: ransomKill })}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">{t(`${h}.stats.invasionAlerts`)}</div>
              <div className={`stat-card-value tone-${invasionLogs24.length > 0 ? 'red' : 'green'}`}>{invasionLogs24.length}</div>
              <div className="stat-card-sub muted-strong">
                {invasionLogs24.length === 0 ? t(`${h}.stats.noInvasionLogs`) : (invasionTopTypes || t(`${h}.stats.invasionTotal`, { count: invasionLogs24.length }))}
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="panel" style={{ paddingBottom: 0 }}>
          <div className="tabs">
            <button className={`tab${mainTab === 'file' ? ' tab-active' : ''}`} onClick={() => setMainTab('file')}>{t(`${h}.tabs.file`)}</button>
            <button className={`tab${mainTab === 'ransome' ? ' tab-active' : ''}`} onClick={() => setMainTab('ransome')}>{t(`${h}.tabs.ransom`)}</button>
            <button className={`tab${mainTab === 'invasion' ? ' tab-active' : ''}`} onClick={() => setMainTab('invasion')}>{t(`${h}.tabs.invasion`)}</button>
            <button className={`tab${mainTab === 'baseline' ? ' tab-active' : ''}`} onClick={() => setMainTab('baseline')}>{t(`${h}.tabs.baseline`)}</button>
          </div>
        </div>

        {/* ===== 主机防护 ===== */}
        {mainTab === 'file' && (
          <div className="panel">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="eyebrow">{t(`${h}.file.eyebrow`)}</div>
                <h3 className="section-title-lg mt-1">{t(`${h}.file.title`)}</h3>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs muted-strong">{t(`${h}.common.masterSwitch`)}</span>
                <Toggle on={fileMaster} onChange={(v) => { setFileMaster(v); }} />
                <button
                  className="btn-primary btn-sm"
                  disabled={fileDraft === null || savingFile}
                  onClick={() => { void saveFilePolicy(); }}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  {savingFile && <Spinner />}
                  {savingFile ? t(`${h}.common.saving`) : t(`${h}.common.saveApply`)}
                </button>
              </div>
            </div>
            <div className="text-xs muted mb-4">
              {t(`${h}.file.desc`)}
            </div>

            {/* 防御模式 */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 14,
                padding: '12px 16px',
                background: '#fdf6f1',
                border: '1px solid #eadfd8',
                borderRadius: 10,
                marginBottom: 18,
              }}
            >
              <span className="text-xs muted-strong" style={{ whiteSpace: 'nowrap' }}>{t(`${h}.file.defenseMode`)}</span>
              <RadioBtn selected={defenseMode === 'block'} onClick={() => setDefenseMode('block')} label={t(`${h}.file.blockMode`)} />
              <RadioBtn selected={defenseMode === 'monitor'} onClick={() => setDefenseMode('monitor')} label={t(`${h}.file.monitorMode`)} />
            </div>

            {/* Sub-tabs */}
            <div className="flex gap-2 mb-4">
              <button className={`tab${fileSub === 'builtin' ? ' tab-active' : ''}`} onClick={() => setFileSub('builtin')}>
                {t(`${h}.file.builtinRules`)} {builtinEnabledPaths.size}/{builtinTemplate.length}
              </button>
              <button className={`tab${fileSub === 'fileprot' ? ' tab-active' : ''}`} onClick={() => setFileSub('fileprot')}>
                {t(`${h}.file.fileProtect`)} ({customFileRules.length})
              </button>
              <button className={`tab${fileSub === 'procprot' ? ' tab-active' : ''}`} onClick={() => setFileSub('procprot')}>
                {t(`${h}.file.processProtect`)} {procRules.filter((p) => p.type === '进程保护').length} | {procRules.filter((p) => p.type === '进程黑名单').length}
              </button>
            </div>

            {fileSub === 'builtin' && (
              <>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs muted">
                    {t(`${h}.file.builtinDesc`, { count: builtinTemplate.length })}
                  </span>
                  <label className="flex items-center gap-2 text-xs muted-strong cursor-pointer">
                    <span>{t(`${h}.file.preFileMaster`)}</span>
                    <Toggle
                      on={effectiveFilePolicy.preFileList['switch-on']}
                      onChange={togglePreFileMaster}
                    />
                  </label>
                </div>
                <div style={{ maxHeight: 520, overflowY: 'auto', border: '1px solid #eadfd8', borderRadius: 10 }}>
                  <table className="tbl" style={{ margin: 0 }}>
                    <thead style={{ position: 'sticky', top: 0, background: '#fdfaf7', zIndex: 1 }}>
                      <tr>
                        <th>{t(`${h}.file.colObject`)}</th>
                        <th>{t(`${h}.file.colDesc`)}</th>
                        <th style={{ width: 90 }}>{t(`${h}.file.colPermission`)}</th>
                        <th style={{ width: 90 }}>{t(`${h}.file.colStatus`)}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {builtinTemplate.map((rule) => (
                        <tr key={rule.path}>
                          <td><code className="text-sm font-mono text-[#171212]">{rule.path}</code></td>
                          <td><span className="text-xs muted">{rule.desc ?? '-'}</span></td>
                          <td><span className="badge badge-slate text-[10px]">{modeI18n(rule.mode, t)}</span></td>
                          <td>
                            <Toggle
                              on={builtinEnabledPaths.has(rule.path)}
                              onChange={(v) => { toggleBuiltinRule(rule.path, v); }}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {fileSub === 'fileprot' && (
              <>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs muted">{t(`${h}.file.customDesc`)}</span>
                  <button
                    className="btn-primary btn-sm"
                    disabled={customFileRules.length >= 20}
                    onClick={() =>
                      setModal({
                        kind: 'file-rule',
                        onConfirm: (rule) => {
                          addCustomFileRule(rule);
                          closeModal();
                          fireToast(t(`${h}.file.addedRule`), 'success');
                        },
                      })
                    }
                  >
                    {t(`${h}.common.add`)}
                  </button>
                </div>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>{t(`${h}.file.colFileDir`)}</th>
                      <th>{t(`${h}.file.colTrust`)}</th>
                      <th style={{ width: 50, textAlign: 'center' }}>{t(`${h}.file.read`)}</th>
                      <th style={{ width: 50, textAlign: 'center' }}>{t(`${h}.file.write`)}</th>
                      <th style={{ width: 50, textAlign: 'center' }}>{t(`${h}.file.execute`)}</th>
                      <th style={{ width: 50, textAlign: 'center' }}>{t(`${h}.file.deleteLabel`)}</th>
                      <th style={{ width: 80 }}>{t(`${h}.common.operation`)}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {customFileRules.map((rule, i) => (
                      <tr key={i}>
                        <td><code className="text-sm font-mono text-[#171212]">{rule.path}</code></td>
                        <td><code className="text-xs font-mono muted-strong">{rule.trust}</code></td>
                        {(['r', 'w', 'x', 'd'] as const).map((k) => (
                          <td key={k} style={{ textAlign: 'center' }}>
                            <span className={`badge badge-${rule[k] ? 'green' : 'slate'} text-[10px]`}>
                              {rule[k] ? '✓' : '—'}
                            </span>
                          </td>
                        ))}
                        <td>
                          <button
                            className="text-xs text-[#dc2626] font-semibold hover:underline"
                            onClick={() => {
                              removeCustomFileRule(i);
                              fireToast(t(`${h}.file.ruleDeleted`), 'success');
                            }}
                          >
                            {t(`${h}.common.delete`)}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            {fileSub === 'procprot' && (
              <>
                <div className="text-xs muted mb-3">{t(`${h}.file.procDesc`)}</div>
                <div className="flex items-center justify-between mb-3">
                  <span className="font-semibold text-[#171212] text-sm">{t(`${h}.file.procProtectBlacklist`)}</span>
                  <button
                    className="btn-primary btn-sm"
                    disabled={procRules.length >= 40}
                    onClick={() =>
                      setModal({
                        kind: 'proc-rule',
                        onConfirm: (rule) => {
                          addProcRule(rule);
                          closeModal();
                          fireToast(t(`${h}.file.procRuleAdded`), 'success');
                        },
                      })
                    }
                  >
                    {t(`${h}.common.add`)}
                  </button>
                </div>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>{t(`${h}.file.colProcPath`)}</th>
                      <th style={{ width: 130 }}>{t(`${h}.file.colRuleType`)}</th>
                      <th style={{ width: 100 }}>{t(`${h}.common.operation`)}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {procRules.map((rule, i) => (
                      <tr key={i}>
                        <td><code className="text-sm font-mono text-[#171212]">{rule.path}</code></td>
                        <td>
                          <span className={`badge badge-${rule.type === '进程保护' ? 'red' : 'orange'}`}>
                            {rule.type === '进程保护' ? t(`${h}.file.processProtectLabel`) : t(`${h}.file.processBlacklist`)}
                          </span>
                        </td>
                        <td>
                          <button
                            className="text-xs text-[#dc2626] font-semibold hover:underline"
                            onClick={() => {
                              removeProcRule(i);
                              fireToast(t(`${h}.file.ruleDeleted`), 'success');
                            }}
                          >
                            {t(`${h}.common.delete`)}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            {/* 主机防护日志 */}
            <div style={{ marginTop: 24 }}>
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-semibold text-[#171212] text-sm">{t(`${h}.file.logTitle`)}</h4>
                <button className="btn-secondary btn-sm" onClick={() => fireToast(t(`${h}.file.logRefreshed`), 'info')}>{t(`${h}.common.refresh`)}</button>
              </div>
              <table className="tbl">
                <thead>
                  <tr>
                    <th style={{ width: 160 }}>{t(`${h}.common.time`)}</th>
                    <th style={{ width: 120 }}>{t(`${h}.common.processUser`)}</th>
                    <th>{t(`${h}.common.process`)}</th>
                    <th>{t(`${h}.file.colProtectedObject`)}</th>
                    <th style={{ width: 80 }}>{t(`${h}.file.colAction`)}</th>
                    <th style={{ width: 100 }}>{t(`${h}.file.colResult`)}</th>
                  </tr>
                </thead>
                <tbody>
                  {fileLogs.length === 0 && (
                    <tr><td colSpan={6} className="text-xs muted" style={{ textAlign: 'center', padding: 16 }}>{t(`${h}.file.noLogs`)}</td></tr>
                  )}
                  {fileLogs.map((row, i) => {
                    const a = (row.action ?? '').toUpperCase();
                    const tone = a === 'BLOCK' ? 'red' : a === 'MONITOR' ? 'green' : 'slate';
                    return (
                      <tr key={i}>
                        <td><span className="text-xs muted-strong font-mono">{row.time ?? '-'}</span></td>
                        <td><span className="text-xs">{row.user ?? '-'}</span></td>
                        <td><code className="text-xs font-mono text-[#171212]">{row.process ?? '-'}</code></td>
                        <td><code className="text-xs font-mono">{row.path ?? '-'}</code></td>
                        <td><span className="badge badge-slate text-[10px]">{operationI18n(row.operation, t)}</span></td>
                        <td><span className={`badge badge-${tone}`}>{actionI18n(row.action, t)}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ===== 勒索防护 ===== */}
        {mainTab === 'ransome' && (
          <div className="panel">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="eyebrow">{t(`${h}.ransom.eyebrow`)}</div>
                <h3 className="section-title-lg mt-1">{t(`${h}.ransom.title`)}</h3>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs muted-strong">{t(`${h}.common.masterSwitch`)}</span>
                <Toggle on={ransomMaster} onChange={(v) => { setRansomMaster(v); }} />
                <button
                  className="btn-primary btn-sm"
                  disabled={policyDraft === null || saving}
                  onClick={() => { void saveRansomPolicy(); }}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  {saving && <Spinner />}
                  {saving ? t(`${h}.common.saving`) : t(`${h}.common.saveApply`)}
                </button>
              </div>
            </div>
            <div className="text-xs muted mb-4">
              {t(`${h}.ransom.desc`)}
            </div>

            {/* 关键开关 */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 14,
                padding: '12px 16px',
                background: '#fdf6f1',
                border: '1px solid #eadfd8',
                borderRadius: 10,
                marginBottom: 18,
              }}
            >
              <span className="text-xs muted-strong" style={{ whiteSpace: 'nowrap' }}>{t(`${h}.ransom.killSuspicious`)}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <RadioBtn selected={killProcess === true} onClick={() => setKillProcess(true)} label={t(`${h}.ransom.killYes`)} />
                <RadioBtn selected={killProcess === false} onClick={() => setKillProcess(false)} label={t(`${h}.ransom.killNo`)} />
              </div>
              <span className="text-xs muted ml-auto">{t(`${h}.ransom.killWarning`)}</span>
            </div>

            {/* Sub-tabs */}
            <div className="flex gap-2 mb-4">
              <button className={`tab${ransomSub === 'decoy' ? ' tab-active' : ''}`} onClick={() => setRansomSub('decoy')}>
                {t(`${h}.ransom.decoyDir`)} ({baits.length})
              </button>
              <button className={`tab${ransomSub === 'whitelist' ? ' tab-active' : ''}`} onClick={() => setRansomSub('whitelist')}>
                {t(`${h}.ransom.whitelist`)} ({ransomWhite.length})
              </button>
            </div>

            {ransomSub === 'decoy' && (
              <>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs muted">{t(`${h}.ransom.decoyDesc`)}</span>
                  <button
                    className="btn-primary btn-sm"
                    onClick={() =>
                      setModal({
                        kind: 'batch-path',
                        title: t(`${h}.ransom.addDecoyTitle`),
                        placeholder: t(`${h}.ransom.addDecoyPlaceholder`),
                        onConfirm: (lines) => {
                          setBaits([...baits, ...lines].slice(0, 20));
                          closeModal();
                          fireToast(t(`${h}.ransom.decoyAdded`), 'success');
                        },
                      })
                    }
                  >
                    {t(`${h}.common.add`)}
                  </button>
                </div>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>{t(`${h}.ransom.colDecoyDir`)}</th>
                      <th style={{ width: 120 }}>{t(`${h}.ransom.colDeployStatus`)}</th>
                      <th style={{ width: 100 }}>{t(`${h}.common.operation`)}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {baits.map((p, i) => (
                      <tr key={i}>
                        <td><code className="text-sm font-mono text-[#171212]">{p}</code></td>
                        <td><span className="badge badge-green">{t(`${h}.ransom.deployed`)}</span></td>
                        <td>
                          <button
                            className="text-xs text-[#dc2626] font-semibold hover:underline"
                            onClick={() => {
                              setBaits(baits.filter((_, idx) => idx !== i));
                              fireToast(t(`${h}.ransom.decoyDeleted`), 'success');
                            }}
                          >
                            {t(`${h}.common.delete`)}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            {ransomSub === 'whitelist' && (
              <>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs muted">{t(`${h}.ransom.whitelistDesc`)}</span>
                  <button
                    className="btn-primary btn-sm"
                    onClick={() =>
                      setModal({
                        kind: 'batch-path',
                        title: t(`${h}.ransom.addWhitelistTitle`),
                        placeholder: t(`${h}.ransom.addWhitelistPlaceholder`),
                        onConfirm: (lines) => {
                          setRansomWhite([...ransomWhite, ...lines].slice(0, 20));
                          closeModal();
                          fireToast(t(`${h}.ransom.whitelistAdded`), 'success');
                        },
                      })
                    }
                  >
                    {t(`${h}.common.add`)}
                  </button>
                </div>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>{t(`${h}.ransom.colProgramPath`)}</th>
                      <th style={{ width: 100 }}>{t(`${h}.common.operation`)}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ransomWhite.map((p, i) => (
                      <tr key={i}>
                        <td><code className="text-sm font-mono text-[#171212]">{p}</code></td>
                        <td>
                          <button
                            className="text-xs text-[#dc2626] font-semibold hover:underline"
                            onClick={() => {
                              setRansomWhite(ransomWhite.filter((_, idx) => idx !== i));
                              fireToast(t(`${h}.ransom.whitelistDeleted`), 'success');
                            }}
                          >
                            {t(`${h}.common.delete`)}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            {/* 勒索防护日志 */}
            <div style={{ marginTop: 24 }}>
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-semibold text-[#171212] text-sm">{t(`${h}.ransom.logTitle`)}</h4>
                <button className="btn-secondary btn-sm" onClick={() => fireToast(t(`${h}.file.logRefreshed`), 'info')}>{t(`${h}.common.refresh`)}</button>
              </div>
              <table className="tbl">
                <thead>
                  <tr>
                    <th style={{ width: 140 }}>{t(`${h}.common.time`)}</th>
                    <th>{t(`${h}.common.process`)}</th>
                    <th style={{ width: 120 }}>{t(`${h}.common.processUser`)}</th>
                    <th style={{ width: 130 }}>{t(`${h}.ransom.colKillProcess`)}</th>
                  </tr>
                </thead>
                <tbody>
                  {liveLogs.length === 0 && (
                    <tr>
                      <td colSpan={4} className="text-center py-6 text-xs muted">
                        {t(`${h}.ransom.noLogs`)}
                      </td>
                    </tr>
                  )}
                  {liveLogs.map((entry, i) => {
                    // 勒索防护日志的 action 只有 BLOCK / KILL 两种：
                    //   KILL  → 进程已被终止 → 终止 (红)
                    //   BLOCK → 仅拦截未终止 → 阻断 (橙)
                    const a = (entry.action ?? '').toUpperCase();
                    const killed = a === 'KILL';
                    const label = a === 'KILL' ? t(`${h}.ransom.terminated`) : a === 'BLOCK' ? t(`${h}.ransom.blocked`) : (entry.action ?? '-');
                    return (
                      <tr key={i}>
                        <td><span className="text-xs muted-strong font-mono">{entry.time ?? '-'}</span></td>
                        <td><code className="text-xs font-mono text-[#171212]">{entry.process ?? entry.path ?? entry.raw}</code></td>
                        <td><span className="text-xs">{entry.user ?? '-'}</span></td>
                        <td><span className={`badge badge-${killed ? 'red' : 'orange'}`}>{label}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ===== 入侵检测 ===== */}
        {mainTab === 'invasion' && (
          <div className="panel">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="eyebrow">{t(`${h}.invasion.eyebrow`)}</div>
                <h3 className="section-title-lg mt-1">{t(`${h}.invasion.title`)}</h3>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs muted-strong">{t(`${h}.common.masterSwitch`)}</span>
                <Toggle on={invasionMaster} onChange={(v) => { setInvasionMaster(v); }} />
                <button
                  className="btn-primary btn-sm"
                  disabled={invasionDraft === null || savingInvasion}
                  onClick={() => { void saveInvasionPolicy(); }}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  {savingInvasion && <Spinner />}
                  {savingInvasion ? t(`${h}.common.saving`) : t(`${h}.common.saveApply`)}
                </button>
              </div>
            </div>
            <div className="text-xs muted mb-4">
              {t(`${h}.invasion.desc`)}
            </div>

            {/* Sub-tabs — 与 KSecGUI Invasion.vue 对齐 */}
            <div className="flex gap-2 mb-4">
              <button className={`tab${invasionSub === 'rules' ? ' tab-active' : ''}`} onClick={() => setInvasionSub('rules')}>
                {t(`${h}.invasion.rules`)} {enabledRulesCount}/{invasionRules.length}
              </button>
              <button className={`tab${invasionSub === 'wl-prog' ? ' tab-active' : ''}`} onClick={() => setInvasionSub('wl-prog')}>
                {t(`${h}.invasion.whitelistProg`)} ({wlProg.length})
              </button>
              {/* 白名单文件 / 白名单IP 暂时下线（路由 + 保存逻辑保留，将来恢复只需删本注释） */}
            </div>

            {invasionSub === 'rules' && (
              <>
                <div className="text-xs muted mb-3">
                  {t(`${h}.invasion.rulesDesc`, { count: invasionRules.length })}
                </div>
                <div className="space-y-2" style={{ maxHeight: 480, overflowY: 'auto', paddingRight: 6 }}>
                  {invasionRules.map((r) => (
                    <div
                      key={r.ruleName}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 14,
                        padding: '12px 16px',
                        border: '1px solid #eadfd8',
                        borderRadius: 10,
                        background: 'white',
                      }}
                    >
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="flex items-center gap-2">
                          <span className="badge badge-slate text-[10px]">{r.type}</span>
                          <span className="text-sm font-semibold text-[#171212]">{r.name}</span>
                        </div>
                        <div className="text-xs muted mt-1">{r.desc}</div>
                      </div>
                      <Toggle
                        on={enabledRuleNames.has(r.ruleName)}
                        onChange={(v) => { toggleInvasionRule(r.ruleName, v); }}
                      />
                    </div>
                  ))}
                </div>
              </>
            )}

            {invasionSub === 'wl-prog' && (
              <WhitelistTable
                desc={t(`${h}.invasion.wlProgDesc`)}
                items={wlProg.map((v) => ({ value: v, desc: '' }))}
                onAdd={() =>
                  setModal({
                    kind: 'batch-path',
                    title: t(`${h}.invasion.addWlProgTitle`),
                    placeholder: t(`${h}.invasion.addWlProgPlaceholder`),
                    onConfirm: (lines) => {
                      const { ok, bad } = validateInvasionEntries(lines, 'path');
                      if (bad.length > 0) {
                        fireToast(t(`${h}.invasion.formatErrorIgnored`, { items: bad.slice(0, 3).join('、') + (bad.length > 3 ? '…' : '') }), 'warning');
                      }
                      if (ok.length === 0) { closeModal(); return; }
                      const next = mergeUnique(wlProg, ok, 20);
                      if (next.dropped > 0) fireToast(t(`${h}.invasion.exceedLimit`, { count: next.dropped }), 'warning');
                      setWlProg(next.merged);
                      closeModal();
                      fireToast(t(`${h}.invasion.wlProgAdded`), 'success');
                    },
                  })
                }
                onDelete={(i) => {
                  setWlProg(wlProg.filter((_, idx) => idx !== i));
                  fireToast(t(`${h}.invasion.deleted`), 'success');
                }}
                col1={t(`${h}.invasion.colProgramPath`)}
              />
            )}

            {invasionSub === 'wl-file' && (
              <WhitelistTable
                desc="白名单文件操作不会触发入侵告警，最多 20 条。"
                items={wlFile.map((v) => ({ value: v, desc: '' }))}
                onAdd={() =>
                  setModal({
                    kind: 'batch-path',
                    title: '添加白名单文件',
                    placeholder: '支持输入单条/多条文件路径，每行填写一条，最多支持 20 条',
                    onConfirm: (lines) => {
                      const { ok, bad } = validateInvasionEntries(lines, 'path');
                      if (bad.length > 0) {
                        fireToast(`格式错误已忽略：${bad.slice(0, 3).join('、')}${bad.length > 3 ? '…' : ''}`, 'warning');
                      }
                      if (ok.length === 0) { closeModal(); return; }
                      const next = mergeUnique(wlFile, ok, 20);
                      if (next.dropped > 0) fireToast(`超过 20 条上限，丢弃 ${next.dropped} 条`, 'warning');
                      setWlFile(next.merged);
                      closeModal();
                      fireToast('已添加白名单文件', 'success');
                    },
                  })
                }
                onDelete={(i) => {
                  setWlFile(wlFile.filter((_, idx) => idx !== i));
                  fireToast('已删除', 'success');
                }}
                col1="文件路径"
              />
            )}

            {invasionSub === 'wl-ip' && (
              <WhitelistTable
                desc="来自白名单 IP 的访问不会被判定为入侵，最多 20 条。Falco 仅支持单 IPv4 字面量，不支持 CIDR。"
                items={wlIP.map((v) => ({ value: v, desc: '' }))}
                onAdd={() =>
                  setModal({
                    kind: 'batch-path',
                    title: '添加白名单 IP',
                    placeholder: '每行一条 IPv4 字面量（如 10.0.0.5），最多 20 条；不支持 CIDR',
                    onConfirm: (lines) => {
                      const { ok, bad } = validateInvasionEntries(lines, 'ip');
                      if (bad.length > 0) {
                        fireToast(`非法 IP 已忽略：${bad.slice(0, 3).join('、')}${bad.length > 3 ? '…' : ''}（仅接受单 IPv4，不支持 CIDR）`, 'warning');
                      }
                      if (ok.length === 0) { closeModal(); return; }
                      const next = mergeUnique(wlIP, ok, 20);
                      if (next.dropped > 0) fireToast(`超过 20 条上限，丢弃 ${next.dropped} 条`, 'warning');
                      setWlIP(next.merged);
                      closeModal();
                      fireToast('已添加白名单 IP', 'success');
                    },
                  })
                }
                onDelete={(i) => {
                  setWlIP(wlIP.filter((_, idx) => idx !== i));
                  fireToast('已删除', 'success');
                }}
                col1="IPv4 地址"
              />
            )}

            {/* 入侵检测日志 — SSE 实时推流，源 = /opt/KSec/log/intrusion_detection.log
                展示方式参考 KSecGUI/components/InvasionLog.vue */}
            <div style={{ marginTop: 24 }}>
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-semibold text-[#171212] text-sm">{t(`${h}.invasion.logTitle`)}</h4>
                <button className="btn-secondary btn-sm" onClick={() => fireToast(t(`${h}.file.logRefreshed`), 'info')}>{t(`${h}.common.refresh`)}</button>
              </div>
              <table className="tbl">
                <thead>
                  <tr>
                    <th style={{ width: 160 }}>{t(`${h}.common.time`)}</th>
                    <th style={{ width: 130 }}>{t(`${h}.invasion.colCategory`)}</th>
                    <th style={{ width: 200 }}>{t(`${h}.common.process`)}</th>
                    <th style={{ width: 100 }}>{t(`${h}.common.processUser`)}</th>
                    <th>{t(`${h}.invasion.colDesc`)}</th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const rows: InvasionLogRow[] = invasionLogs
                      .map((entry, idx) => enrichInvasionLog(entry as unknown as { time?: string; rule?: string; output_fields?: Record<string, unknown> }, idx))
                      .filter((r): r is InvasionLogRow => r !== null);
                    if (rows.length === 0) {
                      return (
                        <tr>
                          <td colSpan={5} className="text-xs muted" style={{ textAlign: 'center', padding: 16 }}>
                            {t(`${h}.invasion.noLogs`)}
                          </td>
                        </tr>
                      );
                    }
                    return rows.flatMap((row) => {
                      const isOpen = invasionExpanded.has(row.key);
                      return [
                        <tr key={row.key}>
                          <td><span className="text-xs muted-strong font-mono">{row.time}</span></td>
                          <td><span className="badge badge-red text-[10px]">{row.ruleType}</span></td>
                          <td>
                            <button
                              type="button"
                              onClick={() => toggleInvasionExpand(row.key)}
                              title={row.source}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 4,
                                background: 'transparent',
                                border: 'none',
                                padding: 0,
                                cursor: 'pointer',
                                color: '#0070e0',
                                fontFamily: 'ui-monospace,SFMono-Regular,Menlo,monospace',
                                fontSize: 12,
                                maxWidth: 180,
                                whiteSpace: 'nowrap',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                              }}
                            >
                              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{row.source}</span>
                              <span aria-hidden style={{ fontSize: 9 }}>{isOpen ? '▲' : '▼'}</span>
                            </button>
                          </td>
                          <td><span className="text-xs">{row.user}</span></td>
                          <td><span className="text-xs">{row.desc}</span></td>
                        </tr>,
                        isOpen ? (
                          <tr key={`${row.key}-chain`}>
                            <td colSpan={5} style={{ background: '#fafafa' }}>
                              <span className="text-xs muted" title={row.processChain}>{row.processChain}</span>
                            </td>
                          </tr>
                        ) : null,
                      ];
                    });
                  })()}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ===== 合规检测 / CIS 基线（mock 矩阵；待接 KSec baseline 模块）===== */}
        {mainTab === 'baseline' && (() => {
          const isInProgress = baselineStatus === 'scanning' || baselineStatus === 'repairing' || baselineStatus === 'roolbacking';
          const phase: 'scanned' | 'repaired' | 'rollbacked' | null =
            baselineStatus === 'scanned' ? 'scanned' :
            baselineStatus === 'repaired' ? 'repaired' :
            baselineStatus === 'rollbacked' ? 'rollbacked' : null;
          const ov = baselineReport?.overview ?? {};
          return (
            <div className="panel">
              {/* Hero: 头部状态卡 */}
              <div
                className="flex items-start justify-between mb-4"
                style={{ padding: 16, background: '#fdf6f1', border: '1px solid #eadfd8', borderRadius: 10 }}
              >
                <div className="flex-1">
                  <div className="eyebrow">{t(`${h}.baseline.eyebrow`)}</div>
                  {baselineStatus === 'home' && (
                    <>
                      <h3 className="section-title-lg mt-1">{t(`${h}.baseline.homeTitle`)}</h3>
                      <div className="text-xs muted mt-1">
                        {t(`${h}.baseline.homeDesc`)}
                      </div>
                    </>
                  )}
                  {baselineStatus === 'scanned' && (
                    <>
                      <h3 className="section-title-lg mt-1">
                        {t(`${h}.baseline.scannedTitle`, { count: ov['不通过项'] ?? 0 })}
                        <span style={{ color: Number(ov['不通过项']) === 0 ? '#00c63c' : '#ff830c', fontWeight: 700, margin: '0 4px' }}>
                          {ov['不通过项'] ?? 0}
                        </span>
                      </h3>
                      <div className="text-xs muted mt-1">
                        {ov['检测时间'] && <span className="font-mono muted-strong mr-3">{ov['检测时间']}</span>}
                        {t(`${h}.baseline.scannedDesc`, { total: ov['总检测项'] ?? 0 })}
                      </div>
                    </>
                  )}
                  {baselineStatus === 'repaired' && (
                    <>
                      <h3 className="section-title-lg mt-1">{t(`${h}.baseline.repairedTitle`)}</h3>
                      <div className="text-xs muted mt-1">
                        {ov['修复时间'] && <span className="font-mono muted-strong mr-3">{ov['修复时间']}</span>}
                        {t(`${h}.baseline.repairedDesc`, { success: ov['成功项'] ?? 0, fail: ov['失败项'] ?? 0 })}
                      </div>
                    </>
                  )}
                  {baselineStatus === 'rollbacked' && (
                    <>
                      <h3 className="section-title-lg mt-1">{t(`${h}.baseline.rollbackedTitle`)}</h3>
                      <div className="text-xs muted mt-1">
                        {ov['回滚时间'] && <span className="font-mono muted-strong mr-3">{ov['回滚时间']}</span>}
                        {t(`${h}.baseline.rollbackedDesc`, { success: ov['成功项'] ?? 0, fail: ov['失败项'] ?? 0 })}
                      </div>
                    </>
                  )}
                  {isInProgress && (
                    <>
                      <h3 className="section-title-lg mt-1 flex items-center gap-2">
                        <Spinner size={16} />
                        {baselineStatus === 'scanning' && t(`${h}.baseline.scanning`)}
                        {baselineStatus === 'repairing' && t(`${h}.baseline.repairing`)}
                        {baselineStatus === 'roolbacking' && t(`${h}.baseline.rollingBack`)}
                      </h3>
                      <div className="text-xs muted mt-1">{t(`${h}.baseline.backendRunning`)}</div>
                    </>
                  )}
                </div>
                {!isInProgress && (
                  <div className="flex items-center gap-2">
                    {baselineStatus === 'home' && (
                      <button
                        className="btn-primary btn-sm"
                        disabled={baselineChecked.size === 0}
                        onClick={() => void runBaselineScan()}
                      >{t(`${h}.baseline.scanNow`)}</button>
                    )}
                    {baselineStatus === 'scanned' && (
                      <>
                        <button className="btn-secondary btn-sm" onClick={() => void runBaselineReset()}>{t(`${h}.baseline.rescan`)}</button>
                        <button className="btn-primary btn-sm" onClick={() => void runBaselineRepair()}>{t(`${h}.baseline.repairNow`)}</button>
                      </>
                    )}
                    {baselineStatus === 'repaired' && (
                      <>
                        <button className="btn-secondary btn-sm" onClick={() => void runBaselineRollback()}>{t(`${h}.baseline.rollback`)}</button>
                        <button className="btn-primary btn-sm" onClick={() => void runBaselineReset()}>{t(`${h}.baseline.rescan`)}</button>
                      </>
                    )}
                    {baselineStatus === 'rollbacked' && (
                      <button className="btn-primary btn-sm" onClick={() => void runBaselineReset()}>{t(`${h}.baseline.rescan`)}</button>
                    )}
                  </div>
                )}
              </div>

              {/* 5 大类列表 */}
              {baselineCats.length === 0 && (
                <div className="text-xs muted text-center" style={{ padding: 32 }}>
                  {t(`${h}.baseline.noPolicy`)}
                </div>
              )}
              <div className="space-y-3">
                {baselineCats.map((cat) => {
                  const catScanned = cat.items.some((it) => baselineScannedIds.has(it.id));
                  let successNum = 0;
                  let failNum = 0;
                  if (phase && catScanned) {
                    for (const it of cat.items) {
                      const d = baselineDetailMap.get(it.id);
                      if (!d) continue;
                      if (d.result === 'success') successNum++;
                      else if (d.result === 'fail' || d.result === '不支持') failNum++;
                    }
                  }
                  const isOpen = baselineExpanded.has(cat.type);
                  return (
                    <div key={cat.type} style={{ border: '1px solid #eadfd8', borderRadius: 10, background: 'white' }}>
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 12,
                          padding: '12px 16px',
                        }}
                      >
                        {baselineStatus === 'home' && (
                          <input
                            type="checkbox"
                            checked={baselineChecked.has(cat.type)}
                            onChange={() => toggleBaselineChecked(cat.type)}
                            style={{ accentColor: '#dc2626' }}
                          />
                        )}
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div className="text-sm font-semibold text-[#171212]">{cat.type}</div>
                          <div className="text-xs muted mt-0.5">{cat.description}</div>
                        </div>
                        <button
                          type="button"
                          onClick={() => toggleBaselineExpand(cat.type)}
                          style={{
                            background: 'transparent', border: 'none', cursor: 'pointer',
                            fontSize: 12, color: '#6b7280', display: 'inline-flex', alignItems: 'center', gap: 6,
                          }}
                        >
                          {baselineStatus === 'home' && <span>{t(`${h}.baseline.items`, { count: cat.items.length })}</span>}
                          {phase && catScanned && (
                            <span>
                              {phase === 'scanned' ? (
                                <>{t(`${h}.baseline.itemsWithRisk`, { total: cat.items.length, risk: failNum })}</>
                              ) : (
                                <>成功 <span style={{ color: '#0070e0', fontWeight: 700 }}>{successNum}</span> 项{failNum > 0 && <>，失败 <span style={{ color: '#ff830c', fontWeight: 700 }}>{failNum}</span> 项</>}</>
                              )}
                            </span>
                          )}
                          {phase && !catScanned && (
                            <span>{cat.items.length} 项，<span style={{ color: '#989cb2' }}>{t(`${h}.baseline.notChecked`)}</span></span>
                          )}
                          <span aria-hidden style={{ fontSize: 10 }}>{isOpen ? '▲' : '▼'}</span>
                        </button>
                      </div>
                      {isOpen && (
                        <div style={{ borderTop: '1px solid #eadfd8' }}>
                          <table className="tbl" style={{ margin: 0 }}>
                            <thead style={{ background: '#fdfaf7' }}>
                              <tr>
                                <th>检测项</th>
                                {!phase && <th style={{ width: 180 }}>基线值</th>}
                                {phase === 'scanned' && (<><th style={{ width: 150 }}>基线值</th><th style={{ width: 150 }}>实际值</th><th style={{ width: 100 }}>检测结果</th></>)}
                                {phase === 'repaired' && (<><th style={{ width: 150 }}>修复前</th><th style={{ width: 150 }}>修复后</th><th style={{ width: 100 }}>修复结果</th></>)}
                                {phase === 'rollbacked' && (<><th style={{ width: 150 }}>回滚前</th><th style={{ width: 150 }}>回滚后</th><th style={{ width: 100 }}>回滚结果</th></>)}
                              </tr>
                            </thead>
                            <tbody>
                              {cat.items.map((it) => {
                                const d = phase ? baselineDetailMap.get(it.id) : undefined;
                                const before = d?.before ?? '-';
                                const after = d?.after ?? '-';
                                const result = catScanned ? (d?.result ?? (phase === 'scanned' ? 'security' : 'uncheck')) : 'uncheck';
                                const label = phase ? baselineResultLabel(result, phase) : null;
                                const valStr = String(it.value === true ? 'true' : it.value);
                                return (
                                  <tr key={it.id}>
                                    <td>
                                      <div className="text-sm text-[#171212]">{it.name}</div>
                                      {it.desp && <div className="text-xs muted" style={{ marginTop: 2 }}>{it.desp}</div>}
                                    </td>
                                    {!phase && (
                                      <td>
                                        <span title={it.remark ?? ''} style={{ borderBottom: it.remark ? '1px dashed #999' : 'none' }}>
                                          {valStr === '-1' && it.remark ? `${valStr} ⓘ` : valStr}
                                        </span>
                                      </td>
                                    )}
                                    {phase && (
                                      <>
                                        <td><code className="text-xs font-mono">{before === ',' || !before ? '-' : before}</code></td>
                                        <td><code className="text-xs font-mono">{after === ',' || !after ? '-' : after}</code></td>
                                        <td><span style={{ color: label?.color }} className="text-xs">{label?.text ?? '-'}</span></td>
                                      </>
                                    )}
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })()}

        {/* ===== Modals ===== */}
        {modal?.kind === 'batch-path' && (
          <BatchPathModal title={modal.title} placeholder={modal.placeholder} onCancel={closeModal} onConfirm={modal.onConfirm} />
        )}
        {modal?.kind === 'file-rule' && <FileRuleModal onCancel={closeModal} onConfirm={modal.onConfirm} />}
        {modal?.kind === 'proc-rule' && <ProcRuleModal onCancel={closeModal} onConfirm={modal.onConfirm} />}

        <Toast toast={toast} onClose={() => setToast(null)} />
      </div>
    </AdminLayout>
  );
};

// 抽出共用：白名单列表
type LabeledItem = { value: string; desc: string };
const WhitelistTable: React.FC<{
  desc: string;
  items: LabeledItem[];
  onAdd: () => void;
  onDelete: (i: number) => void;
  col1: string;
}> = ({ desc, items, onAdd, onDelete, col1 }) => (
  <>
    <div className="flex items-center justify-between mb-3">
      <span className="text-xs muted">{desc}</span>
      <button className="btn-primary btn-sm" onClick={onAdd}>+ 添加</button>
    </div>
    <table className="tbl">
      <thead>
        <tr>
          <th style={{ width: 200 }}>{col1}</th>
          <th>说明</th>
          <th style={{ width: 100 }}>操作</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, i) => (
          <tr key={i}>
            <td><code className="text-sm font-mono text-[#171212]">{item.value}</code></td>
            <td><span className="text-xs muted">{item.desc || '-'}</span></td>
            <td>
              <button className="text-xs text-[#dc2626] font-semibold hover:underline" onClick={() => onDelete(i)}>删除</button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </>
);

// ===========================
// Modals
// ===========================

const BatchPathModal: React.FC<{
  title: string;
  placeholder: string;
  onCancel: () => void;
  onConfirm: (lines: string[]) => void;
}> = ({ title, placeholder, onCancel, onConfirm }) => {
  const [text, setText] = useState('');
  const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
  return (
    <Modal
      open
      eyebrow="新建"
      title={title}
      onClose={onCancel}
      footer={
        <>
          <button className="btn-secondary" onClick={onCancel}>取消</button>
          <button className="btn-primary" disabled={lines.length === 0} onClick={() => onConfirm(lines)}>确定</button>
        </>
      }
    >
      <textarea
        className="input"
        rows={10}
        style={{
          width: '100%',
          fontFamily: 'ui-monospace,SFMono-Regular,Menlo,monospace',
          fontSize: 12,
          lineHeight: 1.6,
          resize: 'vertical',
        }}
        placeholder={placeholder}
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <div className="text-xs muted mt-2">每行填写一条，最多支持 20 条</div>
    </Modal>
  );
};

const FileRuleModal: React.FC<{
  onCancel: () => void;
  onConfirm: (rule: CustomFileRule) => void;
}> = ({ onCancel, onConfirm }) => {
  const [path, setPath] = useState('');
  const [trust, setTrust] = useState('');
  const [r, setR] = useState(false);
  const [w, setW] = useState(false);
  const [x, setX] = useState(false);
  const [d, setD] = useState(false);
  const canSubmit = path.startsWith('/');
  return (
    <Modal
      open
      eyebrow="新建"
      title="添加文件防护规则"
      onClose={onCancel}
      footer={
        <>
          <button className="btn-secondary" onClick={onCancel}>取消</button>
          <button className="btn-primary" disabled={!canSubmit} onClick={() => onConfirm({ path, trust: trust || '-', r, w, x, d })}>确定</button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <div className="eyebrow text-[10px] mb-1"><span style={{ color: '#dc2626' }}>*</span> 保护文件/目录</div>
          <input className="input" placeholder="请输入绝对路径" value={path} onChange={(e) => setPath(e.target.value)} />
        </div>
        <div>
          <div className="eyebrow text-[10px] mb-1">信任进程 <span
            className="muted"
            title={'信任进程为空时表示信任所有进程\n支持目录形式'}
          >ⓘ</span></div>
          <textarea
            className="input"
            rows={5}
            style={{ fontFamily: 'ui-monospace,SFMono-Regular,Menlo,monospace', fontSize: 12, lineHeight: 1.6, resize: 'vertical' }}
            placeholder="支持输入单条/多条信任进程，每行填写一条，最多 20 条；支持目录"
            value={trust}
            onChange={(e) => setTrust(e.target.value)}
          />
        </div>
        <div>
          <div className="eyebrow text-[10px] mb-2">权限 <span
            className="muted"
            title={'1、权限：配置信任进程对保护文件/目录的权限，非信任进程对保护文件/目录无权限\n2、写：包含创建、写、移动或重命名权限'}
          >ⓘ</span></div>
          <div className="flex items-center gap-5">
            <label className="flex items-center gap-1.5 cursor-pointer text-sm">
              <input type="checkbox" style={{ accentColor: '#dc2626' }} checked={r} onChange={(e) => setR(e.target.checked)} /> 读
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer text-sm">
              <input type="checkbox" style={{ accentColor: '#dc2626' }} checked={w} onChange={(e) => setW(e.target.checked)} /> 写
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer text-sm">
              <input type="checkbox" style={{ accentColor: '#dc2626' }} checked={x} onChange={(e) => setX(e.target.checked)} /> 执行
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer text-sm">
              <input type="checkbox" style={{ accentColor: '#dc2626' }} checked={d} onChange={(e) => setD(e.target.checked)} /> 删除
            </label>
          </div>
        </div>
      </div>
    </Modal>
  );
};

const ProcRuleModal: React.FC<{
  onCancel: () => void;
  onConfirm: (rule: ProcRule) => void;
}> = ({ onCancel, onConfirm }) => {
  const [type, setType] = useState<'进程保护' | '进程黑名单'>('进程保护');
  const [path, setPath] = useState('');
  const lines = path.split('\n').map((l) => l.trim()).filter(Boolean);
  return (
    <Modal
      open
      eyebrow="新建"
      title="添加进程防护规则"
      onClose={onCancel}
      footer={
        <>
          <button className="btn-secondary" onClick={onCancel}>取消</button>
          <button
            className="btn-primary"
            disabled={lines.length === 0}
            onClick={() => onConfirm({ path: lines[0], type })}
          >
            确定
          </button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <div className="eyebrow text-[10px] mb-1"><span style={{ color: '#dc2626' }}>*</span> 规则类型</div>
          <select className="input" value={type} onChange={(e) => setType(e.target.value as ProcRule['type'])}>
            <option value="进程保护">进程保护</option>
            <option value="进程黑名单">进程黑名单</option>
          </select>
        </div>
        <div>
          <div className="eyebrow text-[10px] mb-1"><span style={{ color: '#dc2626' }}>*</span> 进程路径</div>
          <textarea
            className="input"
            rows={6}
            style={{ fontFamily: 'ui-monospace,SFMono-Regular,Menlo,monospace', fontSize: 12, lineHeight: 1.6, resize: 'vertical' }}
            placeholder="支持输入单条/多条进程路径，每行填写一条，最多支持 20 条"
            value={path}
            onChange={(e) => setPath(e.target.value)}
          />
        </div>
      </div>
    </Modal>
  );
};

export default HostHardeningPage;
