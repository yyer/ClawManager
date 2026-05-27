import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';
import {
  getLogs,
  getRansomPolicy,
  openLogStream,
  putRansomPolicy,
} from '../../../../services/hostHardening';
import {
  DEFAULT_RANSOM_POLICY,
  type LogEntry,
  type RansomPolicy,
} from '../../../../types/hostHardening';

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
// 主机防护 — 内置规则数据
// ===========================

const BUILTIN_FILE_RULES: Array<[path: string, desc: string, type: '文件' | '目录']> = [
  ['/usr/bin', '保护系统目录下可执行文件不被篡改', '目录'],
  ['/usr/sbin', '保护系统目录下可执行文件不被篡改', '目录'],
  ['/boot', '保护grub配置和内核镜像不被篡改', '目录'],
  ['/etc/inittab', '保护系统运行级别配置文件不被篡改', '文件'],
  ['/lib/systemd/system/graphical.target', '保护图形界面配置文件不被篡改', '文件'],
  ['/usr/lib/systemd/system/graphical.target', '保护图形界面配置文件不被篡改', '文件'],
  ['/lib/systemd/system/multi-user.target', '保护多用户命令行目标单元文件不被篡改', '文件'],
  ['/usr/lib/systemd/system/multi-user.target', '保护多用户命令行目标单元文件不被篡改', '文件'],
  ['/etc/audit', '保护日志和审计配置文件不被篡改', '目录'],
  ['/etc/pam.d', '保护登录认证配置文件不被篡改', '目录'],
  ['/etc/ld.so.preload', '保护动态库配置文件不被篡改', '文件'],
  ['/etc/ssh', '保护SSH配置文件不被篡改', '目录'],
  ['/etc/profile', '保护Bash配置文件不被篡改', '文件'],
  ['/etc/profile.d', '保护Bash配置文件不被篡改', '目录'],
  ['/etc/bash.bashrc', '保护Bash配置文件不被篡改', '文件'],
  ['/etc/bashrc', '保护Bash配置文件不被篡改', '文件'],
  ['/root/.bashrc', '保护Bash配置文件不被篡改', '文件'],
  ['/root/.bash_profile', '保护Bash配置文件不被篡改', '文件'],
  ['/etc/dnf/dnf.conf', '保护软件更新配置文件不被篡改', '文件'],
  ['/etc/yum', '保护软件更新配置文件不被篡改', '目录'],
  ['/etc/yum.repos.d', '保护软件更新配置文件不被篡改', '目录'],
  ['/etc/apt', '保护软件更新配置文件不被篡改', '目录'],
  ['/etc/cron.deny', '保护定时任务配置文件不被篡改', '文件'],
  ['/etc/crontab', '保护定时任务配置文件不被篡改', '文件'],
  ['/etc/cron.d', '保护定时任务配置文件不被篡改', '目录'],
  ['/etc/cron.daily', '保护定时任务配置文件不被篡改', '目录'],
  ['/etc/cron.hourly', '保护定时任务配置文件不被篡改', '目录'],
  ['/etc/cron.monthly', '保护定时任务配置文件不被篡改', '目录'],
  ['/etc/cron.weekly', '保护定时任务配置文件不被篡改', '目录'],
  ['/var/spool/cron', '保护定时任务配置文件不被篡改', '目录'],
  ['/etc/anacrontab', '保护定时任务配置文件不被篡改', '文件'],
  ['/etc/resolv.conf', '保护域名解析文件不被篡改', '文件'],
  ['/run/resolvconf/resolv.conf', '保护域名解析文件不被篡改', '文件'],
  ['/etc/host.conf', '保护域名解析文件不被篡改', '文件'],
  ['/etc/hosts.allow', '保护访问配置文件不被篡改', '文件'],
  ['/etc/hosts.deny', '保护访问配置文件不被篡改', '文件'],
  ['/proc/kallsyms', '保护内存镜像和内核导出符号文件不被篡改', '文件'],
];

type CustomFileRule = {
  path: string;
  trust: string;
  r: boolean;
  w: boolean;
  x: boolean;
  d: boolean;
};
const INITIAL_CUSTOM_FILE_RULES: CustomFileRule[] = [
  { path: '/var/lib/clawmanager/data', trust: '/opt/clawmanager/server', r: true, w: true, x: false, d: false },
  { path: '/var/lib/clawmanager/uploads', trust: '/opt/clawmanager/server', r: true, w: true, x: false, d: true },
  { path: '/etc/clawmanager', trust: '/opt/clawmanager/server', r: true, w: true, x: false, d: false },
  { path: '/opt/clawmanager/config/*', trust: '/opt/clawmanager/server', r: true, w: true, x: false, d: false },
  { path: '/var/lib/mysql/clawmanager', trust: '/usr/sbin/mysqld', r: true, w: true, x: false, d: false },
  { path: '/var/log/clawmanager/*', trust: '/opt/clawmanager/server, /usr/sbin/rsyslogd', r: true, w: true, x: false, d: true },
  { path: '/etc/nginx/nginx.conf', trust: '/usr/sbin/nginx', r: true, w: false, x: false, d: false },
  { path: '/etc/ksecure/policies/*', trust: '/opt/ksecure/ksec', r: true, w: true, x: false, d: false },
  { path: '/tmp/test-decoy', trust: '-', r: false, w: false, x: false, d: false },
];

type ProcRule = { path: string; type: '进程保护' | '进程黑名单' };
const INITIAL_PROC_RULES: ProcRule[] = [
  { path: '/usr/sbin/auditd', type: '进程保护' },
  { path: '/opt/clawmanager/server', type: '进程保护' },
];

const FILE_PROT_LOG: Array<[string, string, string, string, string, string]> = [
  ['2026-05-19 14:48:22', 'root', '/tmp/x (pid 8721)', '/etc/passwd', '写入', '已阻断'],
  ['2026-05-19 14:35:15', 'www-data', '/bin/rm (pid 4521)', '/var/log/auth.log', '删除', '已阻断'],
  ['2026-05-19 14:18:33', 'root', '/bin/chmod (pid 3211)', '/etc/shadow', '修改权限', '已阻断'],
  ['2026-05-19 13:52:11', 'sshd', '/usr/sbin/sshd (pid 1024)', '/etc/ssh/sshd_config', '读取', '放行'],
  ['2026-05-19 12:24:48', 'admin', '/bin/echo (pid 7811)', '/tmp/payload.sh', '写入', '非受保护'],
];

// 勒索防护数据已迁移到 ksec-bridge（/api/host/policy/ransome + /api/host/logs/stream?module=ransome）

// ===========================
// 入侵检测
// ===========================

type IntrusionRule = { icon: string; cat: string; desc: string; enabled: boolean };
const INITIAL_INTRUSION_RULES: IntrusionRule[] = [
  { icon: '📡', cat: '反弹shell', desc: '检测进程的非法网络连接行为', enabled: true },
  { icon: '🧠', cat: '无文件执行', desc: '检测使用 memfd_create 创建匿名内存文件并在其中执行代码的行为', enabled: true },
  { icon: '🔼', cat: '本地提权', desc: '检测使用 setuid 改变用户权限的行为', enabled: true },
  { icon: '🔼', cat: '本地提权', desc: '检测使用 chmod 设置 setuid 或 setgid 位权限的行为', enabled: true },
  { icon: '🔼', cat: '本地提权', desc: '检测修改 sudoers 文件提升权限的行为', enabled: true },
  { icon: '💉', cat: '进程注入', desc: '检测使用 ptrace 向进程注入代码的行为', enabled: true },
  { icon: '💉', cat: '进程注入', desc: '检测篡改进程内存数据注入代码的行为', enabled: true },
  { icon: '🔗', cat: '敏感文件泄漏', desc: '检测创建 /etc 或根目录下敏感文件硬链接的行为', enabled: true },
  { icon: '🔗', cat: '敏感文件泄漏', desc: '检测创建 /etc 或根目录下敏感文件/目录软链接的行为', enabled: true },
  { icon: '🦠', cat: 'rootkit攻击', desc: '检测 /dev 目录下创建文件的行为', enabled: true },
  { icon: '🦠', cat: 'rootkit攻击', desc: '检测 /bin 等目录下创建文件的行为', enabled: true },
  { icon: '🦠', cat: 'rootkit攻击', desc: '检测篡改 /etc/ld.so.preload 文件的行为', enabled: true },
  { icon: '🧩', cat: '内核模块加载', desc: '检测使用 insmod 或 modprobe 加载内核模块的行为', enabled: true },
  { icon: '🧹', cat: '痕迹擦除', desc: '检测清除系统审计日志的行为', enabled: true },
  { icon: '⏰', cat: '计划任务篡改', desc: '检测创建或修改计划任务的行为', enabled: true },
  { icon: '📂', cat: 'shm目录非法执行', desc: '检测 /dev/shm 目录下执行文件的行为', enabled: true },
  { icon: '🛠️', cat: '可疑工具执行', desc: '检测主机/容器启动可疑网络工具的行为', enabled: true },
];

type LabeledItem = { value: string; desc: string };
const INITIAL_WL_PROG: LabeledItem[] = [
  { value: '/usr/bin/strace', desc: '调试工具' },
  { value: '/usr/bin/gdb', desc: '调试器' },
  { value: '/usr/bin/ansible-playbook', desc: '运维工具' },
  { value: '/opt/clawmanager/upgrade-helper', desc: '内置升级辅助' },
];
const INITIAL_WL_FILE: LabeledItem[] = [
  { value: '/var/lib/clawmanager/upgrade-pending', desc: '升级临时文件' },
  { value: '/tmp/clawmanager-cache/*', desc: '缓存目录' },
];
const INITIAL_WL_IP: LabeledItem[] = [
  { value: '10.0.0.0/8', desc: '内网 VPC' },
  { value: '172.18.0.0/16', desc: 'K8s Pod 网段' },
  { value: '203.0.113.42', desc: '运维跳板机' },
];

const INTRUSION_LOG: Array<[string, string, string, string, string]> = [
  ['2026-05-19 14:42:11', 'SSH 暴力破解', '/usr/sbin/sshd (pid 9821)', 'sshd', '源 IP 45.142.x.x 在 1 分钟内 50 次失败登录'],
  ['2026-05-19 14:18:03', '进程注入', '/usr/bin/curl (pid 9821)', 'www-data', 'curl 进程尝试 ptrace pid 1（init）'],
  ['2026-05-19 13:22:45', '端口扫描', '/usr/bin/nmap (pid 7234)', 'admin', '检测到 217 端口连接/秒'],
  ['2026-05-19 10:51:18', '本地提权', '/tmp/x (pid 6712)', 'www-data', '尝试修改 /etc/sudoers 提升权限'],
  ['2026-05-19 09:33:22', '反弹shell', '/bin/bash (pid 5891)', 'root', '检测到 /dev/tcp/45.x.x.x/4444 反向 shell'],
];

// ===========================
// 主页
// ===========================

type MainTab = 'file' | 'ransome' | 'invasion';
type FileSubTab = 'builtin' | 'fileprot' | 'procprot';
type RansomeSubTab = 'decoy' | 'whitelist';
type InvasionSubTab = 'rules' | 'wl-prog' | 'wl-file' | 'wl-ip';

const HostHardeningPage: React.FC = () => {
  const [mainTab, setMainTab] = useState<MainTab>('file');
  const [toast, setToast] = useState<ToastState>(null);
  const fireToast = (message: string, kind: ToastKind = 'info') => setToast({ message, kind });

  // 主机防护 state
  const [fileMaster, setFileMaster] = useState(true);
  const [defenseMode, setDefenseMode] = useState<'block' | 'monitor'>('monitor');
  const [builtinEnabled, setBuiltinEnabled] = useState<boolean[]>(() => BUILTIN_FILE_RULES.map(() => true));
  const [customFileRules, setCustomFileRules] = useState<CustomFileRule[]>(INITIAL_CUSTOM_FILE_RULES);
  const [procRules, setProcRules] = useState<ProcRule[]>(INITIAL_PROC_RULES);
  const [fileSub, setFileSub] = useState<FileSubTab>('builtin');

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
        if (!cancelled) fireToast(`加载策略失败：${err.message}`, 'warning');
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
    fireToast(isMasterFlip ? '正在应用… 涉及 KSec daemon 重启，约 3-5 秒' : '保存中…', 'info');
    try {
      await putRansomPolicy(policyDraft);
      setServerPolicy(policyDraft);
      setPolicyDraft(null);
      fireToast('配置已保存', 'success');
    } catch (err) {
      fireToast(`保存失败：${(err as Error).message}`, 'warning');
    } finally {
      setSaving(false);
    }
  };

  // 入侵检测 state
  const [invasionMaster, setInvasionMaster] = useState(true);
  const [intrusionRules, setIntrusionRules] = useState<IntrusionRule[]>(INITIAL_INTRUSION_RULES);
  const [wlProg, setWlProg] = useState<LabeledItem[]>(INITIAL_WL_PROG);
  const [wlFile, setWlFile] = useState<LabeledItem[]>(INITIAL_WL_FILE);
  const [wlIP, setWlIP] = useState<LabeledItem[]>(INITIAL_WL_IP);
  const [invasionSub, setInvasionSub] = useState<InvasionSubTab>('rules');

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
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/cat-isolate">环境隔离与安全增强</Link>
          <span>/</span>
          <span className="crumb-current">宿主加固</span>
        </div>

        {/* Hero */}
        <div className="panel">
          <div className="flex items-start justify-between gap-6 mb-5">
            <div className="hero-block flex-1">
              <div className="h-eyebrow">主机层加固 · 运行时异常行为检测</div>
              <h2 className="h-title">宿主加固中心</h2>
              <p className="h-subtitle">3 个运行时安全模块（主机防护 / 勒索防护 / 入侵检测）— 守护 ClawManager 所在宿主机安全。</p>
            </div>
          </div>
          <div className="grid grid-cols-4 gap-3">
            <div className="stat-card">
              <div className="stat-card-label">加固代理状态</div>
              <div className="stat-card-value tone-green">就绪</div>
              <div className="stat-card-sub muted-strong">连接正常 · 策略已下发</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">24h 主机防护告警</div>
              <div className="stat-card-value tone-red">5</div>
              <div className="stat-card-sub muted-strong">文件拦截 4 · 进程拦截 1</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">24h 勒索防护告警</div>
              <div className="stat-card-value tone-red">3</div>
              <div className="stat-card-sub muted-strong">诱饵触发 + 终止进程</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">24h 入侵检测告警</div>
              <div className="stat-card-value tone-red">3</div>
              <div className="stat-card-sub muted-strong">本地提权 2 · 反弹shell 1</div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="panel" style={{ paddingBottom: 0 }}>
          <div className="tabs">
            <button className={`tab${mainTab === 'file' ? ' tab-active' : ''}`} onClick={() => setMainTab('file')}>主机防护</button>
            <button className={`tab${mainTab === 'ransome' ? ' tab-active' : ''}`} onClick={() => setMainTab('ransome')}>勒索防护</button>
            <button className={`tab${mainTab === 'invasion' ? ' tab-active' : ''}`} onClick={() => setMainTab('invasion')}>入侵检测</button>
          </div>
        </div>

        {/* ===== 主机防护 ===== */}
        {mainTab === 'file' && (
          <div className="panel">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="eyebrow">主机防护 · 文件 + 进程 双轨</div>
                <h3 className="section-title-lg mt-1">关键文件与进程防护</h3>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs muted-strong">总开关</span>
                <Toggle on={fileMaster} onChange={(v) => { setFileMaster(v); fireToast('主机防护已切换', 'info'); }} />
                <button className="btn-primary btn-sm" onClick={() => fireToast('配置已保存', 'success')}>保存并应用</button>
              </div>
            </div>
            <div className="text-xs muted mb-4">
              保护系统关键文件、进程，防止被篡改和删除。支持文件级权限控制（读/写/执行/删除）+ 进程白名单/黑名单双重控制。
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
              <span className="text-xs muted-strong" style={{ whiteSpace: 'nowrap' }}>防御模式 ⓘ</span>
              <RadioBtn selected={defenseMode === 'block'} onClick={() => setDefenseMode('block')} label="拦截模式 · 命中即阻断" />
              <RadioBtn selected={defenseMode === 'monitor'} onClick={() => setDefenseMode('monitor')} label="监控模式 · 仅告警不阻断" />
            </div>

            {/* Sub-tabs */}
            <div className="flex gap-2 mb-4">
              <button className={`tab${fileSub === 'builtin' ? ' tab-active' : ''}`} onClick={() => setFileSub('builtin')}>
                内置规则 {builtinEnabled.filter(Boolean).length}/{BUILTIN_FILE_RULES.length}
              </button>
              <button className={`tab${fileSub === 'fileprot' ? ' tab-active' : ''}`} onClick={() => setFileSub('fileprot')}>
                文件防护 ({customFileRules.length})
              </button>
              <button className={`tab${fileSub === 'procprot' ? ' tab-active' : ''}`} onClick={() => setFileSub('procprot')}>
                进程防护 {procRules.filter((p) => p.type === '进程保护').length} | {procRules.filter((p) => p.type === '进程黑名单').length}
              </button>
            </div>

            {fileSub === 'builtin' && (
              <>
                <div className="text-xs muted mb-3">
                  {BUILTIN_FILE_RULES.length} 条出厂内置防护规则，覆盖 /etc/、/boot/、/var/log/audit/ 等关键路径。
                </div>
                <div style={{ maxHeight: 520, overflowY: 'auto', border: '1px solid #eadfd8', borderRadius: 10 }}>
                  <table className="tbl" style={{ margin: 0 }}>
                    <thead style={{ position: 'sticky', top: 0, background: '#fdfaf7', zIndex: 1 }}>
                      <tr>
                        <th>保护对象</th>
                        <th>说明</th>
                        <th style={{ width: 90 }}>类型</th>
                        <th style={{ width: 90 }}>状态</th>
                      </tr>
                    </thead>
                    <tbody>
                      {BUILTIN_FILE_RULES.map(([path, desc, type], i) => (
                        <tr key={path}>
                          <td><code className="text-sm font-mono text-[#171212]">{path}</code></td>
                          <td><span className="text-xs muted">{desc}</span></td>
                          <td><span className="badge badge-slate text-[10px]">{type}</span></td>
                          <td>
                            <Toggle
                              on={builtinEnabled[i]}
                              onChange={(v) => {
                                const next = [...builtinEnabled];
                                next[i] = v;
                                setBuiltinEnabled(next);
                                fireToast(`${path} 已切换`, 'info');
                              }}
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
                  <span className="text-xs muted">最多支持 20 条文件防护规则。每条可独立配置 读 / 写 / 执行 / 删除 四种权限。</span>
                  <button
                    className="btn-primary btn-sm"
                    disabled={customFileRules.length >= 20}
                    onClick={() =>
                      setModal({
                        kind: 'file-rule',
                        onConfirm: (rule) => {
                          setCustomFileRules([...customFileRules, rule]);
                          closeModal();
                          fireToast('已添加文件防护规则', 'success');
                        },
                      })
                    }
                  >
                    + 添加
                  </button>
                </div>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>保护文件/目录</th>
                      <th>信任进程</th>
                      <th style={{ width: 50, textAlign: 'center' }}>读</th>
                      <th style={{ width: 50, textAlign: 'center' }}>写</th>
                      <th style={{ width: 50, textAlign: 'center' }}>执行</th>
                      <th style={{ width: 50, textAlign: 'center' }}>删除</th>
                      <th style={{ width: 80 }}>操作</th>
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
                              setCustomFileRules(customFileRules.filter((_, idx) => idx !== i));
                              fireToast('已删除规则', 'success');
                            }}
                          >
                            删除
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
                <div className="text-xs muted mb-3">最多支持 20 条进程保护规则、20 条进程黑名单规则。</div>
                <div className="flex items-center justify-between mb-3">
                  <span className="font-semibold text-[#171212] text-sm">进程保护 / 黑名单</span>
                  <button
                    className="btn-primary btn-sm"
                    disabled={procRules.length >= 40}
                    onClick={() =>
                      setModal({
                        kind: 'proc-rule',
                        onConfirm: (rule) => {
                          setProcRules([...procRules, rule]);
                          closeModal();
                          fireToast('已添加进程防护规则', 'success');
                        },
                      })
                    }
                  >
                    + 添加
                  </button>
                </div>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>进程路径</th>
                      <th style={{ width: 130 }}>规则类型</th>
                      <th style={{ width: 100 }}>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {procRules.map((rule, i) => (
                      <tr key={i}>
                        <td><code className="text-sm font-mono text-[#171212]">{rule.path}</code></td>
                        <td>
                          <span className={`badge badge-${rule.type === '进程保护' ? 'red' : 'orange'}`}>
                            {rule.type}
                          </span>
                        </td>
                        <td>
                          <button
                            className="text-xs text-[#dc2626] font-semibold hover:underline"
                            onClick={() => {
                              setProcRules(procRules.filter((_, idx) => idx !== i));
                              fireToast('已删除规则', 'success');
                            }}
                          >
                            删除
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
                <h4 className="font-semibold text-[#171212] text-sm">主机防护日志</h4>
                <button className="btn-secondary btn-sm" onClick={() => fireToast('已刷新日志', 'info')}>刷新</button>
              </div>
              <table className="tbl">
                <thead>
                  <tr>
                    <th style={{ width: 140 }}>时间</th>
                    <th style={{ width: 120 }}>进程用户</th>
                    <th>进程</th>
                    <th>保护对象</th>
                    <th style={{ width: 80 }}>动作</th>
                    <th style={{ width: 100 }}>处理结果</th>
                  </tr>
                </thead>
                <tbody>
                  {FILE_PROT_LOG.map(([t, user, proc, obj, act, result], i) => {
                    const tone = result === '已阻断' ? 'red' : result === '放行' ? 'green' : 'slate';
                    return (
                      <tr key={i}>
                        <td><span className="text-xs muted-strong font-mono">{t}</span></td>
                        <td><span className="text-xs">{user}</span></td>
                        <td><code className="text-xs font-mono text-[#171212]">{proc}</code></td>
                        <td><code className="text-xs font-mono">{obj}</code></td>
                        <td><span className="badge badge-slate text-[10px]">{act}</span></td>
                        <td><span className={`badge badge-${tone}`}>{result}</span></td>
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
                <div className="eyebrow">勒索病毒防护 · 诱饵文件 + 行为分析</div>
                <h3 className="section-title-lg mt-1">勒索防护</h3>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs muted-strong">总开关</span>
                <Toggle on={ransomMaster} onChange={(v) => { setRansomMaster(v); }} />
                <button
                  className="btn-primary btn-sm"
                  disabled={policyDraft === null || saving}
                  onClick={() => { void saveRansomPolicy(); }}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  {saving && <Spinner />}
                  {saving ? '保存中…' : '保存并应用'}
                </button>
              </div>
            </div>
            <div className="text-xs muted mb-4">
              实时监测潜在的勒索病毒威胁，及时发现和阻止恶意软件的入侵。在系统关键位置投放诱饵文件，结合行为分析识别勒索家族。
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
              <span className="text-xs muted-strong" style={{ whiteSpace: 'nowrap' }}>终止可疑进程</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <RadioBtn selected={killProcess === true} onClick={() => setKillProcess(true)} label="是 · 命中后自动 kill" />
                <RadioBtn selected={killProcess === false} onClick={() => setKillProcess(false)} label="否 · 仅告警，由运维处置" />
              </div>
              <span className="text-xs muted ml-auto">⚠ 启用后将自动终止可疑进程，建议确认无误报后再开</span>
            </div>

            {/* Sub-tabs */}
            <div className="flex gap-2 mb-4">
              <button className={`tab${ransomSub === 'decoy' ? ' tab-active' : ''}`} onClick={() => setRansomSub('decoy')}>
                自定义诱饵目录 ({baits.length})
              </button>
              <button className={`tab${ransomSub === 'whitelist' ? ' tab-active' : ''}`} onClick={() => setRansomSub('whitelist')}>
                白名单程序 ({ransomWhite.length})
              </button>
            </div>

            {ransomSub === 'decoy' && (
              <>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs muted">默认在系统关键位置投放诱饵文件，并支持增加诱饵目录。最多支持 20 条自定义诱饵目录。</span>
                  <button
                    className="btn-primary btn-sm"
                    onClick={() =>
                      setModal({
                        kind: 'batch-path',
                        title: '添加自定义诱饵目录',
                        placeholder: '支持输入单条/多条目录，每行填写一条，最多支持 20 条目录',
                        onConfirm: (lines) => {
                          setBaits([...baits, ...lines].slice(0, 20));
                          closeModal();
                          fireToast('已添加诱饵目录', 'success');
                        },
                      })
                    }
                  >
                    + 添加
                  </button>
                </div>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>诱饵目录</th>
                      <th style={{ width: 120 }}>投放状态</th>
                      <th style={{ width: 100 }}>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {baits.map((p, i) => (
                      <tr key={i}>
                        <td><code className="text-sm font-mono text-[#171212]">{p}</code></td>
                        <td><span className="badge badge-green">已投放</span></td>
                        <td>
                          <button
                            className="text-xs text-[#dc2626] font-semibold hover:underline"
                            onClick={() => {
                              setBaits(baits.filter((_, idx) => idx !== i));
                              fireToast('已删除诱饵目录', 'success');
                            }}
                          >
                            删除
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
                  <span className="text-xs muted">白名单程序在触发诱饵时不会被判定为勒索行为（如备份程序）。最多支持 20 条。</span>
                  <button
                    className="btn-primary btn-sm"
                    onClick={() =>
                      setModal({
                        kind: 'batch-path',
                        title: '添加白名单程序路径',
                        placeholder: '支持输入单条/多条路径，每行填写一条，最多支持 20 条路径',
                        onConfirm: (lines) => {
                          setRansomWhite([...ransomWhite, ...lines].slice(0, 20));
                          closeModal();
                          fireToast('已添加白名单', 'success');
                        },
                      })
                    }
                  >
                    + 添加
                  </button>
                </div>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>程序路径</th>
                      <th style={{ width: 100 }}>操作</th>
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
                              fireToast('已删除白名单', 'success');
                            }}
                          >
                            删除
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
                <h4 className="font-semibold text-[#171212] text-sm">勒索防护日志</h4>
                <button className="btn-secondary btn-sm" onClick={() => fireToast('已刷新日志', 'info')}>刷新</button>
              </div>
              <table className="tbl">
                <thead>
                  <tr>
                    <th style={{ width: 140 }}>时间</th>
                    <th>进程</th>
                    <th style={{ width: 120 }}>进程用户</th>
                    <th style={{ width: 130 }}>终止进程</th>
                  </tr>
                </thead>
                <tbody>
                  {liveLogs.length === 0 && (
                    <tr>
                      <td colSpan={4} className="text-center py-6 text-xs muted">
                        暂无日志
                      </td>
                    </tr>
                  )}
                  {liveLogs.map((entry, i) => {
                    const act = entry.action ?? '-';
                    return (
                      <tr key={i}>
                        <td><span className="text-xs muted-strong font-mono">{entry.time ?? '-'}</span></td>
                        <td><code className="text-xs font-mono text-[#171212]">{entry.process ?? entry.path ?? entry.raw}</code></td>
                        <td><span className="text-xs">{entry.user ?? '-'}</span></td>
                        <td><span className={`badge badge-${act === '已终止' ? 'red' : 'orange'}`}>{act}</span></td>
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
                <div className="eyebrow">入侵检测 · ATT&amp;CK 框架</div>
                <h3 className="section-title-lg mt-1">主机入侵检测</h3>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs muted-strong">总开关</span>
                <Toggle on={invasionMaster} onChange={(v) => { setInvasionMaster(v); fireToast('入侵检测已切换', 'info'); }} />
                <button className="btn-primary btn-sm" onClick={() => fireToast('配置已保存', 'success')}>保存并应用</button>
              </div>
            </div>
            <div className="text-xs muted mb-4">
              基于 ATT&amp;CK 框架中的入侵模型，实时监控运行时基础事件并通过入侵引擎判决来识别入侵行为。
            </div>

            {/* Sub-tabs */}
            <div className="flex gap-2 mb-4">
              <button className={`tab${invasionSub === 'rules' ? ' tab-active' : ''}`} onClick={() => setInvasionSub('rules')}>
                检测规则 {intrusionRules.filter((r) => r.enabled).length}/{intrusionRules.length}
              </button>
              <button className={`tab${invasionSub === 'wl-prog' ? ' tab-active' : ''}`} onClick={() => setInvasionSub('wl-prog')}>
                白名单程序 ({wlProg.length})
              </button>
              <button className={`tab${invasionSub === 'wl-file' ? ' tab-active' : ''}`} onClick={() => setInvasionSub('wl-file')}>
                白名单文件 ({wlFile.length})
              </button>
              <button className={`tab${invasionSub === 'wl-ip' ? ' tab-active' : ''}`} onClick={() => setInvasionSub('wl-ip')}>
                白名单IP ({wlIP.length})
              </button>
            </div>

            {invasionSub === 'rules' && (
              <>
                <div className="text-xs muted mb-3">17 项内置检测规则，按 ATT&amp;CK 战术分类。可逐项启用/禁用。</div>
                <div className="space-y-2" style={{ maxHeight: 480, overflowY: 'auto', paddingRight: 6 }}>
                  {intrusionRules.map((r, i) => (
                    <div
                      key={i}
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
                      <span style={{ fontSize: 18, flexShrink: 0 }}>{r.icon}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="text-sm font-semibold text-[#171212]">{r.cat}</div>
                        <div className="text-xs muted mt-0.5">{r.desc}</div>
                      </div>
                      <Toggle
                        on={r.enabled}
                        onChange={(v) => {
                          const next = [...intrusionRules];
                          next[i] = { ...next[i], enabled: v };
                          setIntrusionRules(next);
                          fireToast(`${r.cat} 已切换`, 'info');
                        }}
                      />
                    </div>
                  ))}
                </div>
              </>
            )}

            {invasionSub === 'wl-prog' && (
              <WhitelistTable
                desc="白名单程序在触发规则时不会被判定为入侵行为。"
                items={wlProg}
                onAdd={() =>
                  setModal({
                    kind: 'batch-path',
                    title: '添加白名单程序',
                    placeholder: '支持输入单条/多条程序路径，每行填写一条，最多支持 20 条程序路径',
                    onConfirm: (lines) => {
                      setWlProg([...wlProg, ...lines.map((v) => ({ value: v, desc: '' }))].slice(0, 20));
                      closeModal();
                      fireToast('已添加白名单程序', 'success');
                    },
                  })
                }
                onDelete={(i) => {
                  setWlProg(wlProg.filter((_, idx) => idx !== i));
                  fireToast('已删除', 'success');
                }}
                col1="程序路径"
              />
            )}

            {invasionSub === 'wl-file' && (
              <WhitelistTable
                desc="白名单文件操作不会触发入侵告警。"
                items={wlFile}
                onAdd={() =>
                  setModal({
                    kind: 'batch-path',
                    title: '添加白名单文件',
                    placeholder: '支持输入单条/多条文件路径，每行填写一条，最多支持 20 条文件路径',
                    onConfirm: (lines) => {
                      setWlFile([...wlFile, ...lines.map((v) => ({ value: v, desc: '' }))].slice(0, 20));
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
                desc="来自白名单 IP 的访问不会被判定为入侵。"
                items={wlIP}
                onAdd={() =>
                  setModal({
                    kind: 'batch-path',
                    title: '添加白名单IP',
                    placeholder: '支持输入单条/多条IP地址，每行填写一条，最多支持 20 条IP地址',
                    onConfirm: (lines) => {
                      setWlIP([...wlIP, ...lines.map((v) => ({ value: v, desc: '' }))].slice(0, 20));
                      closeModal();
                      fireToast('已添加白名单IP', 'success');
                    },
                  })
                }
                onDelete={(i) => {
                  setWlIP(wlIP.filter((_, idx) => idx !== i));
                  fireToast('已删除', 'success');
                }}
                col1="IP / CIDR"
              />
            )}

            {/* 入侵检测日志 */}
            <div style={{ marginTop: 24 }}>
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-semibold text-[#171212] text-sm">入侵检测日志</h4>
                <button className="btn-secondary btn-sm" onClick={() => fireToast('已刷新日志', 'info')}>刷新</button>
              </div>
              <table className="tbl">
                <thead>
                  <tr>
                    <th style={{ width: 140 }}>时间</th>
                    <th style={{ width: 120 }}>类别</th>
                    <th>进程</th>
                    <th style={{ width: 120 }}>进程用户</th>
                    <th>描述</th>
                  </tr>
                </thead>
                <tbody>
                  {INTRUSION_LOG.map(([t, cat, proc, user, desc], i) => (
                    <tr key={i}>
                      <td><span className="text-xs muted-strong font-mono">{t}</span></td>
                      <td><span className="badge badge-red text-[10px]">{cat}</span></td>
                      <td><code className="text-xs font-mono text-[#171212]">{proc}</code></td>
                      <td><span className="text-xs">{user}</span></td>
                      <td><span className="text-xs muted">{desc}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

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
          <div className="eyebrow text-[10px] mb-1">信任进程 <span className="muted" title="支持目录形式">ⓘ</span></div>
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
          <div className="eyebrow text-[10px] mb-2">权限</div>
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
