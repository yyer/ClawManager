import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';
import ApplyDispatchButton from '../../../../components/secplane/ApplyDispatchButton';
import { useInstanceHealth } from './useInstanceHealth';
import { useSurfaceBackend } from './useSurfaceBackend';
import { FEATURES } from '../../../../config/features';

const SCENARIO_DEFENSES = ['defense.memoryGuard', 'defense.selfProtection'];

// 状态面防护 (scenario b) — 对齐 KSecForAIDemo/scenario-b-state.html
// 接 backend：defense.memoryGuard / defense.selfProtection toggles + 相关 alerts

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green' | 'slate';
type Mode = 'enforce' | 'observe' | 'off';
const ALERT_PREFIXES = ['defense.memoryGuard', 'defense.selfProtection', 'pp.'];

const PROTECTED_PATHS: Array<[string, string, string, Mode, number]> = [
  ['memory_store/', '智能体长期记忆存储', 'memory_store/**/*', 'enforce', 18],
  ['MEMORY.md', '智能体记忆 markdown', '**/MEMORY.md', 'enforce', 8],
  ['SOUL.md', '智能体人格设定', '**/SOUL.md', 'enforce', 6],
  ['memory/', '记忆目录通配', '**/memory/**', 'enforce', 6],
];

const INTEGRITY_EVENTS: Array<[string, string, string, string, Tone, string]> = [
  ['openclaw-prod-east-12', 'memory_store/long_term.json', '严重', '2m', 'red', '注入正则命中'],
  ['openclaw-finance-svc', 'MEMORY.md', '高', '5m', 'orange', 'Hash 漂移'],
  ['openclaw-mcp-router', 'SOUL.md', '严重', '12m', 'red', '注入正则 + Hash 漂移'],
  ['openclaw-staging-7', 'memory_store/new-session.md', '中', '25m', 'amber', '新文件创建'],
  ['openclaw-dev-test-1', 'memory_store/long_term.json', '提示', '1h', 'slate', 'chokidar 降级'],
];

const PATH_OPTIONS = ['memory_store/', 'MEMORY.md', 'SOUL.md', 'memory/'];

const StateSurfacePage: React.FC = () => {
  const { rules, alerts, dispatching, dispatchMsg, modeOf, setMode, dispatchApply } = useSurfaceBackend(ALERT_PREFIXES);
  const { instances, healthy } = useInstanceHealth();
  const enabledDefenseCount = rules.filter((r) => SCENARIO_DEFENSES.includes(r.rule_id) && r.is_enabled).length;
  // 显示给前端的 mode：以 memoryGuard 作为本场景的代表（用户切换会同步 memoryGuard + selfProtection 双开关）
  const mode = modeOf('defense.memoryGuard', 'enforce');
  const handleModeChange = (next: Mode) => {
    setMode('defense.memoryGuard', next);
    setMode('defense.selfProtection', next);
  };

  const [pathFilter, setPathFilter] = useState<string>('all');
  const [actionFilter, setActionFilter] = useState<'all' | 'block' | 'observe' | 'redact'>('all');
  const [query, setQuery] = useState('');

  const q = query.trim().toLowerCase();
  const filteredAlerts = alerts.filter((a) => {
    if (actionFilter !== 'all' && a.action !== actionFilter) return false;
    if (pathFilter !== 'all' && !a.subject?.includes(pathFilter)) return false;
    if (!q) return true;
    return [a.agent_id, a.subject, a.rule_id, a.rule_name, a.evidence]
      .some((v) => v?.toLowerCase().includes(q));
  });

  const exportJsonl = () => {
    const text = filteredAlerts.map((a) => JSON.stringify(a)).join('\n');
    const blob = new Blob([text], { type: 'application/jsonl' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `state-surface-alerts-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.jsonl`;
    link.click();
    URL.revokeObjectURL(url);
  };
  return (
    <AdminLayout title="安全防护">
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/runtime">智能体运行时安全</Link>
          <span>/</span>
          <span className="crumb-current">状态面防护</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">记忆污染与会话隔离</div>
            <h2 className="h-title">状态面防护</h2>
            <p className="h-subtitle">拦截智能体对持久化记忆的可疑/超大写入，周期性 Hash 校验，K8s PVC 实例物理隔离。</p>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="stat-card">
              <div className="stat-card-label">防御开关</div>
              <div className={`stat-card-value ${enabledDefenseCount === SCENARIO_DEFENSES.length ? 'tone-green' : 'tone-orange'}`}>{enabledDefenseCount}/{SCENARIO_DEFENSES.length}</div>
              <div className="stat-card-sub muted-strong">memoryGuard · selfProtection</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">近期告警</div>
              <div className={`stat-card-value ${alerts.length > 0 ? 'tone-red' : 'tone-green'}`}>{alerts.length}</div>
              <div className="stat-card-sub muted-strong">最近 50 条 · aegis 来源</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">在管实例</div>
              <div className="stat-card-value">{instances.length}</div>
              <div className="stat-card-sub muted-strong">{healthy.length} running</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">下发通道</div>
              <div className="stat-card-value" style={{ fontSize: '1rem' }}>install_skill</div>
              <div className="stat-card-sub muted-strong">hot-reload via mtime</div>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="flex items-center justify-between mb-4 gap-4">
            <div>
              <div className="eyebrow">记忆污染守卫 · 受保护路径</div>
              <h3 className="section-title-lg mt-1">4 类敏感路径写入拦截</h3>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs muted-strong">防御模式</span>
              <div className="mode-selector">
                <button className={mode === 'enforce' ? 'active-enforce' : ''} onClick={() => handleModeChange('enforce')}>
                  拦截
                </button>
                <button className={mode === 'observe' ? 'active-observe' : ''} onClick={() => handleModeChange('observe')}>
                  监控
                </button>
                <button className={mode === 'off' ? 'active-off' : ''} onClick={() => handleModeChange('off')}>
                  停止
                </button>
              </div>
              <ApplyDispatchButton onDispatch={dispatchApply} busy={dispatching} className="btn-primary btn-sm" triggerLabel="保存并应用" />
              {dispatchMsg && <span className="text-xs muted ml-2">{dispatchMsg}</span>}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            {PROTECTED_PATHS.map(([path, desc, pattern, , hits]) => (
              <div key={path} className="p-4 rounded-2xl border border-[#eadfd8] bg-[#fffaf7]">
                <div className="flex items-start justify-between mb-2">
                  <code className="text-sm font-bold text-[#171212]">{path}</code>
                  <span className="badge badge-slate">共用模式</span>
                </div>
                <div className="text-xs muted mb-2">{desc}</div>
                <code className="block text-xs muted-strong bg-white px-2 py-1 rounded">{pattern}</code>
                <div className="divider" />
                <div className="flex items-center justify-between">
                  <span className="text-xs muted-strong">24h 拦截</span>
                  <span className="text-lg font-bold tone-red">{hits}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {FEATURES.memoryIntegrityCheck && <div className="panel">
          <div className="mb-4">
            <div className="eyebrow">记忆完整性校验</div>
            <h3 className="section-title-lg mt-1">记忆完整性监控</h3>
          </div>
          <div className="alert alert-warning mb-3">
            <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            检测到 5 个监听事件 · 2 严重 / 1 高 / 1 中 / 1 提示
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th>实例</th>
                <th>文件</th>
                <th>状态</th>
                <th>检查时间</th>
              </tr>
            </thead>
            <tbody>
              {INTEGRITY_EVENTS.map(([inst, file, sev, time, tone, trigger]) => (
                <tr key={inst + file}>
                  <td><span className="font-mono text-xs">{inst}</span></td>
                  <td><code className="text-xs">{file}</code></td>
                  <td>
                    <span className={`badge badge-${tone}`}>{sev}</span>{' '}
                    <span className="text-xs muted ml-1">{trigger}</span>
                  </td>
                  <td><span className="text-xs muted-strong">{time}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>}

        <div className="panel">
          <div className="flex items-center justify-between mb-4 gap-4 flex-wrap">
            <div>
              <div className="eyebrow">最近记忆写入拦截</div>
              <h3 className="section-title-lg mt-1">防护日志 · 24h 拦截事件</h3>
            </div>
            <div className="flex gap-2 items-center flex-wrap">
              <select
                className="input"
                style={{ width: 150 }}
                value={pathFilter}
                onChange={(e) => setPathFilter(e.target.value)}
              >
                <option value="all">全部路径</option>
                {PATH_OPTIONS.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
              <select
                className="input"
                style={{ width: 140 }}
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value as typeof actionFilter)}
              >
                <option value="all">全部动作</option>
                <option value="block">拦截 (block)</option>
                <option value="observe">监控 (observe)</option>
                <option value="redact">脱敏 (redact)</option>
              </select>
              <input
                className="input"
                style={{ width: 200 }}
                placeholder="🔍 实例 / 规则 / 路径…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <button
                className="btn-secondary btn-sm"
                onClick={exportJsonl}
                disabled={filteredAlerts.length === 0}
              >
                导出 JSONL
              </button>
            </div>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 80 }}>时间</th>
                <th>实例</th>
                <th>命中路径 / 主体</th>
                <th style={{ width: 140 }}>规则</th>
                <th>触发理由 / 证据</th>
                <th style={{ width: 80 }}>动作</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.length === 0 && (
                <tr>
                  <td colSpan={6} className="text-xs muted" style={{ textAlign: 'center', padding: 20 }}>
                    {alerts.length === 0 ? '暂无拦截事件' : '当前过滤条件无匹配事件'}
                  </td>
                </tr>
              )}
              {filteredAlerts.slice(0, 50).map((a) => (
                <tr key={a.id}>
                  <td><span className="muted-strong text-xs">{a.ts?.replace('T', ' ').slice(0, 19) ?? '—'}</span></td>
                  <td><span className="font-mono text-xs">{a.agent_id ?? '—'}</span></td>
                  <td><code className="text-xs">{a.subject ?? '—'}</code></td>
                  <td><code className="text-xs text-[#7a4a30]">{a.rule_id ?? '—'}</code></td>
                  <td><span className="text-xs muted">{a.evidence ?? a.rule_name ?? '—'}</span></td>
                  <td>
                    <span className={`badge badge-${a.action === 'block' ? 'red' : a.action === 'redact' ? 'orange' : 'slate'}`}>
                      {a.action}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="text-xs muted mt-3 text-center">
            共 {alerts.length} 条 · 过滤后 {filteredAlerts.length} · 表中最多展示 50 行
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default StateSurfacePage;
