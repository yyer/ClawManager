import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';
import ApplyDispatchButton from '../../../../components/secplane/ApplyDispatchButton';
import { useInstanceHealth } from './useInstanceHealth';
import { useSurfaceBackend } from './useSurfaceBackend';

const SCENARIO_DEFENSES = [
  'defense.commandBlock',
  'defense.loopGuard',
  'defense.encodingGuard',
  'defense.scriptProvenanceGuard',
  'defense.exfiltrationGuard',
];

// 决策面防护 (scenario c) — 对齐 KSecForAIDemo/scenario-c-decision.html
// 接 backend：5 项 defense_toggle (commandBlock/loopGuard/encodingGuard/scriptProvenanceGuard/exfiltrationGuard)
// + dispatchAegisApply + alerts 实时事件流

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green' | 'slate';

// 5 项危险类目 ←→ defense_toggle rule_id 映射
const DANGER_CATEGORIES: Array<[string, string, string, string, Tone]> = [
  ['defense.commandBlock',          'shell 高危',         'commandBlockEnabled',          'rm -rf / dd / mkfs / fork bomb',          'red'],
  ['defense.loopGuard',             '循环写入',           'loopGuardEnabled',             '同一可变工具高频重试 / 限额内反复 mutating', 'red'],
  ['defense.encodingGuard',         '编码混淆',           'encodingGuardEnabled',         'base64 / hex / Unicode 转义绕过',         'red'],
  ['defense.scriptProvenanceGuard', 'Write-then-Execute', 'scriptProvenanceGuardEnabled', 'curl|bash / wget|sh / 链式调用',          'red'],
  ['defense.exfiltrationGuard',     'SSRF / 外渗',        'exfiltrationGuardEnabled',     '内网扫描 / 反向 shell / DNS 隧道',         'red'],
];

const ALERT_PREFIXES = [
  'defense.commandBlock',
  'defense.loopGuard',
  'defense.encodingGuard',
  'defense.scriptProvenanceGuard',
  'defense.exfiltrationGuard',
];

const DecisionSurfacePage: React.FC = () => {
  const { rules, alerts, dispatching, dispatchMsg, modeOf, setMode: setRuleMode, dispatchApply } = useSurfaceBackend(ALERT_PREFIXES);
  const { instances, healthy } = useInstanceHealth();
  const enabledDefenseCount = rules.filter((r) => SCENARIO_DEFENSES.includes(r.rule_id) && r.is_enabled).length;
  const [actionFilter, setActionFilter] = useState<'all' | 'block' | 'observe' | 'redact'>('all');
  const [query, setQuery] = useState('');

  const q = query.trim().toLowerCase();
  const filteredAlerts = alerts.filter((a) => {
    if (actionFilter !== 'all' && a.action !== actionFilter) return false;
    if (!q) return true;
    return [a.agent_id, a.rule_id, a.rule_name, a.subject, a.evidence]
      .some((v) => v?.toLowerCase().includes(q));
  });

  return (
    <AdminLayout title="安全防护">
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/runtime">智能体运行时安全</Link>
          <span>/</span>
          <span className="crumb-current">决策面防护</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">危险工具调用管控</div>
            <h2 className="h-title">决策面防护</h2>
            <p className="h-subtitle">智能体工具调用执行前的静态扫描与决策对齐。命中高危模式或意图模糊触发二次确认或人工审批。</p>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="stat-card">
              <div className="stat-card-label">防御开关</div>
              <div className={`stat-card-value ${enabledDefenseCount === SCENARIO_DEFENSES.length ? 'tone-green' : 'tone-orange'}`}>{enabledDefenseCount}/{SCENARIO_DEFENSES.length}</div>
              <div className="stat-card-sub muted-strong">5 类危险工具调用</div>
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
              <div className="eyebrow">工具调用三态防护 · 5 项独立配置</div>
              <h3 className="section-title-lg mt-1">工具调用防护配置</h3>
            </div>
            <ApplyDispatchButton onDispatch={dispatchApply} busy={dispatching} className="btn-primary btn-sm" triggerLabel="保存并应用" />
            {dispatchMsg && <span className="text-xs muted ml-2">{dispatchMsg}</span>}
          </div>
          <div className="space-y-2.5">
            {DANGER_CATEGORIES.map(([ruleId, name, flag, desc, tone]) => {
              const curMode = modeOf(ruleId, 'enforce');
              const hitCount = alerts.filter((a) => a.rule_id?.startsWith(ruleId)).length;
              return (
                <div key={ruleId} className="flex items-center gap-4 p-4 rounded-2xl border border-[#eadfd8] bg-white">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="font-semibold text-[#171212]">{name}</span>
                      <code className="text-[10px] muted-strong tracking-wider">{flag}</code>
                      <code className="text-[10px] text-[#7a4a30] bg-[#fdf6f1] px-1.5 py-0.5 rounded">before_tool_call</code>
                    </div>
                    <div className="text-xs muted">{desc}</div>
                  </div>
                  <div className="shrink-0">
                    <div className="mode-selector">
                      <button className={curMode === 'enforce' ? 'active-enforce' : ''} onClick={() => setRuleMode(ruleId, 'enforce')}>拦截</button>
                      <button className={curMode === 'observe' ? 'active-observe' : ''} onClick={() => setRuleMode(ruleId, 'observe')}>监控</button>
                      <button className={curMode === 'off' ? 'active-off' : ''} onClick={() => setRuleMode(ruleId, 'off')}>停止</button>
                    </div>
                  </div>
                  <div className="text-right shrink-0" style={{ minWidth: 80 }}>
                    <div className={`text-lg font-bold leading-none ${hitCount > 0 ? `tone-${tone}` : 'muted-strong'}`}>{hitCount}</div>
                    <div className="text-xs muted-strong mt-0.5">近期命中</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="eyebrow">最近工具调用决策</div>
              <h3 className="section-title-lg mt-1">工具调用防护日志</h3>
            </div>
            <div className="flex gap-2 items-center">
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
                style={{ width: 240 }}
                placeholder="🔍 实例 / 规则 / 命令…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 80 }}>时间</th>
                <th>实例</th>
                <th>规则</th>
                <th>命令 / 证据</th>
                <th>命中模式</th>
                <th style={{ width: 80 }}>严重度</th>
                <th style={{ width: 80 }}>动作</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-xs muted" style={{ textAlign: 'center', padding: 20 }}>
                    {alerts.length === 0 ? '暂无防护事件' : '当前过滤条件无匹配事件'}
                  </td>
                </tr>
              )}
              {filteredAlerts.slice(0, 50).map((a) => (
                <tr key={a.id}>
                  <td><span className="muted-strong text-xs">{a.ts?.replace('T', ' ').slice(11, 19)}</span></td>
                  <td><span className="font-mono text-xs">{a.agent_id ?? '—'}</span></td>
                  <td><code className="text-xs">{a.rule_id?.split('.')[1] ?? a.rule_id ?? '—'}</code></td>
                  <td><code className="text-xs text-[#171212] truncate inline-block" style={{ maxWidth: 320 }}>{a.subject ?? a.evidence?.slice(0, 80) ?? '—'}</code></td>
                  <td><span className="text-xs">{a.rule_name ?? '—'}</span></td>
                  <td><span className={`badge ${a.severity === 'high' ? 'badge-red' : a.severity === 'medium' ? 'badge-orange' : 'badge-slate'}`}>{a.severity}</span></td>
                  <td><span className={`badge badge-${a.action === 'block' ? 'red' : a.action === 'observe' ? 'orange' : 'slate'}`}>{a.action}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </AdminLayout>
  );
};

export default DecisionSurfacePage;
