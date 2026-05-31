import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../components/AdminLayout';
import {
  secplaneService,
  type SecplaneAlert,
  type AlertSource,
  type Severity,
} from '../../../services/secplaneService';

const SOURCE_OPTIONS: { value: AlertSource | ''; label: string }[] = [
  { value: '', label: '全部来源' },
  { value: 'aegis', label: 'aegis' },
  { value: 'secureclaw', label: 'secureclaw' },
  { value: 'gateway', label: 'gateway' },
  { value: 'platform', label: 'platform' },
  { value: 'ksecure', label: 'ksecure' },
  { value: 'kubearmor', label: 'kubearmor' },
];

const SEVERITY_OPTIONS: { value: Severity | ''; label: string }[] = [
  { value: '', label: '全部严重度' },
  { value: 'high', label: '高 (high)' },
  { value: 'medium', label: '中 (medium)' },
  { value: 'low', label: '低 (low)' },
];

const sourceBadgeTone = (src: string): string => {
  switch (src) {
    case 'aegis': return 'badge-red';
    case 'secureclaw': return 'badge-purple';
    case 'gateway': return 'badge-blue';
    case 'platform': return 'badge-slate';
    case 'ksecure': return 'badge-teal';
    case 'kubearmor': return 'badge-amber';
    default: return 'badge-slate';
  }
};

const severityTone = (sev: string): string => {
  switch (sev) {
    case 'high': return 'badge-red';
    case 'medium': return 'badge-orange';
    case 'low': return 'badge-slate';
    default: return 'badge-slate';
  }
};

const actionTone = (action: string): string => {
  const a = action?.toLowerCase();
  if (a === 'block') return 'badge-red';
  if (a === 'redact') return 'badge-orange';
  if (a === 'observe') return 'badge-slate';
  return 'badge-slate';
};

// 快速过滤芯片：每个对应一组预设过滤条件 (内部 state 修改)
const QUICK_CHIPS: Array<{ label: string; apply: { source?: string; action?: string; severity?: string; rule_id?: string } }> = [
  { label: '仅 BLOCK', apply: { action: 'block' } },
  { label: '今日高危', apply: { severity: 'high' } },
  { label: 'jailbreak 类', apply: { rule_id: 'jailbreak' } },
  { label: '出站拦截', apply: { rule_id: 'outbound' } },
  { label: '主机异常', apply: { source: 'ksecure' } },
];

// 防护场景过滤 — rule_id 前缀映射
const SCENE_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: '全部场景' },
  { value: 'defense.userRiskScan', label: '输入面' },
  { value: 'defense.memoryGuard', label: '状态面' },
  { value: 'defense.commandBlock', label: '决策面' },
  { value: 'defense.outputRedaction', label: '输出面' },
  { value: 'pp.', label: '资产防篡改' },
  { value: 'output_redaction', label: '脱敏告警' },
];

const ACTION_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: '全部动作' },
  { value: 'block', label: 'BLOCK' },
  { value: 'redact', label: 'REDACT' },
  { value: 'observe', label: 'OBSERVE' },
  { value: 'approval', label: 'APPROVAL' },
  { value: 'warn', label: 'WARN' },
];

const SecurityEventsPage: React.FC = () => {
  const [items, setItems] = useState<SecplaneAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [source, setSource] = useState<AlertSource | ''>('');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [ruleIdFilter, setRuleIdFilter] = useState('');
  const [keyword, setKeyword] = useState('');
  const [scene, setScene] = useState('');
  const [actionFilter, setActionFilter] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: { source?: AlertSource; severity?: Severity; rule_id?: string; limit?: number } = { limit: 200 };
      if (source) params.source = source;
      if (severity) params.severity = severity;
      if (ruleIdFilter.trim()) params.rule_id = ruleIdFilter.trim();
      const data = await secplaneService.listAlerts(params);
      setItems(data);
    } catch {
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [source, severity, ruleIdFilter]);

  useEffect(() => {
    load();
  }, [load]);

  const filtered = useMemo(() => {
    let list = items;
    // 场景前缀过滤
    if (scene) {
      list = list.filter((a) => a.rule_id?.startsWith(scene));
    }
    // 动作前缀过滤
    if (actionFilter) {
      list = list.filter((a) => a.action?.toLowerCase() === actionFilter);
    }
    // 关键字
    if (keyword.trim()) {
      const k = keyword.trim().toLowerCase();
      list = list.filter((a) =>
        [a.rule_id, a.rule_name, a.subject, a.evidence, a.trace_id, a.agent_id]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(k))
      );
    }
    return list;
  }, [items, scene, actionFilter, keyword]);

  const counts = useMemo(() => {
    let blocks = 0, redacts = 0, observes = 0;
    for (const a of items) {
      const ac = a.action?.toLowerCase();
      if (ac === 'block') blocks += 1;
      else if (ac === 'redact') redacts += 1;
      else if (ac === 'observe') observes += 1;
    }
    return { total: items.length, blocks, redacts, observes };
  }, [items]);

  const applyChip = (apply: typeof QUICK_CHIPS[number]['apply']) => {
    if (apply.source) setSource(apply.source as AlertSource);
    if (apply.severity) setSeverity(apply.severity as Severity);
    if (apply.action) setActionFilter(apply.action);
    if (apply.rule_id) setRuleIdFilter(apply.rule_id);
  };

  const resetFilters = () => {
    setSource('');
    setSeverity('');
    setRuleIdFilter('');
    setScene('');
    setActionFilter('');
    setKeyword('');
  };

  return (
    <AdminLayout title="安全防护">
      <div className="secp-scope space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <span className="crumb-current">事件日志</span>
        </div>

        <div className="panel">
          <div className="flex items-start justify-between gap-6 mb-5">
            <div className="hero-block flex-1">
              <div className="h-eyebrow">SECURITY EVENTS · 跨场景事件流</div>
              <h2 className="h-title">事件日志</h2>
              <p className="h-subtitle">
                来自 ClawAegisEx（运行时）、SecureClaw（审计加固）、KSecure（主机层）的告警事件。
                支持按来源、严重度、规则 ID 多维筛选；关键字搜索 trace_id / 主体 / 证据片段。
              </p>
            </div>
            <button type="button" className="btn-secondary btn-sm" onClick={load} disabled={loading}>
              {loading ? '刷新中…' : '刷新'}
            </button>
          </div>
          <div className="grid grid-cols-4 gap-3">
            <div className="stat-card">
              <div className="stat-card-label">事件总数</div>
              <div className="stat-card-value">{counts.total}</div>
              <div className="stat-card-sub muted-strong">当前筛选下</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">已拦截</div>
              <div className="stat-card-value tone-red">{counts.blocks}</div>
              <div className="stat-card-sub muted-strong">action=block</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">已脱敏</div>
              <div className="stat-card-value tone-orange">{counts.redacts}</div>
              <div className="stat-card-sub muted-strong">action=redact</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">观察记录</div>
              <div className="stat-card-value tone-slate">{counts.observes}</div>
              <div className="stat-card-sub muted-strong">action=observe</div>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="eyebrow">快速筛选</div>
              <h3 className="section-title-lg mt-1">事件搜索 + 多维过滤</h3>
            </div>
            <div className="text-xs muted-strong">
              共 {items.length} 条 · 筛选后 {filtered.length}
              <span className="dot bg-green-500 ml-2" />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3 mb-3">
            <input
              type="text"
              className="input"
              placeholder="🔍 搜索 trace_id / 主体 / 证据"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
            />
            <select className="input" value={source} onChange={(e) => setSource(e.target.value as AlertSource | '')}>
              {SOURCE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
            <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value as Severity | '')}>
              {SEVERITY_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-3 gap-3 mb-3">
            <select className="input" value={scene} onChange={(e) => setScene(e.target.value)}>
              {SCENE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
            <select className="input" value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
              {ACTION_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
            <input
              type="text"
              className="input"
              placeholder="规则 ID 精确过滤（如 defense.userRiskScan）"
              value={ruleIdFilter}
              onChange={(e) => setRuleIdFilter(e.target.value)}
            />
          </div>
          <div className="flex items-center justify-between mb-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs muted">快速过滤：</span>
              {QUICK_CHIPS.map((c) => (
                <button key={c.label} type="button" className="tag" onClick={() => applyChip(c.apply)}>
                  {c.label}
                </button>
              ))}
            </div>
            <button type="button" className="btn-secondary btn-sm" onClick={resetFilters}>
              ✗ 清除筛选
            </button>
          </div>

          {loading ? (
            <div className="muted text-sm py-6 text-center">加载中…</div>
          ) : filtered.length === 0 ? (
            <div className="muted text-sm py-6 text-center">无匹配事件。</div>
          ) : (
            <table className="tbl">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>来源</th>
                  <th>规则</th>
                  <th>主体</th>
                  <th>证据预览</th>
                  <th>Trace</th>
                  <th>严重度</th>
                  <th>动作</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => (
                  <tr key={a.id}>
                    <td className="muted text-xs whitespace-nowrap">{a.ts}</td>
                    <td><span className={`badge ${sourceBadgeTone(a.source)}`}>{a.source}</span></td>
                    <td>
                      <div className="text-sm">{a.rule_name || a.rule_id || '—'}</div>
                      {a.rule_id && a.rule_name && (
                        <div className="muted text-xs font-mono">{a.rule_id}</div>
                      )}
                    </td>
                    <td className="text-xs">{a.subject || a.agent_id || '—'}</td>
                    <td className="muted text-xs" style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.evidence || '—'}
                    </td>
                    <td className="muted-strong text-xs font-mono">{a.trace_id ? a.trace_id.slice(0, 12) : '—'}</td>
                    <td><span className={`badge ${severityTone(a.severity)}`}>{a.severity}</span></td>
                    <td><span className={`badge ${actionTone(a.action)}`}>{a.action}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </AdminLayout>
  );
};

export default SecurityEventsPage;
