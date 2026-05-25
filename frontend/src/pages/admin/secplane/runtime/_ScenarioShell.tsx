import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  secplaneService,
  type SecplaneRule,
  type SecplaneAlert,
  type DispatchResult,
  type RuleMode,
} from '../../../../services/secplaneService';
import RuleDetailModal, { type RuleModalData } from './RuleDetailModal';
import DispatchResultBanner from './DispatchResultBanner';
import InstanceHealthPanel from './InstanceHealthPanel';
import { useInstanceHealth } from './useInstanceHealth';

// Shared scaffold for the runtime scenario pages. Renders crumb + hero +
// defense toggles + (optional) extras + (optional) per-scenario alert stream
// + apply button. Each scenario page declares its defenses and which rule_id
// prefixes it wants to surface alerts for; this component handles loading,
// toggling, mode-switching, dispatching, and filtering.

export interface ScenarioDefense {
  ruleId: string;                  // e.g. "defense.memoryGuard"
  name: string;                    // human label
  hook?: string;                   // optional hook tag
  desc?: string;
  supportsMode: boolean;           // 8 of the 14 defenses have enforce/observe/off
  // Optional rule-library reference data — when present, a "查看规则" button
  // is rendered on the defense card and clicking it opens RuleDetailModal.
  ruleModalData?: RuleModalData;
}

export interface ScenarioMeta {
  letter: string;
  eyebrow: string;
  title: string;
  subtitle: string;
  defenses: ScenarioDefense[];
  // Which rule_id prefixes to surface in the per-scenario alerts table.
  // e.g. ['defense.memoryGuard', 'pp.'] — matches alerts whose rule_id
  // starts with any of these. If omitted, no alerts panel is rendered.
  alertRuleIdPrefixes?: string[];
  // Optional extra panels (e.g. protected resource lists) rendered between
  // the toggles and the alerts table.
  extras?: React.ReactNode;
}

const MODES: RuleMode[] = ['enforce', 'observe', 'off'];

const actionTone = (action: string): string => {
  const a = action?.toLowerCase();
  if (a === 'block') return 'badge-red';
  if (a === 'redact') return 'badge-orange';
  if (a === 'observe') return 'badge-slate';
  return 'badge-slate';
};

const severityTone = (sev: string): string => {
  switch (sev) {
    case 'high': return 'badge-red';
    case 'medium': return 'badge-orange';
    case 'low': return 'badge-slate';
    default: return 'badge-slate';
  }
};

export const ScenarioShell: React.FC<{ meta: ScenarioMeta }> = ({ meta }) => {
  const [rules, setRules] = useState<SecplaneRule[]>([]);
  const [alerts, setAlerts] = useState<SecplaneAlert[]>([]);
  const [busy, setBusy] = useState(false);
  const [dispatchResult, setDispatchResult] = useState<DispatchResult | null>(null);
  const [dispatchError, setDispatchError] = useState<string | null>(null);
  const [openRuleModalFor, setOpenRuleModalFor] = useState<string | null>(null);
  const [confirmNeeded, setConfirmNeeded] = useState(false);
  const instanceHealth = useInstanceHealth();

  const wantsAlerts = !!(meta.alertRuleIdPrefixes && meta.alertRuleIdPrefixes.length);

  const loadAll = useCallback(async () => {
    try {
      const promises: [Promise<SecplaneRule[]>, Promise<SecplaneAlert[]>?] = [
        secplaneService.listRules('defense_toggle'),
      ];
      if (wantsAlerts) {
        promises[1] = secplaneService.listAlerts({ source: 'aegis', limit: 50 });
      }
      const [ruleItems, alertItems] = await Promise.all(promises);
      setRules(ruleItems);
      if (alertItems) setAlerts(alertItems);
    } catch {
      // tolerate; user can retry
    }
  }, [wantsAlerts]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const ruleByDefense = useMemo(() => {
    const map: Record<string, SecplaneRule> = {};
    for (const r of rules) {
      if (r.rule_id?.startsWith('defense.')) map[r.rule_id] = r;
    }
    return map;
  }, [rules]);

  const filteredAlerts = useMemo(() => {
    if (!wantsAlerts) return [];
    const prefixes = meta.alertRuleIdPrefixes ?? [];
    return alerts.filter((a) => {
      const rid = a.rule_id ?? '';
      return prefixes.some((p) => rid === p || rid.startsWith(p));
    });
  }, [alerts, meta.alertRuleIdPrefixes, wantsAlerts]);

  const updateRule = async (next: SecplaneRule) => {
    setBusy(true);
    try {
      const saved = await secplaneService.saveRule(next);
      setRules((prev) => prev.map((x) => (x.rule_id === saved.rule_id ? saved : x)));
    } catch {
      loadAll();
    } finally {
      setBusy(false);
    }
  };

  const handleToggle = (def: ScenarioDefense) => {
    const r = ruleByDefense[def.ruleId];
    if (!r) return;
    updateRule({ ...r, is_enabled: !r.is_enabled });
  };

  const handleMode = (def: ScenarioDefense, mode: RuleMode) => {
    const r = ruleByDefense[def.ruleId];
    if (!r) return;
    updateRule({ ...r, mode, is_enabled: mode !== 'off' });
  };

  const doApply = async () => {
    setBusy(true);
    setDispatchError(null);
    setDispatchResult(null);
    setConfirmNeeded(false);
    try {
      const res = await secplaneService.dispatchAegisApply();
      setDispatchResult(res);
      if (wantsAlerts) {
        const fresh = await secplaneService.listAlerts({ source: 'aegis', limit: 50 });
        setAlerts(fresh);
      }
    } catch (err) {
      setDispatchError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleApply = () => {
    // Two-step confirm when any target instance is unhealthy. Skip the check
    // if the instance list failed to load (don't block the user on a flaky
    // /admin/instances response).
    if (
      !confirmNeeded &&
      !instanceHealth.loading &&
      !instanceHealth.error &&
      instanceHealth.unhealthy.length > 0
    ) {
      setConfirmNeeded(true);
      return;
    }
    doApply();
  };

  const enabledCount = meta.defenses.filter((d) => ruleByDefense[d.ruleId]?.is_enabled).length;

  return (
    <div className="secp-scope space-y-6">
      <div className="crumb">
        <Link to="/admin/secplane">安全防护</Link>
        <span>/</span>
        <Link to="/admin/secplane/runtime">智能体运行时安全</Link>
        <span>/</span>
        <span className="crumb-current">{meta.title}</span>
      </div>

      <div className="panel">
        <div className="flex items-start justify-between gap-6 mb-5">
          <div className="hero-block flex-1">
            <div className="h-eyebrow">{meta.eyebrow}</div>
            <h2 className="h-title">{meta.title}</h2>
            <p className="h-subtitle">{meta.subtitle}</p>
          </div>
          <div className="flex flex-col items-end gap-2">
            <button
              type="button"
              className={confirmNeeded ? 'btn-danger' : 'btn-primary'}
              onClick={handleApply}
              disabled={busy}
            >
              {busy
                ? '下发中…'
                : confirmNeeded
                  ? `确认下发（含 ${instanceHealth.unhealthy.length} 个不健康实例）`
                  : '应用到所有实例'}
            </button>
            {confirmNeeded && (
              <button
                type="button"
                className="btn-secondary btn-sm"
                onClick={() => setConfirmNeeded(false)}
                disabled={busy}
              >
                取消
              </button>
            )}
            {!confirmNeeded && (
              <button type="button" className="btn-secondary btn-sm" onClick={loadAll} disabled={busy}>
                刷新
              </button>
            )}
          </div>
        </div>
        <div className="grid grid-cols-4 gap-3">
          <div className="stat-card">
            <div className="stat-card-label">防御项</div>
            <div className="stat-card-value">{meta.defenses.length}</div>
            <div className="stat-card-sub muted-strong">已映射至 ClawAegis</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">已启用</div>
            <div className="stat-card-value tone-green">{enabledCount}</div>
            <div className="stat-card-sub muted-strong">enforce 或 observe</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">本场景告警</div>
            <div className="stat-card-value tone-red">{wantsAlerts ? filteredAlerts.length : '—'}</div>
            <div className="stat-card-sub muted-strong">按 rule_id 前缀过滤</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">下发通道</div>
            <div className="stat-card-value tone-blue" style={{ fontSize: '1rem' }}>install_skill</div>
            <div className="stat-card-sub muted-strong">bundle → hot-reload</div>
          </div>
        </div>
      </div>

      <InstanceHealthPanel
        instances={instanceHealth.instances}
        loading={instanceHealth.loading}
        error={instanceHealth.error}
        onReload={instanceHealth.reload}
      />

      {confirmNeeded && (
        <div className="alert alert-warning">
          <span>
            目标中有 <strong>{instanceHealth.unhealthy.length}</strong> 个实例不处于 running 状态
            （{instanceHealth.unhealthy.map((i) => i.name).join('、')}）。
            下发命令会入队但卡在 pending，直到实例恢复才会被消费。再点一次按钮确认继续。
          </span>
        </div>
      )}

      {dispatchResult && <DispatchResultBanner result={dispatchResult} />}
      {dispatchError && (
        <div className="alert alert-danger">
          <span>下发失败：{dispatchError}</span>
        </div>
      )}

      <div className="panel">
        <div className="section-title-lg mb-4">防御开关</div>
        <div className="space-y-3">
          {meta.defenses.map((def) => {
            const rule = ruleByDefense[def.ruleId];
            const enabled = !!rule?.is_enabled;
            const mode = (rule?.mode ?? 'enforce') as RuleMode;
            return (
              <div key={def.ruleId} className="panel-warm flex items-start justify-between gap-4" style={{ padding: '18px 22px' }}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-base font-semibold text-[#171212]">{def.name}</span>
                    {def.hook && <span className="tag">{def.hook}</span>}
                    {!rule && <span className="badge badge-slate">未配置</span>}
                  </div>
                  <div className="muted text-xs mb-1">{def.desc}</div>
                  <div className="flex items-center gap-3">
                    <span className="muted-strong text-xs font-mono">{def.ruleId}</span>
                    {def.ruleModalData && (
                      <button
                        type="button"
                        className="muted-strong text-xs hover:underline"
                        style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', font: 'inherit' }}
                        onClick={() => setOpenRuleModalFor(def.ruleId)}
                      >
                        查看规则 →
                      </button>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  {def.supportsMode ? (
                    <div className="mode-selector" role="radiogroup" aria-label={`${def.name} 模式`}>
                      {MODES.map((m) => (
                        <button
                          key={m}
                          type="button"
                          className={mode === m ? `active-${m}` : ''}
                          onClick={() => handleMode(def, m)}
                          disabled={busy || !rule}
                        >
                          {m === 'enforce' ? '拦截' : m === 'observe' ? '观察' : '关闭'}
                        </button>
                      ))}
                    </div>
                  ) : (
                    <>
                      <span className="muted text-xs">{enabled ? '已启用' : '已停用'}</span>
                      <button
                        type="button"
                        className={`toggle ${enabled ? 'toggle-on' : ''}`}
                        onClick={() => handleToggle(def)}
                        disabled={busy || !rule}
                        role="switch"
                        aria-checked={enabled}
                        aria-label={`${def.name} 开关`}
                      >
                        <span className="toggle-thumb" />
                      </button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {meta.extras}

      {wantsAlerts && (
        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div className="section-title-lg">本场景事件流</div>
            <Link to="/admin/secplane/events" className="muted text-xs hover:underline">查看全部 →</Link>
          </div>
          {filteredAlerts.length === 0 ? (
            <div className="muted text-sm py-6 text-center">
              暂无匹配本场景规则的事件（前缀：
              {meta.alertRuleIdPrefixes?.map((p) => <code key={p} className="font-mono mx-1">{p}*</code>)}
              ）。
            </div>
          ) : (
            <table className="tbl">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>规则</th>
                  <th>主体</th>
                  <th>证据预览</th>
                  <th>严重度</th>
                  <th>动作</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((a) => (
                  <tr key={a.id}>
                    <td className="muted text-xs whitespace-nowrap">{a.ts}</td>
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
                    <td><span className={`badge ${severityTone(a.severity)}`}>{a.severity}</span></td>
                    <td><span className={`badge ${actionTone(a.action)}`}>{a.action}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {openRuleModalFor &&
        (() => {
          const def = meta.defenses.find((d) => d.ruleId === openRuleModalFor);
          if (!def?.ruleModalData) return null;
          return (
            <RuleDetailModal data={def.ruleModalData} onClose={() => setOpenRuleModalFor(null)} />
          );
        })()}
    </div>
  );
};

export default ScenarioShell;
