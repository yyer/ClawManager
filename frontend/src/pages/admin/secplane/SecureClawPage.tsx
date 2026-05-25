import React, { useEffect, useMemo, useState } from 'react';
import AdminLayout from '../../../components/AdminLayout';
import DispatchPickerModal from '../../../components/secplane/DispatchPickerModal';
import {
  secplaneService,
  type SecplaneRule,
  type SecplaneAlert,
  type AlertSource,
  type Severity,
  type DispatchResult,
} from '../../../services/secplaneService';

// SecureClawPage manages the 7 secureclaw_config rule rows that drive the
// SecureClaw plugin's user_config.json on every dispatch. Form-style UI,
// not a table — there are too few rows + each has its own input shape
// (toggle vs radio vs number).

const FAILURE_MODES = [
  { value: 'block_all', label: 'Block all', help: '默认 — 全部拦截，最安全' },
  { value: 'safe_mode', label: 'Safe mode', help: '只允许读操作，拦截所有写' },
  { value: 'read_only', label: 'Read only', help: '只允许 ls/cat/git status' },
] as const;

const RISK_PROFILES = [
  { value: 'strict', label: 'Strict', help: '严格审批，限制工具集' },
  { value: 'standard', label: 'Standard', help: '默认' },
  { value: 'permissive', label: 'Permissive', help: '放宽审批，适合受信环境' },
] as const;

const severityChip = (sev: Severity) => {
  const map: Record<Severity, string> = {
    low: 'bg-emerald-100 text-emerald-700 border-emerald-200',
    medium: 'bg-amber-100 text-amber-700 border-amber-200',
    high: 'bg-rose-100 text-rose-700 border-rose-200',
  };
  return map[sev] ?? 'bg-gray-100 text-gray-700 border-gray-200';
};

const actionPill = (action: string) => {
  const lookup: Record<string, string> = {
    blocked: 'bg-rose-100 text-rose-700 border-rose-200',
    observed: 'bg-sky-100 text-sky-700 border-sky-200',
    allowed: 'bg-emerald-100 text-emerald-700 border-emerald-200',
  };
  return lookup[action] || 'bg-gray-100 text-gray-700 border-gray-200';
};

type AuditTriState = 'enforce' | 'observe' | 'off';

// InlineText renders a value that becomes editable on click. Used for
// Layer-3 free-form fields (regex pattern, injection string, IOC value,
// privacy "fix" hint). Saves onBlur; Enter commits; Escape cancels.
const InlineText: React.FC<{
  value: string;
  className?: string;
  onSave: (next: string) => void;
}> = ({ value, className = '', onSave }) => {
  const [editing, setEditing] = useState(false);
  if (!editing) {
    return (
      <code
        onClick={() => setEditing(true)}
        className={`cursor-pointer rounded px-1 font-mono text-xs text-gray-700 hover:bg-yellow-50 ${className}`}
        title="点击编辑"
      >
        {value || <span className="text-gray-400 italic">(empty — 点击新增)</span>}
      </code>
    );
  }
  return (
    <input
      autoFocus
      defaultValue={value}
      className={`rounded border border-indigo-300 px-1 font-mono text-xs text-gray-900 ${className}`}
      onBlur={(e) => {
        const next = e.target.value;
        setEditing(false);
        if (next !== value) onSave(next);
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter') (e.target as HTMLInputElement).blur();
        if (e.key === 'Escape') { setEditing(false); e.preventDefault(); }
      }}
    />
  );
};

// AddInput is the "+ 添加" input pinned at the bottom of a list. Enter or
// the button triggers onAdd; the input clears on success.
const AddInput: React.FC<{
  placeholder: string;
  onAdd: (value: string) => void | Promise<void>;
}> = ({ placeholder, onAdd }) => {
  const [val, setVal] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    const v = val.trim();
    if (!v) return;
    setBusy(true);
    try {
      await onAdd(v);
      setVal('');
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex gap-2 border-t border-gray-100 bg-gray-50/50 px-4 py-2">
      <input
        type="text"
        value={val}
        onChange={(e) => setVal(e.target.value)}
        placeholder={placeholder}
        className="flex-1 rounded border border-gray-300 px-2 py-1 text-xs"
        onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
        disabled={busy}
      />
      <button
        onClick={submit}
        disabled={!val.trim() || busy}
        className="rounded bg-indigo-600 px-3 py-1 text-xs text-white hover:bg-indigo-700 disabled:opacity-60"
      >
        {busy ? '…' : '+ 添加'}
      </button>
    </div>
  );
};

const SecureClawPage: React.FC = () => {
  const [rules, setRules] = useState<SecplaneRule[]>([]);
  const [auditRules, setAuditRules] = useState<SecplaneRule[]>([]);
  const [hardeningRules, setHardeningRules] = useState<SecplaneRule[]>([]);
  // Layer 3: skill/configs/*.json rule sets
  const [dangerousCatRules, setDangerousCatRules] = useState<SecplaneRule[]>([]);
  const [dangerousPatRules, setDangerousPatRules] = useState<SecplaneRule[]>([]);
  const [injectionPatRules, setInjectionPatRules] = useState<SecplaneRule[]>([]);
  const [privacyRules, setPrivacyRules] = useState<SecplaneRule[]>([]);
  const [iocRules, setIocRules] = useState<SecplaneRule[]>([]);
  const [rulesLoading, setRulesLoading] = useState(true);
  const [rulesError, setRulesError] = useState<string | null>(null);
  const [savingRuleID, setSavingRuleID] = useState<string | null>(null);

  const [alerts, setAlerts] = useState<SecplaneAlert[]>([]);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [alertsError, setAlertsError] = useState<string | null>(null);

  const [pickerOpen, setPickerOpen] = useState(false);
  const [dispatching, setDispatching] = useState(false);
  const [dispatchResult, setDispatchResult] = useState<DispatchResult | null>(null);
  const [dispatchError, setDispatchError] = useState<string | null>(null);

  const loadRules = async () => {
    setRulesLoading(true);
    setRulesError(null);
    try {
      const [cfg, audit, harden, dCat, dPat, iPat, pri, ioc] = await Promise.all([
        secplaneService.listRules('secureclaw_config'),
        secplaneService.listRules('secureclaw_audit_check'),
        secplaneService.listRules('secureclaw_hardening'),
        secplaneService.listRules('secureclaw_dangerous_cat'),
        secplaneService.listRules('secureclaw_dangerous_pat'),
        secplaneService.listRules('secureclaw_injection_pat'),
        secplaneService.listRules('secureclaw_privacy_rule'),
        secplaneService.listRules('secureclaw_ioc'),
      ]);
      setRules(cfg);
      setAuditRules(audit);
      setHardeningRules(harden);
      setDangerousCatRules(dCat);
      setDangerousPatRules(dPat);
      setInjectionPatRules(iPat);
      setPrivacyRules(pri);
      setIocRules(ioc);
    } catch (e: any) {
      setRulesError(e?.response?.data?.error ?? e?.message ?? 'failed to load rules');
    } finally {
      setRulesLoading(false);
    }
  };

  const loadAlerts = async () => {
    setAlertsLoading(true);
    setAlertsError(null);
    try {
      const items = await secplaneService.listAlerts({
        source: 'secureclaw' as AlertSource,
        limit: 100,
      });
      setAlerts(items);
    } catch (e: any) {
      setAlertsError(e?.response?.data?.error ?? e?.message ?? 'failed to load alerts');
    } finally {
      setAlertsLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
    loadAlerts();
  }, []);

  const rulesByID = useMemo(() => {
    const m = new Map<string, SecplaneRule>();
    for (const r of rules) m.set(r.rule_id, r);
    return m;
  }, [rules]);

  const persistRule = async (next: SecplaneRule) => {
    setSavingRuleID(next.rule_id);
    setRulesError(null);
    try {
      await secplaneService.saveRule(next);
      await loadRules();
    } catch (e: any) {
      setRulesError(e?.response?.data?.error ?? e?.message ?? 'failed to save');
    } finally {
      setSavingRuleID(null);
    }
  };

  // Soft-delete; backend's DELETE flips is_enabled=false. The rule rows that
  // back the SecureClaw config (categories / patterns / privacy rules) all
  // filter on is_enabled, so this acts like a real delete from the user's POV.
  const hardDeleteRule = async (rule_id: string) => {
    setSavingRuleID(rule_id);
    try {
      await secplaneService.disableRule(rule_id);
      await loadRules();
    } catch (e: any) {
      setRulesError(e?.response?.data?.error ?? e?.message ?? 'failed to delete');
    } finally {
      setSavingRuleID(null);
    }
  };

  const runDispatch = async (instanceIDs: number[] | null) => {
    setDispatching(true);
    setDispatchError(null);
    setDispatchResult(null);
    try {
      const result = await secplaneService.dispatchSecureClaw(instanceIDs ?? undefined);
      setDispatchResult(result);
      setPickerOpen(false);
    } catch (e: any) {
      setDispatchError(e?.response?.data?.error ?? e?.message ?? 'dispatch failed');
    } finally {
      setDispatching(false);
    }
  };

  // ---- per-rule editors ------------------------------------------------

  const renderToggleRow = (ruleID: string, label: string, help?: React.ReactNode) => {
    const rule = rulesByID.get(ruleID);
    if (!rule) return null;
    const isSaving = savingRuleID === ruleID;
    return (
      <div className="flex items-start gap-4 py-3">
        <div className="min-w-0 flex-1">
          <div className="font-medium text-gray-900">{label}</div>
          {help && <div className="mt-0.5 text-xs text-gray-500">{help}</div>}
          <div className="mt-0.5 font-mono text-[10px] text-gray-400">{rule.rule_id}</div>
        </div>
        <button
          disabled={isSaving}
          onClick={() => persistRule({ ...rule, is_enabled: !rule.is_enabled })}
          className={`shrink-0 rounded-full border px-3 py-1 text-xs ${
            rule.is_enabled
              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
              : 'bg-gray-100 text-gray-500 border-gray-200'
          } disabled:opacity-60`}
        >
          {isSaving ? '…' : rule.is_enabled ? '开启' : '关闭'}
        </button>
      </div>
    );
  };

  // renderRadioRow renders a list of mutually-exclusive options as visually
  // obvious radio cards (real input type=radio + visible dot + outline).
  // Non-generic on purpose — earlier `<T extends string>` form was getting
  // parsed inconsistently by some toolchains and made the options look like
  // passive labels in places. Plain string is fine for our 3-option enums.
  function renderRadioRow(
    ruleID: string,
    label: string,
    options: ReadonlyArray<{ value: string; label: string; help: string }>,
  ) {
    const rule = rulesByID.get(ruleID);
    if (!rule) return null;
    const isSaving = savingRuleID === ruleID;
    const current = rule.pattern || options[0].value;
    const groupName = `radio-${ruleID}`;
    return (
      <div className="py-3">
        <div className="mb-2 flex items-center justify-between">
          <div>
            <div className="font-medium text-gray-900">{label}</div>
            <div className="font-mono text-[10px] text-gray-400">{rule.rule_id}</div>
          </div>
          <div className="text-xs text-gray-500">当前: <code className="font-semibold text-indigo-700">{current}</code></div>
        </div>
        <div className="grid gap-2 md:grid-cols-3">
          {options.map((opt) => {
            const active = current === opt.value;
            return (
              <label
                key={opt.value}
                className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 text-sm transition ${
                  active
                    ? 'border-indigo-400 bg-indigo-50 ring-1 ring-indigo-300'
                    : 'border-gray-200 bg-white hover:bg-gray-50'
                } ${isSaving ? 'pointer-events-none opacity-60' : ''}`}
              >
                <input
                  type="radio"
                  name={groupName}
                  value={opt.value}
                  checked={active}
                  disabled={isSaving}
                  onChange={() => persistRule({ ...rule, pattern: opt.value, is_enabled: true })}
                  className="mt-1 h-4 w-4 accent-indigo-600"
                />
                <div className="min-w-0 flex-1">
                  <div className={`font-medium ${active ? 'text-indigo-700' : 'text-gray-900'}`}>{opt.label}</div>
                  <div className="mt-0.5 text-xs text-gray-500">{opt.help}</div>
                </div>
              </label>
            );
          })}
        </div>
      </div>
    );
  }

  const renderNumberRow = (
    ruleID: string,
    label: string,
    placeholder: string,
    opts: { step?: string; unit?: string; min?: string } = {},
  ) => {
    const rule = rulesByID.get(ruleID);
    if (!rule) return null;
    const isSaving = savingRuleID === ruleID;
    return (
      <div className="flex items-center gap-3 py-2">
        <input
          type="checkbox"
          checked={rule.is_enabled}
          disabled={isSaving}
          onChange={() => persistRule({ ...rule, is_enabled: !rule.is_enabled })}
          className="h-4 w-4 rounded border-gray-300"
        />
        <div className="min-w-0 flex-1 text-sm text-gray-700">{label}</div>
        <input
          type="number"
          value={rule.pattern}
          step={opts.step ?? '0.01'}
          min={opts.min ?? '0'}
          disabled={isSaving || !rule.is_enabled}
          onBlur={(e) => {
            if (e.target.value !== rule.pattern) {
              persistRule({ ...rule, pattern: e.target.value });
            }
          }}
          onChange={(e) => {
            // Optimistic update only; commit on blur to avoid spamming the
            // backend on every keystroke.
            setRules((prev) =>
              prev.map((r) => (r.rule_id === rule.rule_id ? { ...r, pattern: e.target.value } : r)),
            );
          }}
          placeholder={placeholder}
          className="w-28 rounded border border-gray-300 px-2 py-1 text-right text-sm disabled:bg-gray-100"
        />
        <span className="text-xs text-gray-500">{opts.unit ?? 'USD'}</span>
      </div>
    );
  };

  // ---- audit + hardening ---------------------------------------------

  const triStateOf = (r: SecplaneRule): AuditTriState => {
    if (!r.is_enabled || r.mode === 'off') return 'off';
    if (r.mode === 'observe') return 'observe';
    return 'enforce';
  };

  const persistAuditTri = (r: SecplaneRule, next: AuditTriState) => {
    if (next === 'off') return persistRule({ ...r, is_enabled: false });
    return persistRule({ ...r, is_enabled: true, mode: next });
  };

  // Group audit rules by category prefix derived from rule pattern (compile
  // helpfully stores category in pattern). Fall back to "general" if absent.
  const auditByCategory = useMemo(() => {
    const groups: Record<string, SecplaneRule[]> = {};
    for (const r of auditRules) {
      const cat = (r.pattern || 'general').trim();
      (groups[cat] = groups[cat] ?? []).push(r);
    }
    return Object.entries(groups).sort(([a], [b]) => a.localeCompare(b));
  }, [auditRules]);

  // Category Chinese labels for the 13 SecureClaw categories we see in the
  // 56 checks. Unknown categories fall through to the raw string.
  const CATEGORY_LABEL: Record<string, string> = {
    'access-control': '访问控制 (access-control)',
    'control-tokens': '控制 token (control-tokens)',
    'cost': '成本 (cost)',
    'credentials': '凭据 (credentials)',
    'cross-layer': '跨层风险 (cross-layer)',
    'degradation': '降级模式 (degradation)',
    'execution': '执行 (execution)',
    'gateway': '网关 (gateway)',
    'ioc': '威胁情报 (ioc)',
    'kill-switch': '紧急刹车 (kill-switch)',
    'memory': '记忆 (memory)',
    'memory-trust': '记忆信任 (memory-trust)',
    'supply-chain': 'Skill 供应链 (supply-chain)',
  };

  const SEG_TONE: Record<AuditTriState, string> = {
    off: 'bg-gray-700 text-white',
    observe: 'bg-amber-500 text-white',
    enforce: 'bg-emerald-600 text-white',
  };

  const renderAuditRow = (r: SecplaneRule) => {
    const state = triStateOf(r);
    const isSaving = savingRuleID === r.rule_id;
    return (
      <tr key={r.rule_id} className={`hover:bg-gray-50 ${state === 'off' ? 'bg-gray-50/50' : ''}`}>
        <td className="px-3 py-2 align-top">
          <div className="flex items-center gap-2">
            <code className="font-mono text-xs text-gray-700">{r.display_name}</code>
            <span className={`rounded-full border px-1.5 py-0.5 text-[10px] ${severityChip(r.severity)}`}>{r.severity}</span>
          </div>
          <div className="mt-0.5 max-w-xl truncate text-xs text-gray-500" title={r.description ?? ''}>
            {r.description ?? '-'}
          </div>
        </td>
        <td className="px-3 py-2 text-right align-top">
          <div className="inline-flex divide-x divide-gray-300 overflow-hidden rounded-md border border-gray-300">
            {(['off', 'observe', 'enforce'] as AuditTriState[]).map((s) => (
              <button
                key={s}
                disabled={isSaving}
                onClick={() => persistAuditTri(r, s)}
                className={`px-2.5 py-1 text-[10px] transition first:rounded-l-md last:rounded-r-md ${
                  state === s ? SEG_TONE[s] : 'bg-white text-gray-600 hover:bg-gray-50'
                } disabled:opacity-60 disabled:cursor-not-allowed`}
              >
                {s === 'off' ? 'Off' : s === 'observe' ? 'Observe' : 'Enforce'}
              </button>
            ))}
          </div>
        </td>
      </tr>
    );
  };

  // Bulk action helper: set every row in a category to the same state.
  const bulkSetCategory = async (cat: string, next: AuditTriState) => {
    for (const r of auditByCategory.find(([c]) => c === cat)?.[1] ?? []) {
      await persistAuditTri(r, next);
    }
  };

  // ---- render ---------------------------------------------------------

  const autoHarden = rulesByID.get('sc.autoHarden');

  return (
    <AdminLayout title="SecureClaw 安全审计与加固">
      <div className="space-y-4">
        <div className="rounded-xl border border-gray-200 bg-white p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-indigo-600">secureclaw · secplane</div>
              <div className="mt-1 text-2xl font-semibold text-gray-900">SecureClaw 安全审计与加固</div>
              <div className="mt-1 text-sm text-gray-600">
                配置 SecureClaw 插件在每个 OpenClaw 实例上的运行策略：失败降级模式、风险等级、成本熔断；以及是否在网关启动时自动跑 harden（默认关闭，谨慎打开）。下方告警列表实时显示 SecureClaw 插件回传的 audit/monitor/killswitch 事件。
              </div>
            </div>
            <button
              onClick={() => setPickerOpen(true)}
              disabled={dispatching}
              className="shrink-0 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-indigo-700 disabled:opacity-60"
              title="选择目标实例并下发 SecureClaw user_config"
            >
              {dispatching ? '下发中…' : '下发到实例…'}
            </button>
          </div>
          {dispatchError && (
            <div className="mt-3 rounded border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{dispatchError}</div>
          )}
          {dispatchResult && (
            <div className="mt-3 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                <span className="font-medium text-emerald-800">下发完成</span>
                <span className="text-gray-600">revision: <code>{dispatchResult.revision}</code></span>
                <span className="text-gray-600">sha: <code>{dispatchResult.sha256.slice(0, 12)}…</code></span>
                {dispatchResult.skill_id !== undefined && (
                  <span className="text-gray-600">skill_id={dispatchResult.skill_id} v{dispatchResult.version_no}</span>
                )}
              </div>
              <div className="mt-2 grid gap-1">
                {dispatchResult.targets.map((t) => (
                  <div key={t.instance_id} className="flex items-center gap-2">
                    <span className="text-gray-500">实例 #{t.instance_id}</span>
                    <span className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-700">{t.command_type}</span>
                    <span className={`rounded-full px-2 py-0.5 ${t.status === 'succeeded' ? 'bg-emerald-100 text-emerald-700' : t.status === 'failed' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700'}`}>
                      {t.status}
                    </span>
                    {t.command_id && <span className="text-gray-500">cmd #{t.command_id}</span>}
                    {t.error && <span className="text-rose-700">{t.error}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {rulesError && <div className="rounded border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{rulesError}</div>}
        {rulesLoading && <div className="rounded border border-gray-200 bg-gray-50 p-3 text-sm text-gray-600">加载中…</div>}

        {/* Section 1: 运行策略 */}
        <section className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="mb-3 border-b border-gray-100 pb-2">
            <div className="text-sm font-semibold text-gray-800">运行策略</div>
            <div className="text-xs text-gray-500">控制 SecureClaw 插件在 onGatewayStart 时怎么干，以及失败时如何降级</div>
          </div>
          {autoHarden && renderToggleRow(
            'sc.autoHarden',
            '自动 Harden',
            <>
              <span className="text-rose-600 font-medium">⚠ 启用后 SecureClaw 会在网关启动时自动修改 openclaw.json、调整 socket 权限、清理 credential 等。</span>
              <span> 仅在你完全理解每项 hardening 操作时启用；生产环境建议保持关闭，用 audit 报告人工 review 后再决定。</span>
            </>,
          )}
          {renderRadioRow('sc.failureMode', '失败降级模式 (failureMode)', FAILURE_MODES)}
          {renderRadioRow('sc.riskProfile', '运行风险等级 (riskProfile)', RISK_PROFILES)}
        </section>

        {/* Section 2: 成本熔断 */}
        <section className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="mb-3 border-b border-gray-100 pb-2">
            <div className="text-sm font-semibold text-gray-800">成本熔断</div>
            <div className="text-xs text-gray-500">超过任意一个启用的上限时，按"circuit breaker"暂停 session</div>
          </div>
          {renderToggleRow(
            'sc.cost.circuitBreakerEnabled',
            '启用成本熔断',
            '关闭后即便配了上限也只会写告警，不会真暂停 session',
          )}
          <div className="mt-2 space-y-1">
            {renderNumberRow('sc.cost.hourlyLimitUsd', '每小时上限', '10.0')}
            {renderNumberRow('sc.cost.dailyLimitUsd', '每天上限', '100.0')}
            {renderNumberRow('sc.cost.monthlyLimitUsd', '每月上限', '2000.0')}
          </div>
        </section>

        {/* Section 3: 监视器 */}
        <section className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="mb-3 border-b border-gray-100 pb-2">
            <div className="text-sm font-semibold text-gray-800">后台监视器</div>
            <div className="text-xs text-gray-500">SecureClaw 启动时拉起的 4 个长期运行监视器。关闭某项 = SecureClaw 跳过该监视器的 start() 调用。</div>
          </div>
          {renderToggleRow('sc.monitors.credentials', '凭据泄漏监视器 (credentials)', '扫描 stateDir 内的 API key / 私钥 / cookie 文件')}
          {renderToggleRow('sc.monitors.memory', '记忆完整性监视器 (memory)', '监视 memory_store / MEMORY.md / SOUL.md 的非预期写入')}
          {renderToggleRow('sc.monitors.skills', 'Skill 扫描监视器 (skills)', '扫描 ~/.openclaw/skills 与 workspace/skills 的可疑安装')}
          {renderToggleRow('sc.monitors.cost', 'Cost 监视器 (cost)', '采集 LLM 调用 token 与 cost — 是上面 cost.* 上限生效的前提')}
        </section>

        {/* Section 4: 记忆审查细项 */}
        <section className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="mb-3 border-b border-gray-100 pb-2">
            <div className="text-sm font-semibold text-gray-800">记忆审查细项</div>
            <div className="text-xs text-gray-500">memory 监视器开启后，下面细项控制具体扫描策略</div>
          </div>
          {renderToggleRow('sc.memory.integrityChecks', '完整性校验 (integrityChecks)', '对受保护的记忆文件做 hash baseline 比对')}
          {renderToggleRow('sc.memory.promptInjectionScan', '注入扫描 (promptInjectionScan)', '在读取记忆内容时扫描 prompt 注入 pattern')}
          {renderToggleRow('sc.memory.quarantineEnabled', '隔离 (quarantineEnabled)', '命中风险时把记忆条目移到 quarantine 目录而不是直接读入 context')}
          {renderToggleRow('sc.memory.trustLevels', '来源信任分级 (trustLevels)', '按来源标注 trusted / unverified / external，影响是否注入到 LLM context')}
        </section>

        {/* Section 5: Skill 审计 */}
        <section className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="mb-3 border-b border-gray-100 pb-2">
            <div className="text-sm font-semibold text-gray-800">Skill 审计</div>
            <div className="text-xs text-gray-500">控制新 skill 安装时的扫描行为</div>
          </div>
          {renderToggleRow('sc.skills.blockUnaudited', '拦截未审计 Skill (blockUnaudited)', '未通过 skill scan 的 skill 不允许安装或启用')}
          {renderToggleRow('sc.skills.scanOnInstall', '安装时扫描 (scanOnInstall)', '新 skill 安装前自动跑 quick-audit，高危直接拒绝')}
          {renderToggleRow('sc.skills.iocCheckEnabled', 'IOC 比对 (iocCheckEnabled)', '对照 ioc/indicators.json 的恶意 hash / 域名做匹配')}
        </section>

        {/* Section 6: 出口控制 */}
        <section className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="mb-3 border-b border-gray-100 pb-2">
            <div className="text-sm font-semibold text-gray-800">网络出口控制</div>
            <div className="text-xs text-gray-500">控制工具调用是否限制在白名单域名内</div>
          </div>
          {renderToggleRow('sc.network.egressAllowlistEnabled', '启用出口白名单 (egressAllowlistEnabled)',
            <>
              开启后只有 SecureClaw allowlist 内的域名能被工具调用访问。
              <span className="ml-1 text-amber-700">注：当前 allowlist 列表仍由 openclaw.json 维护，secplane 暂不下发列表本身。</span>
            </>,
          )}
        </section>

        {/* Section 7: 行为基线 */}
        <section className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="mb-3 border-b border-gray-100 pb-2">
            <div className="text-sm font-semibold text-gray-800">行为基线 (behavioral)</div>
            <div className="text-xs text-gray-500">累积 tool 调用模式，对显著偏离基线的行为告警</div>
          </div>
          {renderToggleRow('sc.behavioral.baselineEnabled', '启用基线累积 (baselineEnabled)', '累积 tool 调用频率到 jsonl，关闭后基线不更新')}
          <div className="mt-2 space-y-1">
            {renderNumberRow('sc.behavioral.deviationThreshold', '偏差阈值 (deviationThreshold)', '0.5', { step: '0.01', unit: '0-1', min: '0' })}
            {renderNumberRow('sc.behavioral.windowMinutes', '窗口长度 (windowMinutes)', '60', { step: '1', unit: '分钟', min: '1' })}
          </div>
        </section>

        {/* Section 8: Audit 检查 */}
        <section className="rounded-xl border border-gray-200 bg-white">
          <div className="border-b border-gray-100 px-4 py-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-semibold text-gray-800">Audit 检查 · 56 项</div>
                <div className="text-xs text-gray-500">
                  SecureClaw 启动时跑 56 个 audit。Enforce = 正常报告；Observe = 仍报但 severity 降为 LOW（auto-harden 不动它）；Off = 完全跳过。
                </div>
              </div>
              <div className="text-xs text-gray-500">
                共 {auditRules.length}；
                enforce {auditRules.filter((r) => triStateOf(r) === 'enforce').length}；
                observe {auditRules.filter((r) => triStateOf(r) === 'observe').length}；
                off {auditRules.filter((r) => triStateOf(r) === 'off').length}
              </div>
            </div>
          </div>
          <div className="divide-y divide-gray-100">
            {auditByCategory.map(([cat, items]) => (
              <details key={cat} open className="group">
                <summary className="flex cursor-pointer items-center justify-between bg-gray-50 px-4 py-2 text-sm hover:bg-gray-100">
                  <span className="font-medium text-gray-800">
                    {CATEGORY_LABEL[cat] ?? cat}
                    <span className="ml-2 text-xs text-gray-500">({items.length})</span>
                  </span>
                  <span className="flex items-center gap-1 text-[10px]" onClick={(e) => e.stopPropagation()}>
                    <button onClick={() => bulkSetCategory(cat, 'enforce')} className="rounded border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-emerald-700 hover:bg-emerald-100">全 Enforce</button>
                    <button onClick={() => bulkSetCategory(cat, 'observe')} className="rounded border border-amber-200 bg-amber-50 px-2 py-0.5 text-amber-700 hover:bg-amber-100">全 Observe</button>
                    <button onClick={() => bulkSetCategory(cat, 'off')} className="rounded border border-gray-300 bg-gray-100 px-2 py-0.5 text-gray-700 hover:bg-gray-200">全 Off</button>
                  </span>
                </summary>
                <table className="min-w-full text-sm">
                  <tbody className="divide-y divide-gray-100">
                    {items.map(renderAuditRow)}
                  </tbody>
                </table>
              </details>
            ))}
            {auditRules.length === 0 && !rulesLoading && (
              <div className="p-6 text-center text-sm text-gray-500">未加载到 audit 规则（seed 可能没跑过）</div>
            )}
          </div>
        </section>

        {/* Section 9: 自动修复模块 */}
        <section className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="mb-3 border-b border-gray-100 pb-2">
            <div className="text-sm font-semibold text-gray-800">自动修复模块 · 5 个</div>
            <div className="text-xs text-gray-500">
              每个模块控制一类自动 fix 是否在 <code>autoHarden=true</code> 时跑。开启某模块 = 允许它在 harden 时改 pod 配置。默认全部关闭以避免任何意外修改。
              <span className="ml-1 text-rose-600">⚠ 启用前先 review 该模块在 audit 报告里会改什么。</span>
            </div>
          </div>
          {hardeningRules.length === 0 && !rulesLoading && (
            <div className="text-sm text-gray-500">未加载到 hardening 模块规则</div>
          )}
          {hardeningRules.map((r) => (
            <div key={r.rule_id} className="flex items-start gap-4 py-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <code className="font-mono text-xs text-gray-900">{r.display_name}</code>
                  {!r.is_enabled && <span className="rounded-full border border-gray-200 bg-gray-100 px-2 py-0.5 text-[10px] text-gray-600">disabled</span>}
                </div>
                {r.description && <div className="mt-0.5 text-xs text-gray-500">{r.description}</div>}
                <div className="mt-0.5 font-mono text-[10px] text-gray-400">{r.rule_id}</div>
              </div>
              <button
                disabled={savingRuleID === r.rule_id}
                onClick={() => persistRule({ ...r, is_enabled: !r.is_enabled })}
                className={`shrink-0 rounded-full border px-3 py-1 text-xs ${
                  r.is_enabled
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-gray-100 text-gray-500 border-gray-200'
                } disabled:opacity-60`}
              >
                {savingRuleID === r.rule_id ? '…' : r.is_enabled ? '允许 harden' : '不动 harden'}
              </button>
            </div>
          ))}
        </section>

        {/* ----- Layer 3: skill/configs/*.json overrides ----- */}

        {/* Section 10: dangerous-commands.json */}
        <section className="rounded-xl border border-gray-200 bg-white">
          <div className="flex items-center justify-between border-b border-gray-100 px-4 py-3">
            <div>
              <div className="text-sm font-semibold text-gray-800">危险命令拦截 · dangerous-commands.json</div>
              <div className="text-xs text-gray-500">
                每 category 有自己的 severity + action。点 pattern 文本可改 regex；底部 `+ 添加` 加新 pattern；右侧 `+ 新增 category` 加自定义类别。
              </div>
            </div>
            <button
              onClick={async () => {
                const name = window.prompt('新 category 名（英文 snake_case，例如 custom_internal_cmd）：');
                if (!name) return;
                const key = name.trim().replace(/\W+/g, '_').toLowerCase();
                if (!key) return;
                await persistRule({
                  rule_id: `sc.dc.cat.${key}`,
                  kind: 'secureclaw_dangerous_cat',
                  display_name: key,
                  pattern: 'block',
                  target: 'user_input',
                  severity: 'high',
                  action: 'block',
                  mode: 'enforce',
                  is_enabled: true,
                  sort_order: 4999,
                });
              }}
              className="rounded border border-indigo-300 bg-white px-3 py-1.5 text-xs text-indigo-700 hover:bg-indigo-50"
            >
              + 新增 category
            </button>
          </div>
          {dangerousCatRules.map((cat) => {
            const catKey = cat.rule_id.replace(/^sc\.dc\.cat\./, '');
            const patterns = dangerousPatRules.filter((p) => p.tags === catKey);
            const isSaving = savingRuleID === cat.rule_id;
            return (
              <details key={cat.rule_id} className="group border-t border-gray-100 first:border-t-0" open>
                <summary className="flex cursor-pointer items-center justify-between gap-3 bg-gray-50 px-4 py-2 hover:bg-gray-100">
                  <div className="flex min-w-0 flex-1 items-center gap-2">
                    <span className="font-medium text-gray-900">{catKey}</span>
                    <span className="text-xs text-gray-500">{patterns.length} 个 pattern</span>
                    {!cat.is_enabled && <span className="rounded-full border border-gray-200 bg-gray-100 px-2 py-0.5 text-[10px] text-gray-600">disabled</span>}
                  </div>
                  <div className="flex items-center gap-2 text-xs" onClick={(e) => e.stopPropagation()}>
                    <select value={cat.severity} disabled={isSaving} onChange={(e) => persistRule({ ...cat, severity: e.target.value as any })}
                      className="rounded border border-gray-300 px-2 py-0.5">
                      <option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
                    </select>
                    <select value={cat.pattern} disabled={isSaving} onChange={(e) => persistRule({ ...cat, pattern: e.target.value })}
                      className="rounded border border-gray-300 px-2 py-0.5">
                      <option value="block">block</option><option value="require_approval">require_approval</option><option value="warn">warn</option>
                    </select>
                    <button disabled={isSaving} onClick={() => persistRule({ ...cat, is_enabled: !cat.is_enabled })}
                      className={`rounded-full border px-2 py-0.5 ${cat.is_enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-gray-100 text-gray-500 border-gray-200'}`}>
                      {cat.is_enabled ? '启用' : '关闭'}
                    </button>
                    <button disabled={isSaving || patterns.length > 0} onClick={() => hardDeleteRule(cat.rule_id)}
                      title={patterns.length > 0 ? '请先移除该 category 下的所有 pattern' : '删除 category'}
                      className="rounded border border-rose-200 bg-white px-2 py-0.5 text-rose-700 hover:bg-rose-50 disabled:opacity-60">
                      删
                    </button>
                  </div>
                </summary>
                <ul className="divide-y divide-gray-100">
                  {patterns.map((p) => (
                    <li key={p.rule_id} className="flex items-center gap-2 px-5 py-1.5">
                      <input type="checkbox" checked={p.is_enabled} disabled={savingRuleID === p.rule_id}
                        onChange={() => persistRule({ ...p, is_enabled: !p.is_enabled })}
                        className="h-4 w-4 rounded border-gray-300" />
                      <div className="flex-1 min-w-0">
                        <InlineText value={p.pattern} onSave={(v) => persistRule({ ...p, pattern: v, display_name: v })} />
                      </div>
                      <button onClick={() => hardDeleteRule(p.rule_id)} className="text-xs text-rose-600 hover:text-rose-800">移除</button>
                    </li>
                  ))}
                  {patterns.length === 0 && <li className="px-5 py-2 text-xs text-gray-400 italic">空 — 在下方添加 pattern</li>}
                </ul>
                <AddInput
                  placeholder={`加新 regex 到 ${catKey}（例如 \\bsudo\\s+rm\\s+-rf）`}
                  onAdd={async (v) => {
                    const slug = Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
                    await persistRule({
                      rule_id: `sc.dc.pat.${catKey}.user-${slug}`,
                      kind: 'secureclaw_dangerous_pat',
                      display_name: v,
                      pattern: v,
                      tags: catKey,
                      target: 'user_input',
                      severity: 'high',
                      action: 'block',
                      mode: 'enforce',
                      is_enabled: true,
                      sort_order: 4999,
                    });
                  }}
                />
              </details>
            );
          })}
        </section>

        {/* Section 11: injection-patterns.json */}
        <section className="rounded-xl border border-gray-200 bg-white">
          <div className="border-b border-gray-100 px-4 py-3">
            <div className="text-sm font-semibold text-gray-800">提示词注入字符串 · injection-patterns.json</div>
            <div className="text-xs text-gray-500">
              7 个 category 下的注入特征短语（大小写不敏感子串匹配）。共 {injectionPatRules.length} 条。
            </div>
          </div>
          {Array.from(new Set(injectionPatRules.map((r) => r.tags ?? ''))).sort().map((cat) => {
            const items = injectionPatRules.filter((r) => r.tags === cat);
            return (
              <details key={cat} className="group border-t border-gray-100 first:border-t-0">
                <summary className="cursor-pointer bg-gray-50 px-4 py-2 hover:bg-gray-100 text-sm">
                  <span className="font-medium text-gray-900">{cat}</span>
                  <span className="ml-2 text-xs text-gray-500">{items.length}</span>
                </summary>
                <ul className="divide-y divide-gray-100">
                  {items.map((r) => (
                    <li key={r.rule_id} className="flex items-center gap-2 px-5 py-1.5">
                      <input type="checkbox" checked={r.is_enabled} disabled={savingRuleID === r.rule_id}
                        onChange={() => persistRule({ ...r, is_enabled: !r.is_enabled })}
                        className="h-4 w-4 rounded border-gray-300" />
                      <div className="flex-1 min-w-0">
                        <InlineText value={r.pattern} onSave={(v) => persistRule({ ...r, pattern: v, display_name: v })} />
                      </div>
                      <button onClick={() => hardDeleteRule(r.rule_id)} className="text-xs text-rose-600 hover:text-rose-800">移除</button>
                    </li>
                  ))}
                  {items.length === 0 && <li className="px-5 py-2 text-xs text-gray-400 italic">空</li>}
                </ul>
                <AddInput
                  placeholder={`加新注入字符串到 ${cat}（不区分大小写子串匹配）`}
                  onAdd={async (v) => {
                    const slug = Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
                    await persistRule({
                      rule_id: `sc.ip.pat.${cat}.user-${slug}`,
                      kind: 'secureclaw_injection_pat',
                      display_name: v,
                      pattern: v,
                      tags: cat,
                      target: 'user_input',
                      severity: 'high',
                      action: 'block',
                      mode: 'enforce',
                      is_enabled: true,
                      sort_order: 5999,
                    });
                  }}
                />
              </details>
            );
          })}
          <div className="flex items-center justify-end gap-2 border-t border-gray-100 bg-gray-50/50 px-4 py-2">
            <button
              onClick={async () => {
                const name = window.prompt('新注入类别名（英文 snake_case，例如 business_logic_bypass）：');
                if (!name) return;
                const key = name.trim().replace(/\W+/g, '_').toLowerCase();
                if (!key) return;
                const phrase = window.prompt('该类别的第一条字符串（占位，可在 UI 改）：') ?? 'placeholder';
                const slug = Date.now().toString(36);
                await persistRule({
                  rule_id: `sc.ip.pat.${key}.user-${slug}`,
                  kind: 'secureclaw_injection_pat',
                  display_name: phrase,
                  pattern: phrase,
                  tags: key,
                  target: 'user_input',
                  severity: 'high',
                  action: 'block',
                  mode: 'enforce',
                  is_enabled: true,
                  sort_order: 5999,
                });
              }}
              className="rounded border border-indigo-300 bg-white px-3 py-1 text-xs text-indigo-700 hover:bg-indigo-50"
            >
              + 新增类别
            </button>
          </div>
        </section>

        {/* Section 12: privacy-rules.json */}
        <section className="rounded-xl border border-gray-200 bg-white">
          <div className="flex items-center justify-between border-b border-gray-100 px-4 py-3">
            <div>
              <div className="text-sm font-semibold text-gray-800">PII 隐私规则 · privacy-rules.json · {privacyRules.length} 条</div>
              <div className="text-xs text-gray-500">点击正则或 fix 列编辑。Action: block 拒发 / remove 删除 / rewrite 重写。</div>
            </div>
            <button
              onClick={async () => {
                const id = window.prompt('新规则 id（英文 snake_case，例如 employee_id）：');
                if (!id) return;
                const key = id.trim().replace(/\W+/g, '_').toLowerCase();
                if (!key) return;
                const regex = window.prompt('正则（可在表格里改）：') ?? '';
                const fix = window.prompt('给 Agent 的重写提示（可空）：') ?? '';
                await persistRule({
                  rule_id: `sc.pr.${key}`,
                  kind: 'secureclaw_privacy_rule',
                  display_name: key,
                  pattern: regex,
                  description: fix,
                  target: 'user_input',
                  severity: 'medium',
                  action: 'redact',
                  mode: 'enforce',
                  is_enabled: true,
                  sort_order: 7999,
                });
              }}
              className="rounded border border-indigo-300 bg-white px-3 py-1.5 text-xs text-indigo-700 hover:bg-indigo-50"
            >
              + 新建规则
            </button>
          </div>
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2">ID</th>
                <th className="px-4 py-2">正则</th>
                <th className="px-4 py-2">Severity</th>
                <th className="px-4 py-2">Action</th>
                <th className="px-4 py-2">Fix 提示</th>
                <th className="px-4 py-2 text-right">启用</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {privacyRules.map((r) => {
                const isSaving = savingRuleID === r.rule_id;
                return (
                  <tr key={r.rule_id} className={`hover:bg-gray-50 ${!r.is_enabled ? 'bg-gray-50/50' : ''}`}>
                    <td className="px-4 py-2 font-mono text-xs">{r.display_name}</td>
                    <td className="px-4 py-2">
                      <InlineText value={r.pattern} className="max-w-xs" onSave={(v) => persistRule({ ...r, pattern: v })} />
                    </td>
                    <td className="px-4 py-2">
                      <select value={r.severity} disabled={isSaving} onChange={(e) => persistRule({ ...r, severity: e.target.value as any })}
                        className="rounded border border-gray-300 px-2 py-0.5 text-xs">
                        <option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
                      </select>
                    </td>
                    <td className="px-4 py-2">
                      <select value={r.action} disabled={isSaving} onChange={(e) => persistRule({ ...r, action: e.target.value as any })}
                        className="rounded border border-gray-300 px-2 py-0.5 text-xs">
                        <option value="block">block</option><option value="remove">remove</option><option value="rewrite">rewrite</option>
                      </select>
                    </td>
                    <td className="px-4 py-2 text-xs text-gray-600">
                      <InlineText value={r.description ?? ''} onSave={(v) => persistRule({ ...r, description: v })} />
                    </td>
                    <td className="px-4 py-2 text-right">
                      <div className="inline-flex items-center gap-1">
                        <button disabled={isSaving} onClick={() => persistRule({ ...r, is_enabled: !r.is_enabled })}
                          className={`rounded-full border px-2 py-0.5 text-xs ${r.is_enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-gray-100 text-gray-500 border-gray-200'}`}>
                          {r.is_enabled ? '开' : '关'}
                        </button>
                        <button onClick={() => hardDeleteRule(r.rule_id)} className="rounded border border-rose-200 bg-white px-2 py-0.5 text-xs text-rose-700 hover:bg-rose-50">删</button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>

        {/* Section 13: supply-chain-ioc.json */}
        <section className="rounded-xl border border-gray-200 bg-white">
          <div className="border-b border-gray-100 px-4 py-3">
            <div className="text-sm font-semibold text-gray-800">供应链威胁情报 · supply-chain-ioc.json · {iocRules.length} 条</div>
            <div className="text-xs text-gray-500">5 个子分类。每条点击可切换启用/关闭，× 移除。</div>
          </div>
          {(['suspicious_skill_pattern', 'c2_server', 'clawhavoc_name', 'clawhavoc_malware', 'malicious_domain', 'infostealer_target'] as const).map((sub) => {
            const items = iocRules.filter((r) => r.tags === sub);
            const PLACEHOLDER: Record<string, string> = {
              suspicious_skill_pattern: '加新 skill 恶意特征正则（如 atob\\()',
              c2_server: '加新 C2 IP / hostname',
              clawhavoc_name: '加新仿冒 skill 名称模式',
              clawhavoc_malware: '加新恶意软件家族名',
              malicious_domain: '加新恶意域名',
              infostealer_target: '加新需保护的敏感文件路径',
            };
            return (
              <details key={sub} className="border-t border-gray-100 first:border-t-0">
                <summary className="cursor-pointer bg-gray-50 px-4 py-2 hover:bg-gray-100 text-sm">
                  <span className="font-medium text-gray-900">{sub}</span>
                  <span className="ml-2 text-xs text-gray-500">{items.length}</span>
                </summary>
                <ul className="divide-y divide-gray-100">
                  {items.length === 0 && <li className="px-5 py-2 text-xs text-gray-400 italic">空</li>}
                  {items.map((r) => (
                    <li key={r.rule_id} className="flex items-center gap-2 px-5 py-1.5">
                      <input type="checkbox" checked={r.is_enabled} disabled={savingRuleID === r.rule_id}
                        onChange={() => persistRule({ ...r, is_enabled: !r.is_enabled })}
                        className="h-4 w-4 rounded border-gray-300" />
                      <div className="flex-1 min-w-0">
                        <InlineText value={r.pattern} onSave={(v) => persistRule({ ...r, pattern: v, display_name: v })} />
                      </div>
                      <button onClick={() => hardDeleteRule(r.rule_id)} className="text-xs text-rose-600 hover:text-rose-800">移除</button>
                    </li>
                  ))}
                </ul>
                <AddInput
                  placeholder={PLACEHOLDER[sub]}
                  onAdd={async (v) => {
                    const slug = Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
                    await persistRule({
                      rule_id: `sc.ioc.${sub}.user-${slug}`,
                      kind: 'secureclaw_ioc',
                      display_name: v,
                      pattern: v,
                      tags: sub,
                      target: 'user_input',
                      severity: 'high',
                      action: 'block',
                      mode: 'enforce',
                      is_enabled: true,
                      sort_order: 8999,
                    });
                  }}
                />
              </details>
            );
          })}
        </section>

        {/* Section 14: 告警 */}
        <section className="rounded-xl border border-gray-200 bg-white">
          <div className="flex items-center justify-between border-b border-gray-100 px-4 py-3">
            <div>
              <div className="text-sm font-semibold text-gray-800">SecureClaw 告警</div>
              <div className="text-xs text-gray-500">audit findings (severity≥medium) / credential monitor / cost monitor / kill switch — 实时从 secplane_alert 拉取，source=secureclaw</div>
            </div>
            <button onClick={loadAlerts} className="rounded border border-gray-300 bg-white px-3 py-1 text-xs text-gray-700 hover:bg-gray-50">
              刷新
            </button>
          </div>
          {alertsError && (
            <div className="m-4 rounded border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{alertsError}</div>
          )}
          <div className="overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
                <tr>
                  <th className="px-4 py-2">时间</th>
                  <th className="px-4 py-2">来源</th>
                  <th className="px-4 py-2">规则 / Defense</th>
                  <th className="px-4 py-2">严重度</th>
                  <th className="px-4 py-2">动作</th>
                  <th className="px-4 py-2">证据</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-gray-50">
                    <td className="px-4 py-2 text-xs text-gray-500">{new Date(alert.ts).toLocaleString()}</td>
                    <td className="px-4 py-2"><span className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-700">{alert.source}</span></td>
                    <td className="px-4 py-2">
                      <div className="font-medium text-gray-900">{alert.rule_name ?? alert.rule_id ?? '-'}</div>
                      {alert.rule_id && alert.rule_name && <div className="text-xs text-gray-500">{alert.rule_id}</div>}
                    </td>
                    <td className="px-4 py-2"><span className={`rounded-full border px-2 py-0.5 text-xs ${severityChip(alert.severity)}`}>{alert.severity}</span></td>
                    <td className="px-4 py-2"><span className={`rounded-full border px-2 py-0.5 text-xs ${actionPill(alert.action)}`}>{alert.action}</span></td>
                    <td className="px-4 py-2 text-xs text-gray-700">
                      <div className="max-w-md truncate" title={alert.evidence ?? ''}>{alert.evidence ?? '-'}</div>
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && !alertsLoading && (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-sm text-gray-500">暂无 SecureClaw 告警 — 等插件起来后会自动填充</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <DispatchPickerModal
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        onDispatch={runDispatch}
        dispatching={dispatching}
        title="选择 SecureClaw 下发目标实例"
        hint="把当前 secureclaw_config 编译为 user_config 并通过 install_skill 推送到选中的 OpenClaw 实例。"
      />
    </AdminLayout>
  );
};

export default SecureClawPage;
