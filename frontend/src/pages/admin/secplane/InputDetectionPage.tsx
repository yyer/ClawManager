import React, { useEffect, useMemo, useState } from 'react';
import AdminLayout from '../../../components/AdminLayout';
import {
  secplaneService,
  type SecplaneRule,
  type SecplaneAlert,
  type AlertSource,
  type Severity,
  type DispatchResult,
  type RuleMode,
} from '../../../services/secplaneService';
import { instanceService } from '../../../services/instanceService';
import type { Instance } from '../../../types/instance';

// ---------------------------------------------------------------------------
// Canonical ClawAegis taxonomy. Names + display labels must stay in sync with
// the Go side (`backend/internal/secplane/policy/model.go`) and the ClawAegis
// schema (`ClawAegis/src/config.ts`). The seed inserts one rule per row here.
// ---------------------------------------------------------------------------

interface DefenseSpec {
  name: string;
  ruleID: string;
  display: string;
  help: string;
  supportsMode: boolean;
}

const DEFENSES: DefenseSpec[] = [
  { name: 'selfProtection', display: '受保护路径访问拦截', help: '拦截读取/写入/删除/搜索 protectedPaths、protectedSkills 与 ClawAegis 源码目录的请求。', supportsMode: true, ruleID: 'defense.selfProtection' },
  { name: 'commandBlock', display: '高危命令拦截', help: '阻止 rm -rf /、curl | sh、shutdown 等明显高危 shell 模式。', supportsMode: true, ruleID: 'defense.commandBlock' },
  { name: 'encodingGuard', display: '编码/混淆载荷检测', help: '检测有界的 base64/base32/hex/url 编码载荷里隐藏的危险命令或外发逻辑。', supportsMode: true, ruleID: 'defense.encodingGuard' },
  { name: 'scriptProvenanceGuard', display: '脚本来源追踪', help: '跟踪本轮新落地的脚本，发现含高危命令或外发信号时阻止后续执行。', supportsMode: true, ruleID: 'defense.scriptProvenanceGuard' },
  { name: 'memoryGuard', display: '记忆写入审查', help: '拒绝针对 memory_store / MEMORY.md / SOUL.md / memory/ 的可疑或过大写入。', supportsMode: true, ruleID: 'defense.memoryGuard' },
  { name: 'userRiskScan', display: '用户输入风险扫描', help: '在 message_received 检测越狱、密钥外发、插件篡改类用户请求。', supportsMode: false, ruleID: 'defense.userRiskScan' },
  { name: 'skillScan', display: 'Skill 启动扫描', help: '在 ~/.openclaw/skills 与 workspace/skills 上跑轻量本地 skill 扫描。', supportsMode: false, ruleID: 'defense.skillScan' },
  { name: 'toolResultScan', display: '工具结果风险扫描', help: '扫描 toolResult 中的提示词注入、密钥窃取、外发等 pattern。', supportsMode: false, ruleID: 'defense.toolResultScan' },
  { name: 'outputRedaction', display: '敏感输出脱敏', help: '在 assistant 输出发送/落盘前屏蔽 API key、token 等敏感值。', supportsMode: false, ruleID: 'defense.outputRedaction' },
  { name: 'promptGuard', display: '提示词安全提醒注入', help: '在 before_prompt_build 注入静态/一次性安全提醒。', supportsMode: false, ruleID: 'defense.promptGuard' },
  { name: 'loopGuard', display: '工具调用循环熔断', help: '同一 run 内同参数高危 tool call 超过预算时熔断。', supportsMode: true, ruleID: 'defense.loopGuard' },
  { name: 'exfiltrationGuard', display: '外发链路检测', help: '跟踪本 run 的工具调用链，识别 SSRF / 数据外发拦截出站。', supportsMode: true, ruleID: 'defense.exfiltrationGuard' },
  { name: 'toolCallEnforcement', display: '工具调用强约束', help: '注入提示词，要求破坏性操作必须通过标准 tool call 执行。', supportsMode: false, ruleID: 'defense.toolCallEnforcement' },
  { name: 'dispatchGuard', display: '消息分发拦截', help: '在 agent 处理前拦截针对受保护资源的危险用户/LLM 消息。', supportsMode: true, ruleID: 'defense.dispatchGuard' },
];

interface FlagSpec {
  flag: string;
  ruleID: string;
  display: string;
}

const USER_RISK_FLAGS: FlagSpec[] = [
  { flag: 'jailbreak-bypass', display: '越狱/绕过守护', ruleID: 'urf.jailbreak-bypass' },
  { flag: 'system-prompt-exfiltration', display: '系统提示词窃取', ruleID: 'urf.system-prompt-exfiltration' },
  { flag: 'disable-plugin', display: '禁用安全插件', ruleID: 'urf.disable-plugin' },
  { flag: 'plugin-path-access', display: '访问插件源码路径', ruleID: 'urf.plugin-path-access' },
  { flag: 'dangerous-execution-request', display: '高危执行请求', ruleID: 'urf.dangerous-execution-request' },
  { flag: 'sensitive-secret-request', display: '敏感凭据请求', ruleID: 'urf.sensitive-secret-request' },
  { flag: 'third-party-as-instructions', display: '第三方内容当指令', ruleID: 'urf.third-party-as-instructions' },
];

const TOOL_RESULT_FLAGS: FlagSpec[] = [
  { flag: 'role-takeover', display: '角色覆盖', ruleID: 'trf.role-takeover' },
  { flag: 'policy-bypass', display: '策略绕过', ruleID: 'trf.policy-bypass' },
  { flag: 'tool-induction', display: '工具诱导', ruleID: 'trf.tool-induction' },
  { flag: 'secret-request', display: '密钥窃取请求', ruleID: 'trf.secret-request' },
  { flag: 'exfiltration-request', display: '数据外发请求', ruleID: 'trf.exfiltration-request' },
  { flag: 'remote-script-bootstrap', display: '远程脚本引导', ruleID: 'trf.remote-script-bootstrap' },
  { flag: 'remote-binary-bootstrap', display: '远程二进制引导', ruleID: 'trf.remote-binary-bootstrap' },
  { flag: 'system-prompt-leak', display: '系统提示泄漏', ruleID: 'trf.system-prompt-leak' },
  { flag: 'approval-bypass', display: '审批流程绕过', ruleID: 'trf.approval-bypass' },
  { flag: 'disable-claw-aegis', display: '禁用 ClawAegis', ruleID: 'trf.disable-claw-aegis' },
  { flag: 'high-risk-command', display: '高危命令', ruleID: 'trf.high-risk-command' },
  { flag: 'credential-exfiltration', display: '凭据外发', ruleID: 'trf.credential-exfiltration' },
];

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

type TabKey = 'defenses' | 'userRisk' | 'toolResult' | 'protected' | 'alerts';

const TABS: Array<{ key: TabKey; label: string; help: string }> = [
  { key: 'defenses', label: '防御开关', help: '14 个 ClawAegis 防御模块的总开关与运行模式' },
  { key: 'userRisk', label: '输入风险标记', help: 'userRiskScan 内置 flag 的三态控制（启用 / observe / 关闭）' },
  { key: 'toolResult', label: '工具结果检测', help: 'toolResultScan 内置 flag 的三态控制' },
  { key: 'protected', label: '受保护资源', help: '运行时受保护的 paths / skills / plugins 列表' },
  { key: 'alerts', label: '告警日志', help: '来自 ClawAegis、平台与其他防御端的统一告警流' },
];

const MODE_LABEL: Record<RuleMode, string> = {
  enforce: 'Enforce · 强制',
  observe: 'Observe · 仅观测',
  off: 'Off · 关闭',
};

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
    redacted: 'bg-amber-100 text-amber-700 border-amber-200',
    observed: 'bg-sky-100 text-sky-700 border-sky-200',
    rerouted: 'bg-indigo-100 text-indigo-700 border-indigo-200',
    allowed: 'bg-emerald-100 text-emerald-700 border-emerald-200',
    block: 'bg-rose-100 text-rose-700 border-rose-200',
    redact: 'bg-amber-100 text-amber-700 border-amber-200',
    observe: 'bg-sky-100 text-sky-700 border-sky-200',
  };
  return lookup[action] || 'bg-gray-100 text-gray-700 border-gray-200';
};

// Build a rule_id slug for protected_* rules from the user-typed value.
const slugifyResource = (kind: 'pp' | 'psk' | 'ppl', value: string): string => {
  const cleaned = value.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '_');
  const trimmed = cleaned.replace(/^_+|_+$/g, '').slice(0, 60);
  return `${kind}.${trimmed || Date.now().toString(36)}`;
};

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

const InputDetectionPage: React.FC = () => {
  const [tab, setTab] = useState<TabKey>('defenses');

  // All extended-kind rules, refreshed together so cross-tab counts stay live.
  const [defenseRules, setDefenseRules] = useState<SecplaneRule[]>([]);
  const [userRiskRules, setUserRiskRules] = useState<SecplaneRule[]>([]);
  const [toolResultRules, setToolResultRules] = useState<SecplaneRule[]>([]);
  const [protectedPaths, setProtectedPaths] = useState<SecplaneRule[]>([]);
  const [protectedSkills, setProtectedSkills] = useState<SecplaneRule[]>([]);
  const [protectedPlugins, setProtectedPlugins] = useState<SecplaneRule[]>([]);
  const [rulesLoading, setRulesLoading] = useState(true);
  const [rulesError, setRulesError] = useState<string | null>(null);

  // Alerts
  const [alerts, setAlerts] = useState<SecplaneAlert[]>([]);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [alertFilter, setAlertFilter] = useState<{ source: string; ruleID: string }>({ source: '', ruleID: '' });

  // Dispatch
  const [dispatching, setDispatching] = useState(false);
  const [dispatchResult, setDispatchResult] = useState<DispatchResult | null>(null);
  const [dispatchError, setDispatchError] = useState<string | null>(null);

  // Dispatch target picker (modal)
  const [pickerOpen, setPickerOpen] = useState(false);
  const [instances, setInstances] = useState<Instance[]>([]);
  const [instancesLoading, setInstancesLoading] = useState(false);
  const [instancesError, setInstancesError] = useState<string | null>(null);
  const [instanceFilter, setInstanceFilter] = useState('');
  const [selectedInstanceIDs, setSelectedInstanceIDs] = useState<Set<number>>(new Set());

  // Saving (per-rule) tracker so the UI can spin a single row.
  const [savingRuleID, setSavingRuleID] = useState<string | null>(null);

  // Draft inputs for each protected-resource list. Lifted to the parent so
  // hooks order stays stable across renders (renderProtectedList runs three
  // times below — it cannot own per-list state itself).
  const [protectedDrafts, setProtectedDrafts] = useState<{ pp: string; psk: string; ppl: string }>({ pp: '', psk: '', ppl: '' });

  // ---- Loaders ----------------------------------------------------------
  const loadAllRules = async () => {
    setRulesLoading(true);
    setRulesError(null);
    try {
      const [d, ur, tr, pp, psk, ppl] = await Promise.all([
        secplaneService.listRules('defense_toggle'),
        secplaneService.listRules('user_risk_flag'),
        secplaneService.listRules('tool_result_flag'),
        secplaneService.listRules('protected_path'),
        secplaneService.listRules('protected_skill'),
        secplaneService.listRules('protected_plugin'),
      ]);
      setDefenseRules(d);
      setUserRiskRules(ur);
      setToolResultRules(tr);
      setProtectedPaths(pp);
      setProtectedSkills(psk);
      setProtectedPlugins(ppl);
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
      const params: { source?: AlertSource; rule_id?: string; limit: number } = { limit: 100 };
      if (alertFilter.source) params.source = alertFilter.source as AlertSource;
      if (alertFilter.ruleID) params.rule_id = alertFilter.ruleID;
      const items = await secplaneService.listAlerts(params);
      setAlerts(items);
    } catch (e: any) {
      setAlertsError(e?.response?.data?.error ?? e?.message ?? 'failed to load alerts');
    } finally {
      setAlertsLoading(false);
    }
  };

  useEffect(() => {
    loadAllRules();
  }, []);

  useEffect(() => {
    if (tab === 'alerts') loadAlerts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  // ---- Save helpers -----------------------------------------------------
  // Index existing rules by rule_id so toggle/save can patch in place.
  const allRulesByID = useMemo(() => {
    const m = new Map<string, SecplaneRule>();
    for (const r of [...defenseRules, ...userRiskRules, ...toolResultRules, ...protectedPaths, ...protectedSkills, ...protectedPlugins]) {
      m.set(r.rule_id, r);
    }
    return m;
  }, [defenseRules, userRiskRules, toolResultRules, protectedPaths, protectedSkills, protectedPlugins]);

  // Save a single rule (existing or new). Refresh affected list afterwards.
  const persistRule = async (next: SecplaneRule) => {
    setSavingRuleID(next.rule_id);
    setRulesError(null);
    try {
      await secplaneService.saveRule(next);
      await loadAllRules();
    } catch (e: any) {
      setRulesError(e?.response?.data?.error ?? e?.message ?? 'failed to save');
    } finally {
      setSavingRuleID(null);
    }
  };

  const hardDeleteRule = async (rule_id: string) => {
    // The backend's DELETE actually flips is_enabled=false rather than DROP;
    // the protected-resources tab filters out !is_enabled rows so this feels
    // like a real delete to the user.
    setSavingRuleID(rule_id);
    try {
      await secplaneService.disableRule(rule_id);
      await loadAllRules();
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
      const result = await secplaneService.dispatchAegis(instanceIDs ?? undefined);
      setDispatchResult(result);
      setPickerOpen(false);
    } catch (e: any) {
      setDispatchError(e?.response?.data?.error ?? e?.message ?? 'dispatch failed');
    } finally {
      setDispatching(false);
    }
  };

  // openDispatchPicker eagerly loads the instance list. Cached for the
  // session — repeat opens are instant unless the user hits "刷新" inside.
  const openDispatchPicker = async () => {
    setPickerOpen(true);
    setInstanceFilter('');
    if (instances.length > 0) return;
    await loadInstances();
  };

  const loadInstances = async () => {
    setInstancesLoading(true);
    setInstancesError(null);
    try {
      // 200 is the cluster cap for openclaw instances at this stage; if a
      // deployment ever crosses that, switch to paginated fetch here.
      const resp = await instanceService.getInstances(1, 200);
      setInstances(resp.instances);
    } catch (e: any) {
      setInstancesError(e?.response?.data?.error ?? e?.message ?? 'failed to load instances');
    } finally {
      setInstancesLoading(false);
    }
  };

  const filteredInstances = useMemo(() => {
    const q = instanceFilter.trim().toLowerCase();
    if (!q) return instances;
    return instances.filter((inst) => {
      return (
        inst.name.toLowerCase().includes(q) ||
        String(inst.id).includes(q) ||
        inst.status.toLowerCase().includes(q) ||
        (inst.pod_name ?? '').toLowerCase().includes(q) ||
        inst.type.toLowerCase().includes(q)
      );
    });
  }, [instances, instanceFilter]);

  const toggleInstanceSelected = (id: number) => {
    setSelectedInstanceIDs((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAllVisible = () => {
    setSelectedInstanceIDs((prev) => {
      const next = new Set(prev);
      for (const inst of filteredInstances) next.add(inst.id);
      return next;
    });
  };

  const clearSelection = () => setSelectedInstanceIDs(new Set());

  // ---- Renderers --------------------------------------------------------

  const renderToggleRow = (
    spec: { ruleID: string; display: string; help?: string; supportsMode: boolean; defaultSeverity: Severity },
    seedTemplate: () => SecplaneRule,
  ) => {
    const existing = allRulesByID.get(spec.ruleID);
    const rule: SecplaneRule = existing ?? seedTemplate();
    const isSaving = savingRuleID === spec.ruleID;
    const isDisabled = !rule.is_enabled || rule.mode === 'off';
    return (
      <tr key={spec.ruleID} className={`hover:bg-gray-50 ${isDisabled ? 'bg-gray-50/50' : ''}`}>
        <td className="px-4 py-3 align-top">
          <div className={`font-medium ${isDisabled ? 'text-gray-500' : 'text-gray-900'}`}>{spec.display}</div>
          <div className="text-xs text-gray-500">{spec.ruleID}</div>
          {spec.help && <div className="mt-1 max-w-xl text-xs text-gray-500">{spec.help}</div>}
        </td>
        <td className="px-4 py-3 text-center">
          <button
            disabled={isSaving}
            onClick={() => persistRule({ ...rule, is_enabled: !rule.is_enabled })}
            className={`rounded-full border px-3 py-0.5 text-xs ${
              rule.is_enabled
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : 'bg-gray-100 text-gray-500 border-gray-200'
            } disabled:opacity-60`}
          >
            {isSaving ? '…' : rule.is_enabled ? 'enabled' : 'disabled'}
          </button>
        </td>
        <td className="px-4 py-3 text-center">
          {spec.supportsMode ? (
            <select
              value={rule.mode}
              disabled={isSaving || !rule.is_enabled}
              onChange={(e) => persistRule({ ...rule, mode: e.target.value as RuleMode })}
              className="rounded border border-gray-300 px-2 py-1 text-sm disabled:bg-gray-100 disabled:text-gray-400"
            >
              {(['enforce', 'observe', 'off'] as RuleMode[]).map((m) => (
                <option key={m} value={m}>{MODE_LABEL[m]}</option>
              ))}
            </select>
          ) : (
            <span className="text-xs text-gray-400" title="此防御不支持 mode 字段">—</span>
          )}
        </td>
        <td className="px-4 py-3 text-center">
          {isDisabled ? (
            <span className="text-xs text-gray-400" title="已禁用">—</span>
          ) : (
            <span className={`rounded-full border px-2 py-0.5 text-xs ${severityChip(rule.severity)}`}>{rule.severity}</span>
          )}
        </td>
      </tr>
    );
  };

  const renderDefenses = () => {
    const seedFor = (s: DefenseSpec): SecplaneRule => ({
      rule_id: s.ruleID,
      kind: 'defense_toggle',
      display_name: s.display,
      pattern: '',
      target: 'user_input',
      severity: 'medium',
      action: 'observe',
      mode: 'enforce',
      is_enabled: true,
      sort_order: 100 + DEFENSES.findIndex((d) => d.name === s.name) * 10,
    });

    // Read current state as a discrete value the segmented control renders.
    type TriState = 'off' | 'observe' | 'enforce';
    type BiState = 'off' | 'on';
    const triStateOf = (r: SecplaneRule): TriState => {
      if (!r.is_enabled || r.mode === 'off') return 'off';
      if (r.mode === 'observe') return 'observe';
      return 'enforce';
    };
    const biStateOf = (r: SecplaneRule): BiState => (r.is_enabled ? 'on' : 'off');

    // applyTri / applyBi turn a button click into a SecplaneRule patch.
    // For "off" we keep the previous mode around so flipping back to a
    // non-off state restores the operator's last choice instead of always
    // defaulting to enforce.
    const applyTri = (r: SecplaneRule, next: TriState): SecplaneRule => {
      switch (next) {
        case 'off':
          return { ...r, is_enabled: false };
        case 'observe':
          return { ...r, is_enabled: true, mode: 'observe' };
        case 'enforce':
          return { ...r, is_enabled: true, mode: 'enforce' };
      }
    };
    const applyBi = (r: SecplaneRule, next: BiState): SecplaneRule => ({
      ...r,
      is_enabled: next === 'on',
      mode: 'enforce',
    });

    const SegBtn: React.FC<{
      active: boolean;
      disabled?: boolean;
      tone: 'off' | 'observe' | 'enforce' | 'on';
      onClick: () => void;
      children: React.ReactNode;
    }> = ({ active, disabled, tone, onClick, children }) => {
      const activeClass = {
        off: 'bg-gray-700 text-white',
        observe: 'bg-amber-500 text-white',
        enforce: 'bg-emerald-600 text-white',
        on: 'bg-emerald-600 text-white',
      }[tone];
      return (
        <button
          disabled={disabled}
          onClick={onClick}
          className={`px-3 py-1 text-xs transition first:rounded-l-md last:rounded-r-md ${
            active ? activeClass : 'bg-white text-gray-600 hover:bg-gray-50'
          } disabled:opacity-60 disabled:cursor-not-allowed`}
        >
          {children}
        </button>
      );
    };

    const renderTriRow = (d: DefenseSpec) => {
      const existing = allRulesByID.get(d.ruleID);
      const rule: SecplaneRule = existing ?? seedFor(d);
      const state = triStateOf(rule);
      const isSaving = savingRuleID === d.ruleID;
      return (
        <tr key={d.ruleID} className={`hover:bg-gray-50 ${state === 'off' ? 'bg-gray-50/50' : ''}`}>
          <td className="px-4 py-3 align-top">
            <div className={`font-medium ${state === 'off' ? 'text-gray-500' : 'text-gray-900'}`}>{d.display}</div>
            <div className="mt-0.5 text-xs text-gray-500">{d.help}</div>
            <div className="mt-0.5 font-mono text-[10px] text-gray-400">{d.ruleID}</div>
          </td>
          <td className="px-4 py-3 text-right">
            <div className="inline-flex divide-x divide-gray-300 overflow-hidden rounded-md border border-gray-300">
              <SegBtn tone="off" active={state === 'off'} disabled={isSaving}
                onClick={() => persistRule(applyTri(rule, 'off'))}>Off</SegBtn>
              <SegBtn tone="observe" active={state === 'observe'} disabled={isSaving}
                onClick={() => persistRule(applyTri(rule, 'observe'))}>Observe</SegBtn>
              <SegBtn tone="enforce" active={state === 'enforce'} disabled={isSaving}
                onClick={() => persistRule(applyTri(rule, 'enforce'))}>Enforce</SegBtn>
            </div>
          </td>
        </tr>
      );
    };

    const renderBiRow = (d: DefenseSpec) => {
      const existing = allRulesByID.get(d.ruleID);
      const rule: SecplaneRule = existing ?? seedFor(d);
      const state = biStateOf(rule);
      const isSaving = savingRuleID === d.ruleID;
      return (
        <tr key={d.ruleID} className={`hover:bg-gray-50 ${state === 'off' ? 'bg-gray-50/50' : ''}`}>
          <td className="px-4 py-3 align-top">
            <div className={`font-medium ${state === 'off' ? 'text-gray-500' : 'text-gray-900'}`}>{d.display}</div>
            <div className="mt-0.5 text-xs text-gray-500">{d.help}</div>
            <div className="mt-0.5 font-mono text-[10px] text-gray-400">{d.ruleID}</div>
          </td>
          <td className="px-4 py-3 text-right">
            <div className="inline-flex divide-x divide-gray-300 overflow-hidden rounded-md border border-gray-300">
              <SegBtn tone="off" active={state === 'off'} disabled={isSaving}
                onClick={() => persistRule(applyBi(rule, 'off'))}>Off</SegBtn>
              <SegBtn tone="on" active={state === 'on'} disabled={isSaving}
                onClick={() => persistRule(applyBi(rule, 'on'))}>On</SegBtn>
            </div>
          </td>
        </tr>
      );
    };

    const modeSupporting = DEFENSES.filter((d) => d.supportsMode);
    const booleanOnly = DEFENSES.filter((d) => !d.supportsMode);

    return (
      <div className="space-y-4">
        <div className="rounded-lg bg-blue-50 p-3 text-xs text-blue-700">
          每个开关对应一个 ClawAegis 内置防御模块。修改后点上方"下发到实例"即可热重载 — 无需重启 gateway。
          <span className="ml-1 text-blue-900/70">Enforce</span> = 拦截 + 注入 LLM 提示词；
          <span className="ml-1 text-blue-900/70">Observe</span> = 仅写告警，LLM 行为不变；
          <span className="ml-1 text-blue-900/70">Off</span> = 整模块不跑。
        </div>

        <section className="overflow-hidden rounded-xl border border-gray-200 bg-white">
          <div className="border-b border-gray-200 bg-gray-50 px-4 py-2">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-600">支持观测模式 · 8 个</div>
            <div className="text-xs text-gray-500">这些防御可在 enforce / observe 两种强度之间切换</div>
          </div>
          <table className="min-w-full divide-y divide-gray-100">
            <tbody className="divide-y divide-gray-100">
              {modeSupporting.map(renderTriRow)}
            </tbody>
          </table>
        </section>

        <section className="overflow-hidden rounded-xl border border-gray-200 bg-white">
          <div className="border-b border-gray-200 bg-gray-50 px-4 py-2">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-600">仅开关 · 6 个</div>
            <div className="text-xs text-gray-500">这些防御没有 observe 中间态 — 要么开启，要么关闭</div>
          </div>
          <table className="min-w-full divide-y divide-gray-100">
            <tbody className="divide-y divide-gray-100">
              {booleanOnly.map(renderBiRow)}
            </tbody>
          </table>
        </section>
      </div>
    );
  };

  const renderFlagTab = (
    title: string,
    explainer: string,
    flags: FlagSpec[],
    kind: 'user_risk_flag' | 'tool_result_flag',
    pool: SecplaneRule[],
  ) => {
    const seedFor = (s: FlagSpec, idx: number): SecplaneRule => ({
      rule_id: s.ruleID,
      kind,
      display_name: s.display,
      pattern: '',
      target: kind === 'user_risk_flag' ? 'user_input' : 'tool_output',
      severity: 'high',
      action: 'block',
      mode: 'enforce',
      is_enabled: true,
      sort_order: (kind === 'user_risk_flag' ? 300 : 500) + idx * 10,
    });
    return (
      <div className="space-y-3">
        <div className="rounded-lg bg-blue-50 p-3 text-xs text-blue-700">{explainer}</div>
        <div className="overflow-hidden rounded-xl border border-gray-200 bg-white">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-3">{title}</th>
                <th className="px-4 py-3 text-center">启用</th>
                <th className="px-4 py-3 text-center">模式（三态）</th>
                <th className="px-4 py-3 text-center">严重度</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {flags.map((f, idx) =>
                renderToggleRow(
                  { ruleID: f.ruleID, display: f.display, supportsMode: true, defaultSeverity: 'high' },
                  () => seedFor(f, idx),
                ),
              )}
            </tbody>
          </table>
        </div>
        <div className="text-xs text-gray-500">当前共 {pool.length} 条 {kind} 规则在数据库中。</div>
      </div>
    );
  };

  const renderProtectedList = (
    title: string,
    placeholder: string,
    pool: SecplaneRule[],
    kindShort: 'pp' | 'psk' | 'ppl',
    kindLong: 'protected_path' | 'protected_skill' | 'protected_plugin',
  ) => {
    const visible = pool.filter((r) => r.is_enabled);
    const draft = protectedDrafts[kindShort];
    const setDraft = (next: string) => setProtectedDrafts((prev) => ({ ...prev, [kindShort]: next }));
    const handleAdd = async () => {
      const value = draft.trim();
      if (!value) return;
      const ruleID = slugifyResource(kindShort, value);
      const next: SecplaneRule = {
        rule_id: ruleID,
        kind: kindLong,
        display_name: value,
        pattern: value,
        target: 'user_input',
        severity: 'high',
        action: 'block',
        mode: 'enforce',
        is_enabled: true,
        sort_order: 700,
      };
      await persistRule(next);
      setDraft('');
    };
    return (
      <div className="rounded-xl border border-gray-200 bg-white p-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="text-sm font-semibold text-gray-800">{title}</div>
          <span className="text-xs text-gray-500">{visible.length} 项生效</span>
        </div>
        <div className="mb-3 flex gap-2">
          <input
            type="text"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={placeholder}
            className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm"
            onKeyDown={(e) => { if (e.key === 'Enter') handleAdd(); }}
          />
          <button
            disabled={!draft.trim()}
            onClick={handleAdd}
            className="rounded bg-indigo-600 px-3 py-2 text-sm text-white hover:bg-indigo-700 disabled:opacity-60"
          >
            添加
          </button>
        </div>
        <ul className="space-y-1">
          {visible.map((r) => (
            <li key={r.rule_id} className="flex items-center gap-2 rounded border border-gray-200 bg-gray-50 px-3 py-2">
              <code className="flex-1 truncate font-mono text-xs text-gray-700" title={r.pattern}>{r.pattern}</code>
              <button
                disabled={savingRuleID === r.rule_id}
                onClick={() => hardDeleteRule(r.rule_id)}
                className="text-xs text-rose-600 hover:text-rose-800 disabled:opacity-60"
              >
                {savingRuleID === r.rule_id ? '…' : '移除'}
              </button>
            </li>
          ))}
          {visible.length === 0 && <li className="text-xs text-gray-500">无配置项。</li>}
        </ul>
      </div>
    );
  };

  const renderProtected = () => (
    <div className="grid gap-4 lg:grid-cols-3">
      {renderProtectedList('受保护路径 (protectedPaths)', '/path/to/protect', protectedPaths, 'pp', 'protected_path')}
      {renderProtectedList('受保护 Skills', 'release-guard', protectedSkills, 'psk', 'protected_skill')}
      {renderProtectedList('受保护 Plugins', 'audit-guard', protectedPlugins, 'ppl', 'protected_plugin')}
    </div>
  );

  const renderAlerts = () => (
    <div className="space-y-3">
      <div className="rounded-xl border border-gray-200 bg-white p-3">
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-sm text-gray-700">来源
            <select
              value={alertFilter.source}
              onChange={(e) => setAlertFilter({ ...alertFilter, source: e.target.value })}
              className="ml-2 rounded border border-gray-300 px-2 py-1 text-sm"
            >
              <option value="">全部</option>
              <option value="aegis">aegis（Pod 端 ClawAegis）</option>
              <option value="platform">platform（平台测试）</option>
              <option value="gateway">gateway</option>
              <option value="secureclaw">secureclaw</option>
              <option value="ksecure">ksecure</option>
              <option value="kubearmor">kubearmor</option>
            </select>
          </label>
          <label className="text-sm text-gray-700">规则 ID
            <input
              type="text"
              value={alertFilter.ruleID}
              onChange={(e) => setAlertFilter({ ...alertFilter, ruleID: e.target.value })}
              placeholder="user_risk_scan / tool_result_scan / ..."
              className="ml-2 w-64 rounded border border-gray-300 px-2 py-1 text-sm"
            />
          </label>
          <button
            onClick={loadAlerts}
            className="ml-auto rounded border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
          >
            刷新
          </button>
        </div>
      </div>
      {alertsError && <div className="rounded border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{alertsError}</div>}
      <div className="overflow-hidden rounded-xl border border-gray-200 bg-white">
        <table className="min-w-full divide-y divide-gray-200 text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-3">时间</th>
              <th className="px-4 py-3">来源</th>
              <th className="px-4 py-3">规则 / Defense</th>
              <th className="px-4 py-3">严重度</th>
              <th className="px-4 py-3">动作</th>
              <th className="px-4 py-3">证据</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {alerts.map((alert) => (
              <tr key={alert.id} className="hover:bg-gray-50">
                <td className="px-4 py-3 text-xs text-gray-500">{new Date(alert.ts).toLocaleString()}</td>
                <td className="px-4 py-3"><span className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-700">{alert.source}</span></td>
                <td className="px-4 py-3">
                  <div className="font-medium text-gray-900">{alert.rule_name ?? alert.rule_id ?? '-'}</div>
                  {alert.rule_id && alert.rule_name && <div className="text-xs text-gray-500">{alert.rule_id}</div>}
                </td>
                <td className="px-4 py-3"><span className={`rounded-full border px-2 py-0.5 text-xs ${severityChip(alert.severity)}`}>{alert.severity}</span></td>
                <td className="px-4 py-3"><span className={`rounded-full border px-2 py-0.5 text-xs ${actionPill(alert.action)}`}>{alert.action}</span></td>
                <td className="px-4 py-3 text-xs text-gray-700">
                  <div className="max-w-md truncate" title={alert.evidence ?? ''}>{alert.evidence ?? '-'}</div>
                </td>
              </tr>
            ))}
            {alerts.length === 0 && !alertsLoading && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-sm text-gray-500">暂无告警事件</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );

  // ---- Top-level layout -------------------------------------------------
  return (
    <AdminLayout title="智能安全防护 / Secplane Aegis">
      <div className="space-y-4">
        <div className="rounded-xl border border-gray-200 bg-white p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-indigo-600">claw-aegis · secplane</div>
              <div className="mt-1 text-2xl font-semibold text-gray-900">智能安全防护</div>
              <div className="mt-1 text-sm text-gray-600">
                统一管理 ClawAegis 14 个防御模块、{USER_RISK_FLAGS.length + TOOL_RESULT_FLAGS.length} 个内置 flag、受保护资源列表，以及来自 Pod 与平台的告警流。规则修改后点击右上"下发到实例"即可热重载至所有运行中的 OpenClaw 实例。
              </div>
            </div>
            <button
              onClick={openDispatchPicker}
              disabled={dispatching}
              className="shrink-0 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-indigo-700 disabled:opacity-60"
              title="选择目标实例并下发 ClawAegis user_config"
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
              <div className="mt-2 text-gray-500">
                ClawAegis 会在 ≤1s 自动 hot-reload 新 user_config（无需重启 OpenClaw）。
              </div>
            </div>
          )}
        </div>

        {rulesError && <div className="rounded border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{rulesError}</div>}

        <div className="flex flex-wrap gap-1 border-b border-gray-200">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-4 py-2 text-sm transition ${
                tab === t.key
                  ? 'border-b-2 border-indigo-500 text-indigo-600 font-medium'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
              title={t.help}
            >
              {t.label}
            </button>
          ))}
          {rulesLoading && <span className="ml-auto self-center text-xs text-gray-500">加载中…</span>}
        </div>

        <div>
          {tab === 'defenses' && renderDefenses()}
          {tab === 'userRisk' && renderFlagTab(
            'userRiskScan 内置 flag',
            '每条 flag 三态：启用+enforce（默认，全力拦截+提示词加固）/ 启用+observe（仅记录告警，不影响 LLM）/ 关闭（完全屏蔽）。',
            USER_RISK_FLAGS,
            'user_risk_flag',
            userRiskRules,
          )}
          {tab === 'toolResult' && renderFlagTab(
            'toolResultScan 内置 flag',
            '在 toolResult / 第三方网页内容 / 编码 payload 中匹配的 flag。三态语义同 userRiskScan。',
            TOOL_RESULT_FLAGS,
            'tool_result_flag',
            toolResultRules,
          )}
          {tab === 'protected' && renderProtected()}
          {tab === 'alerts' && renderAlerts()}
        </div>
      </div>

      {pickerOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
          <div className="flex max-h-[85vh] w-full max-w-3xl flex-col rounded-xl bg-white shadow-xl">
            <div className="flex items-center justify-between border-b border-gray-200 px-5 py-3">
              <div>
                <div className="text-base font-semibold text-gray-900">选择下发目标实例</div>
                <div className="text-xs text-gray-500">
                  把当前规则编译为 ClawAegis user_config，通过 install_skill 推送到选中的 OpenClaw 实例。
                </div>
              </div>
              <button
                onClick={() => setPickerOpen(false)}
                className="rounded p-1 text-gray-500 hover:bg-gray-100 hover:text-gray-800"
                aria-label="关闭"
              >
                ✕
              </button>
            </div>

            <div className="border-b border-gray-200 px-5 py-3">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-[200px]">
                  <input
                    type="text"
                    value={instanceFilter}
                    onChange={(e) => setInstanceFilter(e.target.value)}
                    placeholder="按名称 / ID / 状态 / pod / 类型 过滤…"
                    className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
                  />
                </div>
                <button
                  onClick={selectAllVisible}
                  disabled={filteredInstances.length === 0}
                  className="rounded border border-gray-300 bg-white px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-60"
                >
                  全选当前 ({filteredInstances.length})
                </button>
                <button
                  onClick={clearSelection}
                  disabled={selectedInstanceIDs.size === 0}
                  className="rounded border border-gray-300 bg-white px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-60"
                >
                  清空 ({selectedInstanceIDs.size})
                </button>
                <button
                  onClick={loadInstances}
                  className="rounded border border-gray-300 bg-white px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50"
                >
                  刷新
                </button>
              </div>
              <div className="mt-2 text-xs text-gray-500">
                共 {instances.length} 个实例；过滤命中 {filteredInstances.length}；已选 {selectedInstanceIDs.size}
              </div>
            </div>

            <div className="flex-1 overflow-y-auto">
              {instancesLoading && <div className="p-6 text-center text-sm text-gray-500">加载中…</div>}
              {instancesError && (
                <div className="m-5 rounded border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{instancesError}</div>
              )}
              {!instancesLoading && filteredInstances.length === 0 && (
                <div className="p-6 text-center text-sm text-gray-500">
                  {instances.length === 0 ? '暂无实例' : '当前过滤条件无匹配实例'}
                </div>
              )}
              <ul className="divide-y divide-gray-100">
                {filteredInstances.map((inst) => {
                  const checked = selectedInstanceIDs.has(inst.id);
                  const statusTone = {
                    running: 'bg-emerald-100 text-emerald-700 border-emerald-200',
                    stopped: 'bg-gray-100 text-gray-600 border-gray-200',
                    creating: 'bg-sky-100 text-sky-700 border-sky-200',
                    deleting: 'bg-amber-100 text-amber-700 border-amber-200',
                    error: 'bg-rose-100 text-rose-700 border-rose-200',
                  }[inst.status] ?? 'bg-gray-100 text-gray-600 border-gray-200';
                  const notRunning = inst.status !== 'running';
                  return (
                    <li key={inst.id}>
                      <label className={`flex cursor-pointer items-center gap-3 px-5 py-3 hover:bg-gray-50 ${checked ? 'bg-indigo-50/50' : ''}`}>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleInstanceSelected(inst.id)}
                          className="h-4 w-4 rounded border-gray-300"
                        />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="truncate font-medium text-gray-900">{inst.name}</span>
                            <span className="text-xs text-gray-500">#{inst.id}</span>
                            <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase ${statusTone}`}>{inst.status}</span>
                            <span className="rounded bg-gray-100 px-2 py-0.5 text-[10px] text-gray-600">{inst.type}</span>
                            {notRunning && <span className="text-[10px] text-amber-600" title="非 running 状态的实例下发后可能在启动后才应用">⚠ 未运行</span>}
                          </div>
                          {inst.pod_name && (
                            <div className="mt-0.5 text-xs text-gray-500">
                              <span className="font-mono">{inst.pod_namespace}/{inst.pod_name}</span>
                              {inst.pod_ip && <span className="ml-2">{inst.pod_ip}</span>}
                            </div>
                          )}
                        </div>
                      </label>
                    </li>
                  );
                })}
              </ul>
            </div>

            <div className="flex items-center justify-between border-t border-gray-200 px-5 py-3">
              <div className="text-xs text-gray-500">
                {selectedInstanceIDs.size > 0
                  ? `将下发到选中的 ${selectedInstanceIDs.size} 个实例`
                  : '未选择任何实例 — 可改为下发到全部'}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPickerOpen(false)}
                  className="rounded border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
                >
                  取消
                </button>
                <button
                  onClick={() => runDispatch(null)}
                  disabled={dispatching || instances.length === 0}
                  className="rounded border border-indigo-300 bg-white px-3 py-1.5 text-sm text-indigo-700 hover:bg-indigo-50 disabled:opacity-60"
                  title="不带 instance_ids，由后端选取所有实例"
                >
                  {dispatching ? '下发中…' : `下发到全部 (${instances.length})`}
                </button>
                <button
                  onClick={() => runDispatch(Array.from(selectedInstanceIDs))}
                  disabled={dispatching || selectedInstanceIDs.size === 0}
                  className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white hover:bg-indigo-700 disabled:opacity-60"
                >
                  {dispatching ? '下发中…' : `下发到选中 (${selectedInstanceIDs.size})`}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </AdminLayout>
  );
};

export default InputDetectionPage;
