import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';
import ApplyDispatchButton from '../../../../components/secplane/ApplyDispatchButton';
import { secplaneService, type SecplaneRule } from '../../../../services/secplaneService';
import { useSurfaceBackend } from './useSurfaceBackend';

// 资产防篡改 (scenario f) — 对齐 KSecForAIDemo/scenario-f-asset.html
// 接 backend：3 项 defense_toggle (memoryGuard/loopGuard/selfProtection) + dispatchAegisApply + alerts
// 运维追加的 protectedPaths/Skills/Plugins 走 secplane policy_rule (kind=protected_*)，
// add / remove 立即 upsert 到 backend；下方 ApplyDispatch 把当前规则编译进 user_config 推送。

const CUSTOM_KINDS = [
  { kind: 'protected_path' as const,   name: 'Protected Paths',   field: 'protectedPaths · 路径数组',   badge: 'orange' as const, placeholder: '/path/to/protected', hint: '智能体决策时阻止读/写/删/搜该路径',                idPrefix: 'pp.' },
  { kind: 'protected_skill' as const,  name: 'Protected Skills',  field: 'protectedSkills · 技能 ID 数组', badge: 'purple' as const, placeholder: 'release-guard',     hint: '阻止智能体卸载 / 替换 / 篡改该可信技能',           idPrefix: 'psk.' },
  { kind: 'protected_plugin' as const, name: 'Protected Plugins', field: 'protectedPlugins · 插件 ID 数组', badge: 'green' as const,  placeholder: 'audit-guard',       hint: '阻止智能体卸载 / 替换 / 篡改该核心插件',           idPrefix: 'ppl.' },
];
type CustomKind = (typeof CUSTOM_KINDS)[number]['kind'];

async function sha8(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 8);
}

const ALERT_PREFIXES = ['defense.memoryGuard', 'defense.loopGuard', 'defense.selfProtection', 'pp.', 'psk.', 'ppl.'];

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green' | 'slate';
type Mode = 'enforce' | 'observe' | 'off';
type AssetKind = 'memory' | 'skill' | 'plugin' | 'credential';

// [ruleId, name, flag, desc, hook, tone, default-count, pattern]
const RULES: Array<[string, string, string, string, string, Tone, number, string]> = [
  ['defense.memoryGuard', '记忆完整性', 'memoryGuardEnabled + memoryGuardMode', '拒绝对 memory_store / MEMORY.md / SOUL.md / memory/ 的可疑或超大写入', 'before_tool_call · before_message_write', 'red', 23, 'target ∈ {memory_store, MEMORY.md, SOUL.md, memory/**}'],
  ['defense.loopGuard', '循环写入兜底', 'loopGuardEnabled + loopGuardMode', '限制单次运行内重复变更工具次数 — memory_store 属 LOOP_GUARD_TOOL_NAMES', 'before_tool_call', 'red', 4, 'memory_store ∈ LOOP_GUARD_TOOL_NAMES · retry > budget / run'],
  ['defense.selfProtection', '受保护资产', 'selfProtectionEnabled + selfProtectionMode', '拦截对 protectedPaths / protectedSkills / protectedPlugins 的读/写/删/搜', 'before_tool_call', 'red', 7, 'skill ∈ {claude-skill-v2}; plugin ∈ {@openclaw/auth}'],
];

const CORE_ASSETS: Array<[string, string, AssetKind, string, 'realtime' | 'install' | 'manual']> = [
  ['skill:claude-skill-v2', '可信技能', 'skill', 'skill-scanner 预安装扫描 · 检测 eval/exec/reverse-shell', 'install'],
  ['plugin:@openclaw/auth', '核心插件', 'plugin', 'L1 Audit · plugin 类 checks(56 项静态审计之一)', 'manual'],
  ['memory_store/', '记忆存储', 'memory', 'memory-integrity SHA-256', 'realtime'],
  ['~/.openclaw/SOUL.md', '智能体灵魂', 'memory', 'memory-integrity SHA-256 + 注入正则', 'realtime'],
  ['~/.openclaw/MEMORY.md', '长程记忆', 'memory', 'memory-integrity SHA-256 + 注入正则', 'realtime'],
  ['<stateDir>/memory/*.md', '分片记忆', 'memory', 'memory-integrity 4 级告警', 'realtime'],
  ['<stateDir>/credentials/', '凭据目录', 'credential', 'credential-monitor chokidar · add/change/unlink', 'realtime'],
  ['<stateDir>/.env', '环境变量', 'credential', 'credential-monitor chokidar · 权限位变化', 'realtime'],
];

const DRIFT_CHECKS: Array<[string, string, string, 'drift' | 'ok', Tone, string]> = [
  ['<stateDir>/memory/SOUL.md', 'openclaw-prod-east-12', '24m', 'drift', 'red', '基线 hash 不匹配 · 含可疑注入字符串'],
  ['<stateDir>/memory/MEMORY.md', 'openclaw-finance-svc', '1h', 'drift', 'red', '基线 hash 不匹配'],
  ['<stateDir>/skill/auth-helper/SKILL.md', 'openclaw-ops-bot-3', '3h', 'drift', 'orange', '文件大小变化'],
  ['<stateDir>/baseline/credentials.sha256', '所有实例', '5h', 'ok', 'green', '一致（24 项基线全匹配）'],
  ['<stateDir>/plugin/auth/manifest.json', 'openclaw-staging-7', '6h', 'ok', 'green', '一致'],
];

const MEMORY_ALERTS: Array<[string, string, string, string, string, Tone]> = [
  ['刚刚', 'prod-east-12', 'SOUL.md', '基线漂移 + DAN 注入命中', '严重', 'red'],
  ['8m', 'finance-svc', 'MEMORY.md', '基线漂移', '高', 'orange'],
  ['25m', 'ops-bot-3', 'memory/task-12.md', '注入正则 prompt-injection-3', '中', 'amber'],
  ['1h', 'staging-7', 'memory/notes.md', '基线一致', '提示', 'green'],
  ['3h', 'mcp-router', 'SOUL.md', '基线一致', '提示', 'green'],
];

const assetBadge = (k: AssetKind) =>
  k === 'memory' ? 'badge-orange' : k === 'skill' ? 'badge-purple' : k === 'plugin' ? 'badge-green' : 'badge-red';

const autoBadge = (a: 'realtime' | 'install' | 'manual') =>
  a === 'realtime'
    ? { class: 'badge-green', label: '🟢 实时自动' }
    : a === 'install'
    ? { class: 'badge-orange', label: '🟡 装时一次' }
    : { class: 'badge-red', label: '🔴 手动 / CI' };

const AssetProtectionPage: React.FC = () => {
  const { alerts, dispatching, dispatchMsg, modeOf, setMode: setRuleMode, dispatchApply } = useSurfaceBackend(ALERT_PREFIXES);
  const [customMode, setCustomMode] = useState<Mode>('enforce');
  const [customRules, setCustomRules] = useState<Record<CustomKind, SecplaneRule[]>>({
    protected_path: [],
    protected_skill: [],
    protected_plugin: [],
  });
  const [customInputs, setCustomInputs] = useState<Record<CustomKind, string>>({
    protected_path: '',
    protected_skill: '',
    protected_plugin: '',
  });
  const [customBusy, setCustomBusy] = useState(false);
  const [customError, setCustomError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [p, s, pl] = await Promise.all(
          CUSTOM_KINDS.map((k) => secplaneService.listRules(k.kind)),
        );
        setCustomRules({
          protected_path: p.filter((r) => r.is_enabled),
          protected_skill: s.filter((r) => r.is_enabled),
          protected_plugin: pl.filter((r) => r.is_enabled),
        });
      } catch {
        // ignore — UI 仍可手动添加；下次 dispatch 会重新拉
      }
    })();
  }, []);

  const addCustomItem = async (cfg: (typeof CUSTOM_KINDS)[number]) => {
    const pattern = customInputs[cfg.kind].trim();
    if (!pattern) return;
    setCustomBusy(true);
    setCustomError(null);
    try {
      const id = `${cfg.idPrefix}${await sha8(pattern)}`;
      const displayName = pattern.length > 60 ? `${pattern.slice(0, 60)}…` : pattern;
      const saved = await secplaneService.saveRule({
        rule_id: id,
        kind: cfg.kind,
        display_name: displayName,
        pattern,
        target: 'user_input',
        severity: 'medium',
        action: 'block',
        mode: customMode,
        is_enabled: true,
        sort_order: 0,
      });
      setCustomRules((prev) => {
        const list = prev[cfg.kind];
        const next = list.some((r) => r.rule_id === saved.rule_id)
          ? list.map((r) => (r.rule_id === saved.rule_id ? saved : r))
          : [...list, saved];
        return { ...prev, [cfg.kind]: next };
      });
      setCustomInputs((prev) => ({ ...prev, [cfg.kind]: '' }));
    } catch (e) {
      setCustomError(e instanceof Error ? e.message : String(e));
    } finally {
      setCustomBusy(false);
    }
  };

  const removeCustomItem = async (kind: CustomKind, rule: SecplaneRule) => {
    setCustomBusy(true);
    setCustomError(null);
    try {
      await secplaneService.disableRule(rule.rule_id);
      setCustomRules((prev) => ({
        ...prev,
        [kind]: prev[kind].filter((r) => r.rule_id !== rule.rule_id),
      }));
    } catch (e) {
      setCustomError(e instanceof Error ? e.message : String(e));
    } finally {
      setCustomBusy(false);
    }
  };

  return (
    <AdminLayout title="安全防护">
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/runtime">智能体运行时安全</Link>
          <span>/</span>
          <span className="crumb-current">资产防篡改</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">关键文件/配置防篡改</div>
            <h2 className="h-title">资产防篡改</h2>
            <p className="h-subtitle">守护智能体的记忆、技能、插件与凭据 — 实时阻断恶意变更，留存完整访问追溯。</p>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="stat-card">
              <div className="stat-card-label">受保护智能体资产</div>
              <div className="stat-card-value">38</div>
              <div className="stat-card-sub muted-strong">8 关键资产 + 30 内置路径</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">24h 拦截</div>
              <div className="stat-card-value tone-red">33</div>
              <div className="stat-card-sub muted-strong">ClawAegisEx 应用层全部命中</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">Hash 漂移</div>
              <div className="stat-card-value tone-orange">3</div>
              <div className="stat-card-sub muted-strong">secureclaw 需调查 · 最早 3h 前</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">凭据告警</div>
              <div className="stat-card-value tone-red">5</div>
              <div className="stat-card-sub muted-strong">credential-monitor · 24h</div>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="flex items-center justify-between mb-4 gap-4">
            <div>
              <div className="eyebrow">资产防护三态规则 · 3 项独立配置</div>
              <h3 className="section-title-lg mt-1">资产防护规则配置</h3>
            </div>
            <ApplyDispatchButton onDispatch={dispatchApply} busy={dispatching} className="btn-primary btn-sm" triggerLabel="保存并应用" />
            {dispatchMsg && <span className="text-xs muted ml-2">{dispatchMsg}</span>}
          </div>
          <div className="space-y-2.5">
            {RULES.map(([ruleId, name, flag, desc, hook, tone, count, pat]) => {
              const curMode = modeOf(ruleId, 'enforce');
              const realHits = alerts.filter((a) => a.rule_id?.startsWith(ruleId)).length;
              return (
                <div key={ruleId} className="flex items-center gap-4 p-4 rounded-2xl border border-[#eadfd8] bg-white">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="font-semibold text-[#171212]">{name}</span>
                      <code className="text-[10px] muted-strong tracking-wider">{flag}</code>
                      <code className="text-[10px] text-[#7a4a30] bg-[#fdf6f1] px-1.5 py-0.5 rounded">{hook}</code>
                    </div>
                    <div className="text-xs muted mb-1">{desc}</div>
                    <code className="block text-[10px] muted-strong bg-[#fdf6f1] px-2 py-1 rounded font-mono truncate" style={{ maxWidth: 480 }}>{pat}</code>
                  </div>
                  <div className="shrink-0">
                    <div className="mode-selector">
                      <button className={curMode === 'enforce' ? 'active-enforce' : ''} onClick={() => setRuleMode(ruleId, 'enforce')}>拦截</button>
                      <button className={curMode === 'observe' ? 'active-observe' : ''} onClick={() => setRuleMode(ruleId, 'observe')}>监控</button>
                      <button className={curMode === 'off' ? 'active-off' : ''} onClick={() => setRuleMode(ruleId, 'off')}>停止</button>
                    </div>
                  </div>
                  <div className="text-right shrink-0 flex flex-col items-end gap-1.5" style={{ minWidth: 80 }}>
                    <div>
                      <div className={`text-lg font-bold tone-${tone} leading-none`}>{realHits || count}</div>
                      <div className="text-xs muted-strong mt-0.5">24h 拦截</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="panel">
          <div className="flex items-center justify-between mb-4 gap-4">
            <div>
              <div className="eyebrow">业务自定义防护资产 · 3 类</div>
              <h3 className="section-title-lg mt-1">运维追加的 protectedPaths / Skills / Plugins</h3>
            </div>
            <div className="shrink-0 flex items-center gap-3">
              <div className="mode-selector" title="选择新添加项的初始模式；已存在项保持原模式">
                <button className={customMode === 'enforce' ? 'active-enforce' : ''} onClick={() => setCustomMode('enforce')}>拦截</button>
                <button className={customMode === 'observe' ? 'active-observe' : ''} onClick={() => setCustomMode('observe')}>监控</button>
                <button className={customMode === 'off' ? 'active-off' : ''} onClick={() => setCustomMode('off')}>停止</button>
              </div>
              <ApplyDispatchButton
                onDispatch={dispatchApply}
                busy={dispatching || customBusy}
                className="btn-primary btn-sm"
                triggerLabel="保存并应用"
              />
            </div>
          </div>
          {customError && (
            <div className="mb-3 rounded border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">{customError}</div>
          )}
          <div className="space-y-3">
            {CUSTOM_KINDS.map((cfg) => {
              const items = customRules[cfg.kind];
              return (
                <div key={cfg.kind} className="p-4 rounded-2xl border border-[#eadfd8] bg-white">
                  <div className="flex items-center justify-between mb-2.5 gap-3 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-[#171212]">{cfg.name}</span>
                      <code className="text-[10px] muted-strong tracking-wider">{cfg.field}</code>
                      <span className={`badge badge-${cfg.badge} text-[10px]`}>{items.length} 项</span>
                    </div>
                    <div className="flex gap-2 items-center">
                      <input
                        className="input"
                        placeholder={cfg.placeholder}
                        style={{ width: 200, height: 30, fontSize: 12 }}
                        value={customInputs[cfg.kind]}
                        onChange={(e) => setCustomInputs((p) => ({ ...p, [cfg.kind]: e.target.value }))}
                        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void addCustomItem(cfg); } }}
                        disabled={customBusy}
                      />
                      <button
                        className="btn-primary btn-sm"
                        onClick={() => void addCustomItem(cfg)}
                        disabled={customBusy || !customInputs[cfg.kind].trim()}
                      >
                        + 添加
                      </button>
                    </div>
                  </div>
                  <div className="text-xs muted mb-2">{cfg.hint}</div>
                  <div className="flex flex-wrap gap-2">
                    {items.length === 0 && <span className="text-xs muted">（暂无）</span>}
                    {items.map((r) => (
                      <span
                        key={r.rule_id}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono"
                        style={{ background: '#fdf6f1', border: '1px solid #eadfd8', color: '#7a4a30' }}
                        title={`mode=${r.mode}`}
                      >
                        {r.pattern}
                        <button
                          className="text-[#dc2626] hover:text-[#991b1b] text-sm leading-none ml-1 font-bold disabled:opacity-50"
                          onClick={() => void removeCustomItem(cfg.kind, r)}
                          disabled={customBusy}
                          aria-label={`移除 ${r.pattern}`}
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
          <div className="text-xs muted mt-4 pt-3 border-t border-[#eadfd8]">
            本面板追加的资产仅受 <strong className="text-[#171212]">写时拦截层</strong> 保护；完整性巡检 / 实时漂移告警 不会自动覆盖新追加项，覆盖范围限于上方"受保护的智能体核心资产"清单中标注 🟢/🟡/🔴 的 8 项内置资产。
          </div>
        </div>

        <div className="panel">
          <div className="mb-4">
            <div className="eyebrow">8 项资产 · 完整性监控明细</div>
            <h3 className="section-title-lg mt-1">受保护的智能体核心资产 · 记忆 / 技能 / 插件 / 凭据</h3>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th>路径 / 资源</th>
                <th style={{ width: 80 }}>类型</th>
                <th>secureclaw 校验/监听机制</th>
              </tr>
            </thead>
            <tbody>
              {CORE_ASSETS.map(([path, type, kind, sec, auto]) => {
                const a = autoBadge(auto);
                return (
                  <tr key={path}>
                    <td><code className="text-sm font-mono text-[#171212]">{path}</code></td>
                    <td><span className={`badge ${assetBadge(kind)}`}>{type}</span></td>
                    <td>
                      <span className="text-xs" style={{ color: '#7a4a30', fontWeight: 500 }}>✓ {sec}</span>{' '}
                      <span className={`badge ${a.class} text-[10px] ml-2 whitespace-nowrap`}>{a.label}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="panel">
            <div className="flex items-start justify-between mb-4 gap-3">
              <div>
                <div className="eyebrow">完整性周期校验 · 30 分钟自动</div>
                <h3 className="section-title-lg mt-1">智能体资产基线漂移监控</h3>
              </div>
              <button className="btn-secondary btn-sm">立即校验</button>
            </div>
            <div className="space-y-2">
              {DRIFT_CHECKS.map(([path, node, time, status, tone, desc]) => (
                <div key={path} className="flex items-center gap-3 p-3 rounded-xl border border-[#eadfd8] bg-white">
                  <span className={`dot bg-${tone}-500`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <code className="text-xs font-mono text-[#171212]">{path}</code>
                      <span className="text-xs muted-strong">on {node}</span>
                    </div>
                    <div className="text-xs muted mt-0.5">{desc}</div>
                  </div>
                  <span className={`badge badge-${tone}`}>{status === 'drift' ? '⚠ 漂移' : '✓ 一致'}</span>
                  <span className="text-xs muted-strong">{time}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <div className="mb-4">
              <div className="eyebrow">记忆完整性监控 · 4 级告警分级</div>
              <h3 className="section-title-lg mt-1">智能体记忆资产实时漂移告警</h3>
            </div>
            <div className="space-y-2">
              {MEMORY_ALERTS.map(([t, inst, file, reason, sev, tone], i) => (
                <div key={i} className="flex items-center gap-3 p-2.5 rounded-xl border border-[#eadfd8] bg-white">
                  <span className="muted-strong text-xs shrink-0 w-12">{t}</span>
                  <code className="text-xs font-mono text-[#171212] shrink-0">{inst}</code>
                  <code className="text-xs text-[#171212] shrink-0">{file}</code>
                  <span className="text-xs muted flex-1 truncate">{reason}</span>
                  <span className={`badge badge-${tone} shrink-0`}>{sev}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default AssetProtectionPage;
