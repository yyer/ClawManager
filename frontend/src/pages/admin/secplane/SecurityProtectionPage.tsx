import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../components/AdminLayout';
import { CATEGORIES } from '../protection/_data';
import LiveAegisConfigButton from '../../../components/protection/LiveAegisConfigButton';
import { secplaneService, type SecplaneAlert, type KillSwitchState } from '../../../services/secplaneService';

// Alert.source → 来源 badge 显示文字 + tone
const SOURCE_LABEL: Record<string, string> = {
  aegis: '运行时层',
  secureclaw: '运行时层',
  ksecure: '主机层',
  kubearmor: '主机层',
  gateway: '网关',
  platform: '平台',
};
const sourceLabel = (src: string) => SOURCE_LABEL[src] || src;
const sourceBadgeTone = (src: string) => {
  const lbl = sourceLabel(src);
  if (lbl === '运行时层') return 'badge-red';
  if (lbl === '主机层') return 'badge-blue';
  if (lbl === '网关') return 'badge-orange';
  return 'badge-purple';
};
const severityTone = (sev: string) => (sev === 'high' ? 'red' : sev === 'medium' ? 'orange' : 'slate');

// rule_id 前缀 → 防护场景中文。两套 rule_id 并存：
// (1) defense_toggle 表里的 `defense.*` —— 后端 watcher 生成的告警；
// (2) ClawAegisEx 运行时上报的短名 `outbound_trust` / `tool_result_scan` 等。
const SCENE_BY_PREFIX: Array<[string, string]> = [
  ['defense.requireHttps', '出站治理'],
  ['defense.outboundTrust', '出站治理'],
  ['outbound_trust', '出站治理'],
  ['require_https', '出站治理'],
  ['defense.exfiltrationGuard', '输出面防护'],
  ['exfiltration_guard', '输出面防护'],
  ['tool_result_scan', '输出面防护'],
  ['trf.', '输出面防护'],
  ['defense.selfProtection', '资产防护'],
  ['self_protection', '资产防护'],
  ['defense.toolCall', '决策面防护'],
  ['tool_call_guard', '决策面防护'],
  ['tic.', '决策面防护'],
  ['tcc.', '决策面防护'],
  ['user_risk_flag', '输入面防护'],
  ['prompt_guard', '输入面防护'],
  ['urf.', '输入面防护'],
  ['secureclaw.', '组件可信扫描'],
];
const sceneOf = (ruleID?: string) => {
  if (!ruleID) return '—';
  for (const [pfx, label] of SCENE_BY_PREFIX) {
    if (ruleID.startsWith(pfx)) return label;
  }
  return ruleID;
};

// ts → "刚刚 / N 分钟前 / N 小时前 / YYYY-MM-DD"
const relTime = (iso: string) => {
  const now = Date.now();
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const sec = Math.max(0, Math.floor((now - t) / 1000));
  if (sec < 30) return '刚刚';
  if (sec < 60) return `${sec} 秒前`;
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟前`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} 小时前`;
  return iso.slice(0, 16).replace('T', ' ');
};

// 7 大风险面 - 每个 cat-id 的视觉数据（渐变 / 图标 / 攻击路径备注 / 层级标签）
// 注意：HTML 模板里把环境隔离与安全增强归"主机层"用蓝色，但 _data.ts 里这条用了 #0f766e；
// 我们保留 _data 配色，仅在视觉数据里补 HTML 的渐变和层标签。
type Layer = 'runtime' | 'host' | 'audit' | 'control' | 'planned';
interface ModuleVisual {
  num: string;          // 圈数字 ①②③④⑥⑦⑧
  layer: Layer;
  cardBorder: string;
  cardBg: string;
  iconGradient: string;
  iconShadow: string;
  iconPath: string;
  arrowColor: string;
  footerNote: string;
  layerLabel: string;
  layerTagClass: string;
  badgeClass: string;   // n 场景 badge 的颜色
}
const MODULE_VISUAL: Record<string, ModuleVisual> = {
  'cat-1': { num: '①', layer: 'runtime', cardBorder: '#f4b6b3', cardBg: 'linear-gradient(135deg,#fff,#fdeded)', iconGradient: 'linear-gradient(135deg,#ef4444,#991b1b)', iconShadow: '0 8px 20px -8px rgba(239,68,68,0.5)', iconPath: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z', arrowColor: '#ef4444', footerNote: '运行时主链路', layerLabel: '运行时层', layerTagClass: 'layer-tag-runtime', badgeClass: 'badge-red' },
  'cat-6': { num: '⑥', layer: 'host', cardBorder: '#a8d9d2', cardBg: 'linear-gradient(135deg,#fff,#e8f8f5)', iconGradient: 'linear-gradient(135deg,#0f766e,#115e59)', iconShadow: '0 8px 20px -8px rgba(15,118,110,0.4)', iconPath: 'M3 11v11h18V11M7 11V7a5 5 0 0110 0v4', arrowColor: '#0f766e', footerNote: '主机层兜底防护', layerLabel: '主机层', layerTagClass: 'layer-tag-host', badgeClass: 'badge-blue' },
  'cat-4': { num: '②', layer: 'audit', cardBorder: '#d9c7f5', cardBg: 'linear-gradient(135deg,#fff,#f3edff)', iconGradient: 'linear-gradient(135deg,#7c3aed,#6b21a8)', iconShadow: '0 8px 20px -8px rgba(107,33,168,0.4)', iconPath: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', arrowColor: '#6b21a8', footerNote: '组件供应链可信', layerLabel: '审计层', layerTagClass: 'layer-tag-audit', badgeClass: 'badge-purple' },
  'cat-3': { num: '④', layer: 'planned', cardBorder: '#c8bfb8', cardBg: 'linear-gradient(135deg,#fff,#f9f7f5)', iconGradient: 'linear-gradient(135deg,#94a3b8,#64748b)', iconShadow: '0 8px 20px -8px rgba(100,116,139,0.4)', iconPath: 'M13 10V3L4 14h7v7l9-11h-7z', arrowColor: '#94a3b8', footerNote: '后续版本开放', layerLabel: '规划中', layerTagClass: 'badge badge-orange', badgeClass: 'badge-slate' },
  'cat-2': { num: '③', layer: 'control', cardBorder: '#b8d8f4', cardBg: 'linear-gradient(135deg,#fff,#e8f3fd)', iconGradient: 'linear-gradient(135deg,#2563eb,#1d4ed8)', iconShadow: '0 8px 20px -8px rgba(37,99,235,0.4)', iconPath: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z', arrowColor: '#1d4ed8', footerNote: '控制层入口管控', layerLabel: '控制层', layerTagClass: 'layer-tag-control', badgeClass: 'badge-blue' },
  'cat-7': { num: '⑦', layer: 'control', cardBorder: '#eadfd8', cardBg: 'linear-gradient(135deg,#fff,#fdf6f1)', iconGradient: 'linear-gradient(135deg,#92400e,#78350f)', iconShadow: '0 8px 20px -8px rgba(146,64,14,0.4)', iconPath: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4', arrowColor: '#78350f', footerNote: '与监管治理协同', layerLabel: '控制层', layerTagClass: 'layer-tag-control', badgeClass: 'badge-orange' },
  'cat-5': { num: '⑧', layer: 'control', cardBorder: '#f4cba0', cardBg: 'linear-gradient(135deg,#fff,#fff3e1)', iconGradient: 'linear-gradient(135deg,#d97706,#b45309)', iconShadow: '0 8px 20px -8px rgba(217,119,6,0.4)', iconPath: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01', arrowColor: '#b45309', footerNote: '与策略模板协同', layerLabel: '控制层', layerTagClass: 'layer-tag-control', badgeClass: 'badge-orange' },
};
// 场景气泡（HTML 模板有部分文案 SCENARIOS 不覆盖：cat-4 加 SDS Skill 扫描、cat-3 规划中 3 项）
const BUBBLE_LABELS: Record<string, string[]> = {
  'cat-1': ['输入面防护', '状态面防护', '决策面防护', '输出面防护', '资产防篡改', '人因审批'],
  'cat-6': ['宿主加固', '容器隔离'],
  'cat-4': ['SKILL 技能扫描'],
  'cat-3': ['资源配额', '速率限制', '通信加密'],
  'cat-2': ['出站治理'],
  'cat-7': ['策略治理'],
  'cat-5': ['应急熔断', '全链路审计'],
};
// 网格视图 4 行布局（每行 2 列）
const GRID_ROWS: Array<[string, string]> = [
  ['cat-1', 'cat-6'],
  ['cat-4', 'cat-3'],
  ['cat-2', 'cat-7'],
  ['cat-5', '__placeholder__'],
];

// 环形视图里部分 cat 名字太长展示要缩短
const RING_SHORT_LABEL: Record<string, string> = {
  'cat-6': '环境隔离',
  'cat-3': '协同通信',
};

// 环形视图卡片 - 绝对定位
interface RingCardProps {
  catId: string;
  style: React.CSSProperties;
  bubbles: string[];
  bubbleOpacity?: number;
}
const RingCard: React.FC<RingCardProps> = ({ catId, style, bubbles, bubbleOpacity }) => {
  const vis = MODULE_VISUAL[catId];
  const cat = CATEGORIES.find((c) => c.id === catId);
  if (!cat || !vis) return null;
  const planned = vis.layer === 'planned';
  const label = RING_SHORT_LABEL[catId] ?? cat.label;
  return (
    <div style={{ position: 'absolute', background: '#fff', borderRadius: 16, border: `1px solid ${vis.cardBorder}`, padding: '10px 12px', boxShadow: '0 8px 24px -12px rgba(0,0,0,0.2)', ...style }}>
      <div className="flex items-center gap-2 mb-1">
        <div style={{ width: 28, height: 28, borderRadius: 8, background: vis.iconGradient, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5">
            <path strokeLinecap="round" strokeLinejoin="round" d={vis.iconPath} />
          </svg>
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#171212' }}>{label}</div>
          <div style={{ fontSize: '0.6rem', color: planned ? '#94a3b8' : vis.arrowColor, fontWeight: 600 }}>{vis.layerLabel}</div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {bubbles.map((b) => (
          <span key={b} className="scenario-bubble" style={{ fontSize: '0.6rem', padding: '2px 6px', ...(bubbleOpacity ? { opacity: bubbleOpacity } : {}) }}>{b}</span>
        ))}
      </div>
    </div>
  );
};

// 层级视图卡片 - panel-tight + 左 4px 色条
const LayerCard: React.FC<{ catId: string; sceneSubtitle?: string }> = ({ catId, sceneSubtitle }) => {
  const cat = CATEGORIES.find((c) => c.id === catId);
  const vis = MODULE_VISUAL[catId];
  if (!cat || !vis) return null;
  const planned = vis.layer === 'planned';
  const sceneCount = BUBBLE_LABELS[catId]?.length ?? 0;
  const inner = (
    <div className="panel-tight flex items-start gap-3" style={{ borderLeft: `4px solid ${vis.arrowColor}`, cursor: planned ? 'not-allowed' : 'pointer', opacity: planned ? 0.75 : 1 }}>
      <div style={{ width: 40, height: 40, borderRadius: 10, background: vis.iconGradient, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d={vis.iconPath} />
        </svg>
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <div style={{ fontSize: '0.875rem', fontWeight: 700, color: '#171212' }}>{cat.label}</div>
          {planned ? (
            <span className="badge badge-slate" style={{ fontSize: '0.5625rem', padding: '2px 6px' }}>规划中</span>
          ) : (
            <>
              <span className={`layer-tag ${vis.layerTagClass}`}>{vis.layerLabel}</span>
              <span className={`badge ${vis.badgeClass}`} style={{ fontSize: '0.5625rem', padding: '2px 6px' }}>{sceneCount} 场景</span>
            </>
          )}
        </div>
        <div className="text-xs muted mb-2">{sceneSubtitle ?? (planned ? '多智能体通信安全' : `${sceneCount} 场景`)}</div>
        <div className="flex flex-wrap gap-2">
          {(BUBBLE_LABELS[catId] ?? []).map((b) => (
            <span key={b} className="scenario-bubble" style={planned ? { opacity: 0.5 } : undefined}>{b}</span>
          ))}
        </div>
      </div>
      <div style={{ color: planned ? '#94a3b8' : vis.arrowColor, fontWeight: 600, fontSize: '0.8125rem' }}>{planned ? '规划 →' : '查看 →'}</div>
    </div>
  );
  if (planned) {
    return inner;
  }
  return <Link to={cat.path} style={{ textDecoration: 'none', color: 'inherit', display: 'block' }}>{inner}</Link>;
};

// 层级视图分组（zone divider + n 列卡片）
const LAYER_SUBTITLE: Record<string, string> = {
  'cat-1': '覆盖输入面 / 状态面 / 决策面 / 输出面 / 资产防篡改 / 人因审批',
  'cat-6': '基础设施兜底防护',
  'cat-4': '供应链安全 · SKILL 技能扫描',
  'cat-3': '多智能体通信安全',
};
const LayerSection: React.FC<{ title: string; dotColor: string; rows: Array<string[]> }> = ({ title, dotColor, rows }) => (
  <div>
    <div className="zone-divider">
      <div className="zone-divider-line" />
      <div className="zone-divider-label">
        <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: dotColor, marginRight: 6 }} />
        {title}
      </div>
      <div className="zone-divider-line" />
    </div>
    {rows.map((row, i) => {
      const colsClass = row.length === 1 ? 'grid-cols-1' : row.length === 2 ? 'grid-cols-2' : 'grid-cols-3';
      return (
        <div key={i} className={`grid ${colsClass} gap-3`}>
          {row.map((catId) => (
            <LayerCard key={catId} catId={catId} sceneSubtitle={LAYER_SUBTITLE[catId]} />
          ))}
        </div>
      );
    })}
  </div>
);

const SecurityProtectionPage: React.FC = () => {
  // 7 大风险面 全景视图切换
  const [viewMode, setViewMode] = useState<'grid' | 'ring' | 'layer'>('ring');

  // 真实告警流：listAlerts → 一次取 500 条，最近 10 条用于事件聚合表，
  // 全量用于 hero 4 张统计卡的 24h / 今日 计算。每 30s 刷新。
  const [allAlerts, setAllAlerts] = useState<SecplaneAlert[]>([]);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setAlertsLoading(true);
      try {
        const list = await secplaneService.listAlerts({ limit: 500 });
        if (!cancelled) {
          setAllAlerts(list);
          setAlertsError(null);
        }
      } catch (e) {
        if (!cancelled) {
          const err = e as { message?: string };
          setAlertsError(err.message ?? '加载告警失败');
        }
      } finally {
        if (!cancelled) setAlertsLoading(false);
      }
    };
    load();
    const t = window.setInterval(load, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(t);
    };
  }, []);
  const recentAlerts = allAlerts.slice(0, 10);

  // 4 张统计卡的真实数值
  const now = Date.now();
  const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
  const todayStartMs = todayStart.getTime();
  const last24hMs = now - 24 * 3600 * 1000;
  const isBlock = (a: SecplaneAlert) =>
    /block|deny/i.test(a.action || '') || /enforce|blocked/i.test(a.action || '');
  const todayHits = allAlerts.filter((a) => new Date(a.ts).getTime() >= todayStartMs).length;
  const high24h = allAlerts.filter((a) => new Date(a.ts).getTime() >= last24hMs && a.severity === 'high').length;
  const block24h = allAlerts.filter((a) => new Date(a.ts).getTime() >= last24hMs && isBlock(a)).length;
  const distinctAgents24h = new Set(
    allAlerts
      .filter((a) => new Date(a.ts).getTime() >= last24hMs && a.agent_id)
      .map((a) => a.agent_id as string),
  ).size;

  // 应急熔断（kill switch）状态 + 切换
  const [killSwitch, setKillSwitch] = useState<KillSwitchState | null>(null);
  const [killBusy, setKillBusy] = useState(false);
  const loadKillSwitch = async () => {
    try {
      setKillSwitch(await secplaneService.getKillSwitch());
    } catch {
      // ignore — UI 上以"未知"形式呈现
    }
  };
  useEffect(() => {
    loadKillSwitch();
    const t = window.setInterval(loadKillSwitch, 15_000);
    return () => window.clearInterval(t);
  }, []);
  const enableKillSwitch = async () => {
    const reason = window.prompt('请输入熔断原因（将记录到所有 pod 的 user_config + 审计日志）：', '');
    if (reason === null) return;
    if (!window.confirm('确认启用应急熔断？\n\n所有 ClawAegisEx pod 在 1-10 秒内会拒绝所有工具调用（http_get / browser / mcp 等）。webchat 仍能用，agent 出不去任何外部动作。')) return;
    setKillBusy(true);
    try {
      const res = await secplaneService.enableKillSwitch(reason);
      setKillSwitch(res.state);
      const tc = res.dispatch?.target_count ?? 0;
      window.alert(`🚨 应急熔断已启用\n下发到 ${tc} 个实例。Pod 收到 install_skill 后会在 1-10 秒内生效。`);
    } catch (e) {
      const err = e as { response?: { data?: { error?: string } }; message?: string };
      window.alert('启用失败：' + (err.response?.data?.error ?? err.message ?? '未知错误'));
    } finally {
      setKillBusy(false);
    }
  };
  const disableKillSwitch = async () => {
    if (!window.confirm('确认解除应急熔断？\n\n所有 ClawAegisEx pod 在 1-10 秒内恢复正常防护（按 defense_toggle 表的 mode 执行）。')) return;
    setKillBusy(true);
    try {
      const res = await secplaneService.disableKillSwitch();
      setKillSwitch(res.state);
      const tc = res.dispatch?.target_count ?? 0;
      window.alert(`✅ 应急熔断已解除\n下发到 ${tc} 个实例。`);
    } catch (e) {
      const err = e as { response?: { data?: { error?: string } }; message?: string };
      window.alert('解除失败：' + (err.response?.data?.error ?? err.message ?? '未知错误'));
    } finally {
      setKillBusy(false);
    }
  };
  const killActive = killSwitch?.enabled === 1;

  const exportReport = () => {
    if (allAlerts.length === 0) return;
    const text = allAlerts.map((a) => JSON.stringify(a)).join('\n');
    const blob = new Blob([text], { type: 'application/jsonl' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `secplane-alerts-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.jsonl`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        {killActive && (
          <div
            className="panel"
            style={{
              borderColor: '#dc2626',
              background: 'linear-gradient(90deg,#fef2f2,#fee2e2)',
              borderWidth: 2,
            }}
          >
            <div className="flex items-start gap-3">
              <svg width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="#dc2626" strokeWidth="2.5" style={{ marginTop: 2 }}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div className="flex-1">
                <div className="font-bold text-base" style={{ color: '#991b1b' }}>🚨 应急熔断已启用</div>
                <div className="text-sm mt-1" style={{ color: '#7f1d1d' }}>
                  原因：<span className="font-semibold">{killSwitch?.reason || '(无)'}</span>
                  <span className="muted ml-3">
                    启用人：{killSwitch?.set_by || '(无)'} · 启用时间：{killSwitch?.set_at?.replace('T', ' ').slice(0, 19) ?? '-'}
                  </span>
                </div>
                <div className="text-xs muted mt-1">所有 ClawAegisEx pod 的 <code>before_tool_call</code> 会无条件拒绝工具调用（http_get / browser / mcp 等）。webchat 仍可访问。</div>
              </div>
              <button className="btn-secondary btn-sm shrink-0" disabled={killBusy} onClick={disableKillSwitch}>
                {killBusy ? '处理中…' : '解除熔断'}
              </button>
            </div>
          </div>
        )}
        {/* Hero */}
        <div className="panel">
          <div className="flex items-start justify-between gap-6 mb-5">
            <div className="hero-block flex-1">
              <div className="h-eyebrow">总览</div>
              <h2 className="h-title">智能体平台纵深防御中心</h2>
              <p className="h-subtitle">
                面向智能体的纵深防御中心：覆盖输入面 / 状态面 / 决策面 / 输出面 + 主机层兜底 + 应急处置 + 策略治理。
              </p>
            </div>
            <div className="flex flex-col gap-2 shrink-0">
              <LiveAegisConfigButton />
              <button
                className="btn-secondary"
                onClick={exportReport}
                disabled={allAlerts.length === 0}
                title={allAlerts.length === 0 ? '暂无告警可导出' : `导出最近 ${allAlerts.length} 条告警为 JSONL`}
              >
                <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                导出报告
              </button>
              {killActive ? (
                <button className="btn-secondary" disabled={killBusy} onClick={disableKillSwitch} title="解除熔断 → 所有 pod 恢复正常防护">
                  <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                  </svg>
                  {killBusy ? '处理中…' : '解除熔断'}
                </button>
              ) : (
                <button className="btn-danger" disabled={killBusy} onClick={enableKillSwitch} title="启用熔断 → 全部 pod 1-10 秒内拒绝所有工具调用">
                  <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  {killBusy ? '下发中…' : '应急熔断'}
                </button>
              )}
            </div>
          </div>
          <div className="grid grid-cols-4 gap-3">
            <div className="stat-card">
              <div className="stat-card-label">今日防御命中</div>
              <div className="stat-card-value">{todayHits}</div>
              <div className="stat-card-sub muted">自 00:00 起累计告警条数</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">24h 高危事件</div>
              <div className={`stat-card-value ${high24h > 0 ? 'tone-red' : 'tone-green'}`}>{high24h}</div>
              <div className="stat-card-sub muted">severity=high</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">24h 拦截事件</div>
              <div className={`stat-card-value ${block24h > 0 ? 'tone-orange' : 'tone-green'}`}>{block24h}</div>
              <div className="stat-card-sub muted">action 含 block/deny</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">24h 涉及实例</div>
              <div className="stat-card-value">{distinctAgents24h}</div>
              <div className="stat-card-sub muted">distinct agent_id</div>
            </div>
          </div>
        </div>

        {/* KSecure 纵深防御模型 总览 banner */}
        <div className="ksecure-banner">
          <div className="ksecure-banner-left">
            <div className="ksecure-banner-title">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              KSecure 纵深防御模型
            </div>
            <div className="ksecure-banner-sub">攻击路径：从外到内 · 四层纵深防御</div>
            <div className="ksecure-banner-stats">
              <div className="ksecure-stat"><div className="ksecure-stat-num">7</div><div className="ksecure-stat-label">风险面</div></div>
              <div className="ksecure-stat"><div className="ksecure-stat-num">13</div><div className="ksecure-stat-label">防护场景</div></div>
              <div className="ksecure-stat"><div className="ksecure-stat-num">4</div><div className="ksecure-stat-label">防护层级</div></div>
            </div>
          </div>
          <div className="ksecure-banner-path">
            <div className="ksecure-path-step"><div className="ksecure-path-dot" style={{ background: '#ef4444' }} /><span>运行时层 · 6场景</span></div>
            <div className="ksecure-path-arrow">↓</div>
            <div className="ksecure-path-step"><div className="ksecure-path-dot" style={{ background: '#6b21a8' }} /><span>数据层 · 1场景</span></div>
            <div className="ksecure-path-arrow">↓</div>
            <div className="ksecure-path-step"><div className="ksecure-path-dot" style={{ background: '#1d4ed8' }} /><span>身份+隔离 · 3场景</span></div>
            <div className="ksecure-path-arrow">↔</div>
            <div className="ksecure-path-step"><div className="ksecure-path-dot" style={{ background: '#b45309' }} /><span>治理+策略 · 3场景</span></div>
          </div>
        </div>

        {/* 7 大风险面 全景 · 3 视图（网格 / 环形 / 层级）*/}
        <div className="panel" style={{ padding: 24 }}>
          <div className="flex items-center justify-between mb-5">
            <div>
              <div className="eyebrow">风险面与防护场景</div>
              <h3 className="section-title-lg mt-1">智能体的 7 大风险面 · 13 个防护场景全景</h3>
            </div>
            <div className="layer-legend">
              <div className="layer-dot"><div className="layer-dot-inner" style={{ background: '#ef4444' }} /><span>运行时层</span></div>
              <div className="layer-dot"><div className="layer-dot-inner" style={{ background: '#1d4ed8' }} /><span>主机层</span></div>
              <div className="layer-dot"><div className="layer-dot-inner" style={{ background: '#6b21a8' }} /><span>审计层</span></div>
              <div className="layer-dot"><div className="layer-dot-inner" style={{ background: '#b45309' }} /><span>控制层</span></div>
            </div>
          </div>

          <div className="flex items-center gap-2 mb-5">
            <button type="button" className={`sec-tab ${viewMode === 'grid' ? 'active' : ''}`} onClick={() => setViewMode('grid')}>网格视图</button>
            <button type="button" className={`sec-tab ${viewMode === 'ring' ? 'active' : ''}`} onClick={() => setViewMode('ring')}>环形视图</button>
            <button type="button" className={`sec-tab ${viewMode === 'layer' ? 'active' : ''}`} onClick={() => setViewMode('layer')}>层级视图</button>
          </div>

          {viewMode === 'grid' && (
            <div>
              {GRID_ROWS.map((row, ri) => (
                <div key={ri} className="grid grid-cols-2 gap-4 mb-4">
                  {row.map((catId) => {
                    if (catId === '__placeholder__') {
                      return (
                        <div key="placeholder" style={{ borderRadius: 20, border: '1px dashed #e2ddd8', display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 120, color: '#c8bfb8', fontSize: '0.8125rem' }}>
                          <span>更多防护场景规划中</span>
                        </div>
                      );
                    }
                    const cat = CATEGORIES.find((c) => c.id === catId);
                    const vis = MODULE_VISUAL[catId];
                    if (!cat || !vis) return null;
                    const disabled = !!cat.disabled;
                    const subtitle = disabled
                      ? '多智能体接入与代理间通信安全治理'
                      : `${BUBBLE_LABELS[catId]?.length ?? 0} 个防护场景`;
                    const card = (
                      <>
                        <div className="flex items-start gap-3 mb-3">
                          <div className="mod-icon" style={{ background: vis.iconGradient, boxShadow: vis.iconShadow }}>
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2">
                              <path strokeLinecap="round" strokeLinejoin="round" d={vis.iconPath} />
                            </svg>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap mb-1">
                              <div className="text-base font-bold text-[#171212]">{cat.label}</div>
                              {disabled ? (
                                <span className="badge badge-orange">规划中</span>
                              ) : (
                                <span className={`layer-tag ${vis.layerTagClass}`}>
                                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: vis.arrowColor, display: 'inline-block' }} />
                                  {vis.layerLabel}
                                </span>
                              )}
                            </div>
                            <div className="text-xs muted">{subtitle}</div>
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-2 mb-3">
                          {(BUBBLE_LABELS[catId] ?? []).map((b) => (
                            <span key={b} className="scenario-bubble" style={disabled ? { opacity: 0.4 } : undefined}>{b}</span>
                          ))}
                        </div>
                        <div className="divider" style={{ margin: '12px 0' }} />
                        <div className="flex items-center justify-between text-xs">
                          <span className="muted-strong">{vis.footerNote}</span>
                          <span style={{ color: vis.arrowColor, fontWeight: 600 }}>{disabled ? '规划中 →' : '查看 →'}</span>
                        </div>
                      </>
                    );
                    const cardStyle = { borderColor: vis.cardBorder, background: vis.cardBg };
                    if (disabled) {
                      return (
                        <div key={catId} className="cat-card-new disabled" style={cardStyle}>{card}</div>
                      );
                    }
                    return (
                      <Link key={catId} to={cat.path} className="cat-card-new" style={cardStyle}>{card}</Link>
                    );
                  })}
                </div>
              ))}
            </div>
          )}

          {viewMode === 'ring' && (
            <div className="flex flex-col items-center">
              <div className="flex gap-5 mb-6 flex-wrap justify-center">
                <div className="flex items-center gap-2 text-xs"><div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444' }} />运行时层</div>
                <div className="flex items-center gap-2 text-xs"><div style={{ width: 10, height: 10, borderRadius: '50%', background: '#1d4ed8' }} />主机层</div>
                <div className="flex items-center gap-2 text-xs"><div style={{ width: 10, height: 10, borderRadius: '50%', background: '#6b21a8' }} />审计层</div>
                <div className="flex items-center gap-2 text-xs"><div style={{ width: 10, height: 10, borderRadius: '50%', background: '#b45309' }} />控制层</div>
              </div>
              <div className="relative flex items-center justify-center" style={{ width: 560, height: 560 }}>
                <div style={{ position: 'absolute', width: 540, height: 540, top: '50%', left: '50%', transform: 'translate(-50%,-50%)', borderRadius: '50%', border: '2px solid #ef4444', opacity: 0.25 }} />
                <div style={{ position: 'absolute', width: 390, height: 390, top: '50%', left: '50%', transform: 'translate(-50%,-50%)', borderRadius: '50%', border: '2px solid #1d4ed8', opacity: 0.25 }} />
                <div style={{ position: 'absolute', width: 260, height: 260, top: '50%', left: '50%', transform: 'translate(-50%,-50%)', borderRadius: '50%', border: '2px solid #6b21a8', opacity: 0.25 }} />
                <div style={{ position: 'absolute', width: 140, height: 140, top: '50%', left: '50%', transform: 'translate(-50%,-50%)', borderRadius: '50%', border: '2px solid #b45309', opacity: 0.25 }} />

                <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 100, height: 100, borderRadius: '50%', background: 'linear-gradient(135deg,#ef6b4a,#dc2626)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: '#fff', boxShadow: '0 12px 32px -12px rgba(220,38,38,0.5)', zIndex: 2 }}>
                  <div style={{ fontSize: '2.25rem', fontWeight: 800, lineHeight: 1 }}>7</div>
                  <div style={{ fontSize: '0.5625rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', opacity: 0.9 }}>风险面</div>
                </div>

                {/* ① 运行时层：上方 */}
                <RingCard catId="cat-1" style={{ top: 8, left: '50%', transform: 'translateX(-50%)', width: 180 }} bubbles={['输入', '状态', '决策', '输出', '资产', '人因']} />
                {/* ⑥ 主机层：右下 */}
                <RingCard catId="cat-6" style={{ bottom: 70, right: 38, width: 170 }} bubbles={['宿主', '容器']} />
                {/* ④ 主机层 规划中：右 */}
                <RingCard catId="cat-3" style={{ top: '50%', right: 18, transform: 'translateY(-50%)', width: 150, opacity: 0.7 }} bubbles={['配额', '限速', '加密']} bubbleOpacity={0.5} />
                {/* ② 审计层：左 */}
                <RingCard catId="cat-4" style={{ top: '50%', left: 18, transform: 'translateY(-50%)', width: 165 }} bubbles={['SKILL 技能扫描']} />
                {/* ③ 控制层：左上 */}
                <RingCard catId="cat-2" style={{ top: 115, left: 48, width: 155 }} bubbles={['出站']} />
                {/* ⑦ 控制层：右上 */}
                <RingCard catId="cat-7" style={{ top: 115, right: 48, width: 155 }} bubbles={['策略']} />
                {/* ⑧ 控制层：底部 */}
                <RingCard catId="cat-5" style={{ bottom: 115, left: '50%', transform: 'translateX(-50%)', width: 165 }} bubbles={['熔断', '审计']} />
              </div>

              <div className="flex flex-col gap-2 mt-4" style={{ width: 560 }}>
                <div className="flex items-center gap-3 p-3 rounded-xl" style={{ border: '1px solid #f4b6b3', background: '#fdeded' }}>
                  <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#ef4444', flexShrink: 0 }} />
                  <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#b42318' }}>运行时层</div>
                  <div style={{ fontSize: '0.75rem', color: '#6f6661' }}>— 智能体运行时安全（6 场景）| 输入/状态/决策/输出/资产/人因审批</div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-xl" style={{ border: '1px solid #b8d4f4', background: '#e8f3fd' }}>
                  <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#1d4ed8', flexShrink: 0 }} />
                  <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#1d4ed8' }}>主机层</div>
                  <div style={{ fontSize: '0.75rem', color: '#6f6661' }}>— 环境隔离（2 场景）+ 协同通信（规划中）| 宿主加固/容器隔离/资源管控</div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-xl" style={{ border: '1px solid #d9c7f5', background: '#f3edff' }}>
                  <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#6b21a8', flexShrink: 0 }} />
                  <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#6b21a8' }}>审计层</div>
                  <div style={{ fontSize: '0.75rem', color: '#6f6661' }}>— 数据与组件可信（1 场景）| SKILL 技能扫描</div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-xl" style={{ border: '1px solid #f4cba0', background: '#fff3e1' }}>
                  <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#b45309', flexShrink: 0 }} />
                  <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#b45309' }}>控制层</div>
                  <div style={{ fontSize: '0.75rem', color: '#6f6661' }}>— 身份权限 + 安全策略 + 监管治理（4 场景）| 出站/策略/熔断/审计</div>
                </div>
              </div>
            </div>
          )}

          {viewMode === 'layer' && (
            <div className="space-y-5">
              <LayerSection title="运行时层" dotColor="#ef4444" rows={[['cat-1']]} />
              <LayerSection title="主机层" dotColor="#1d4ed8" rows={[['cat-6', 'cat-3']]} />
              <LayerSection title="审计层" dotColor="#6b21a8" rows={[['cat-4']]} />
              <LayerSection title="控制层" dotColor="#b45309" rows={[['cat-2', 'cat-7', 'cat-5']]} />
            </div>
          )}
        </div>

        {/* 跨产品事件流 */}
        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="eyebrow">安全模块事件聚合</div>
              <h3 className="section-title-lg mt-1">最近 10 条跨产品安全事件</h3>
            </div>
            <Link to="/admin/secplane/events" className="btn-secondary btn-sm" style={{ textDecoration: 'none' }}>
              完整事件流 →
            </Link>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 110 }}>时间</th>
                <th style={{ width: 80 }}>来源</th>
                <th style={{ width: 130 }}>防护场景</th>
                <th>事件</th>
                <th style={{ width: 220 }}>目标</th>
                <th style={{ width: 90 }}>严重</th>
              </tr>
            </thead>
            <tbody>
              {alertsLoading && recentAlerts.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted text-sm py-4 text-center">加载中…</td>
                </tr>
              )}
              {alertsError && !alertsLoading && (
                <tr>
                  <td colSpan={6} className="text-sm py-4 text-center" style={{ color: '#b42318' }}>
                    {alertsError}
                  </td>
                </tr>
              )}
              {!alertsLoading && !alertsError && recentAlerts.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted text-sm py-4 text-center">
                    暂无告警事件。ClawAegisEx / SecureClaw / 各检测器上报后会出现在这里。
                  </td>
                </tr>
              )}
              {recentAlerts.map((a) => {
                const target = a.agent_id || a.subject || '—';
                const event = a.rule_name || a.evidence || a.rule_id || '(未命名事件)';
                return (
                  <tr key={a.id}>
                    <td>
                      <span className="muted-strong text-xs" title={a.ts}>{relTime(a.ts)}</span>
                    </td>
                    <td>
                      <span className={`badge ${sourceBadgeTone(a.source)}`}>{sourceLabel(a.source)}</span>
                    </td>
                    <td>
                      <span className="text-xs font-medium text-[#171212]">{sceneOf(a.rule_id)}</span>
                    </td>
                    <td>
                      <span className="text-sm text-[#171212]" title={a.evidence ?? ''}>{event}</span>
                    </td>
                    <td>
                      <span className="font-mono text-xs">{target}</span>
                    </td>
                    <td>
                      <span className={`badge badge-${severityTone(a.severity)}`}>{a.severity}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </AdminLayout>
  );
};

export default SecurityProtectionPage;
