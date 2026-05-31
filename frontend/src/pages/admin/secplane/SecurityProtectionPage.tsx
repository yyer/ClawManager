import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../components/AdminLayout';
import { CATEGORIES, getScenariosByCategory } from '../protection/_data';
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

const SecurityProtectionPage: React.FC = () => {
  // 类目卡按截图顺序：去掉 overview + events
  const catCards = CATEGORIES.filter((c) => c.id !== 'overview' && c.id !== 'events');

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
              <button className="btn-secondary">
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

        {/* 7 类别卡片网格 */}
        <div className="flex items-baseline justify-between mb-2">
          <div>
            <div className="eyebrow">风险面与防护场景</div>
            <h3 className="section-title-lg mt-1">智能体的 7 大风险面 · 13 个防护场景全景</h3>
          </div>
          <div className="flex items-center gap-2 text-xs muted">
            防护层：
            <span className="badge badge-red">运行时层</span>
            <span className="badge badge-blue">主机层</span>
            <span className="badge badge-purple">审计</span>
            <span className="badge badge-orange">控制层</span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          {catCards.map((cat) => {
            const catScenarios = getScenariosByCategory(cat.id);
            const disabled = !!cat.disabled;
            const inner = disabled ? (
              <div className="text-xs muted leading-5">
                多智能体接入与代理间通信安全治理，将在后续版本开放；资源配额与速率限制由平台 AI 网关 统一承担。
              </div>
            ) : (
              <>
                <div className="space-y-1.5 mb-3">
                  {catScenarios.map((s) => (
                    <div key={s.id} className="flex items-center gap-2 text-xs">
                      <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: cat.color }} />
                      <span className="text-[#171212] font-medium flex-1 truncate">{s.label}</span>
                      <span className="muted text-[10px]">查看 →</span>
                    </div>
                  ))}
                </div>
                <div className="divider" />
                <div className="flex items-center justify-between text-xs">
                  <span className="muted-strong">点击进入类别详情</span>
                  <span style={{ color: cat.color, fontWeight: 600 }}>查看 →</span>
                </div>
              </>
            );
            const cardClass = `cat-overview-card${disabled ? ' cat-overview-card-disabled' : ''}`;
            const header = (
              <div className="flex items-start gap-3 mb-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <div className="text-lg font-bold text-[#171212]">{cat.label}</div>
                    {disabled ? (
                      <span className="badge badge-slate">本期未开放</span>
                    ) : (
                      <span className="badge badge-red">{cat.count} 个场景</span>
                    )}
                  </div>
                </div>
              </div>
            );
            return disabled ? (
              <a key={cat.id} className={cardClass}>
                {header}
                {inner}
              </a>
            ) : (
              <Link key={cat.id} to={cat.path} className={cardClass}>
                {header}
                {inner}
              </Link>
            );
          })}
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
