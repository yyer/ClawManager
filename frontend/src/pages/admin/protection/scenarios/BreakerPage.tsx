import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';
import { secplaneService, type KillSwitchState } from '../../../../services/secplaneService';
import { instanceService } from '../../../../services/instanceService';

// 应急熔断 (scenario i) — 接 secplane kill-switch 后端。
// 当前后端实现的是"系统级 kill switch"：启用后 ClawAegisEx 在所有 running 实例
// 的 before_tool_call 中无条件 block 工具调用。
// 主机级熔断（NetworkPolicy / OS agent）和双人复核签字 不在本期范围内。

type InstanceLite = { id: number; name: string; status?: string };

const BreakerPage: React.FC = () => {
  // -- kill switch 状态 --
  const [ks, setKs] = useState<KillSwitchState | null>(null);
  const [ksLoading, setKsLoading] = useState(false);
  const [ksBusy, setKsBusy] = useState(false);
  const [lastDispatchCount, setLastDispatchCount] = useState<number | null>(null);
  const loadKs = useCallback(async () => {
    setKsLoading(true);
    try {
      setKs(await secplaneService.getKillSwitch());
    } catch {
      // ignore — UI 以 "未知" 形式呈现
    } finally {
      setKsLoading(false);
    }
  }, []);
  useEffect(() => {
    loadKs();
    const t = window.setInterval(loadKs, 10_000);
    return () => window.clearInterval(t);
  }, [loadKs]);
  const active = ks?.enabled === 1;

  // -- 真实实例列表（用于"影响范围预览"）--
  const [instances, setInstances] = useState<InstanceLite[]>([]);
  const loadInstances = useCallback(async () => {
    try {
      const list = await instanceService.getInstances(1, 1000);
      const items = (list?.instances ?? []) as Array<{ id: number; name: string; status?: string; type?: string }>;
      const ocs = items
        .filter((i) => (i.type ?? 'openclaw') === 'openclaw')
        .map((i) => ({ id: i.id, name: i.name, status: i.status }));
      setInstances(ocs);
    } catch {
      setInstances([]);
    }
  }, []);
  useEffect(() => { loadInstances(); }, [loadInstances]);
  const runningInstances = instances.filter((i) => i.status === 'running');

  // -- 表单状态 --
  const [reason, setReason] = useState('');
  const [confirmText, setConfirmText] = useState('');
  const canExecute = !active && !ksBusy && reason.trim().length > 0 && confirmText.trim() === 'CONFIRM';

  const doEnable = async () => {
    if (!canExecute) return;
    setKsBusy(true);
    try {
      const res = await secplaneService.enableKillSwitch(reason.trim());
      setKs(res.state);
      setLastDispatchCount(res.dispatch?.target_count ?? null);
      setReason('');
      setConfirmText('');
      window.alert(`🚨 应急熔断已启用\n下发到 ${res.dispatch?.target_count ?? 0} 个 running 实例。Pod 收到 install_skill 后 1-10 秒内生效。`);
    } catch (e) {
      const err = e as { response?: { data?: { error?: string } }; message?: string };
      window.alert('启用失败：' + (err.response?.data?.error ?? err.message ?? '未知错误'));
    } finally {
      setKsBusy(false);
    }
  };

  const doDisable = async () => {
    if (!active || ksBusy) return;
    if (!window.confirm('确认解除应急熔断？所有 ClawAegisEx pod 1-10 秒内恢复正常防护。')) return;
    setKsBusy(true);
    try {
      const res = await secplaneService.disableKillSwitch();
      setKs(res.state);
      setLastDispatchCount(res.dispatch?.target_count ?? null);
      window.alert(`✅ 应急熔断已解除\n下发到 ${res.dispatch?.target_count ?? 0} 个实例。`);
    } catch (e) {
      const err = e as { response?: { data?: { error?: string } }; message?: string };
      window.alert('解除失败：' + (err.response?.data?.error ?? err.message ?? '未知错误'));
    } finally {
      setKsBusy(false);
    }
  };

  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/cat-govern">监管与运营治理</Link>
          <span>/</span>
          <span className="crumb-current">应急熔断</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">最后一道兜底</div>
            <h2 className="h-title">应急熔断中心</h2>
            <p className="h-subtitle">
              当上层防御失效或出现可疑活动时，一键让所有 ClawAegisEx pod 拒绝所有工具调用（http_get / browser / mcp 等）。Pod 不停，webchat 可访问，agent 无法执行外部动作。
            </p>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="stat-card">
              <div className="stat-card-label">当前状态</div>
              <div className={`stat-card-value ${active ? 'tone-red' : 'tone-green'}`}>
                {ksLoading && !ks ? '…' : active ? '🚨 启用' : '✓ 关闭'}
              </div>
              <div className="stat-card-sub muted-strong">
                {active ? '所有工具调用被拒绝' : '按 defense_toggle 正常防护'}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">在管实例</div>
              <div className="stat-card-value">{instances.length}</div>
              <div className="stat-card-sub muted-strong">含全部状态</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">running 实例</div>
              <div className="stat-card-value tone-green">{runningInstances.length}</div>
              <div className="stat-card-sub muted-strong">熔断影响范围</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">最近一次下发</div>
              <div className="stat-card-value">{lastDispatchCount ?? '—'}</div>
              <div className="stat-card-sub muted-strong">本会话内 target_count</div>
            </div>
          </div>
        </div>

        {active && (
          <div className="panel" style={{ border: '2px solid #f4b6b3', background: 'linear-gradient(180deg, #fdeded 0%, #ffffff 60%)' }}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3">
                <div className="w-12 h-12 rounded-2xl bg-red-600 flex items-center justify-center" style={{ flexShrink: 0 }}>
                  <svg width="22" height="22" fill="none" viewBox="0 0 24 24" stroke="white">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div>
                  <div className="eyebrow" style={{ color: '#b42318' }}>熔断进行中 · ISOLATED</div>
                  <h3 className="text-2xl font-bold text-[#171212] mt-1">系统级应急熔断</h3>
                  <div className="text-xs muted mt-1">
                    原因：<strong className="text-[#171212]">{ks?.reason || '(无)'}</strong>
                    <span className="ml-3">启用人：{ks?.set_by || '(无)'}</span>
                    <span className="ml-3">启用时间：{ks?.set_at?.replace('T', ' ').slice(0, 19) ?? '-'}</span>
                  </div>
                </div>
              </div>
              <button className="btn-secondary shrink-0" disabled={ksBusy} onClick={doDisable}>
                {ksBusy ? '处理中…' : '解除熔断'}
              </button>
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <div className="panel">
            <div className="eyebrow mb-3">手动触发</div>
            <h3 className="section-title-lg mb-4">系统级熔断（所有 running 实例）</h3>
            <div className="alert alert-warning mb-4">
              <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01" />
              </svg>
              当前实现为"系统级 kill switch"，对所有 running ClawAegisEx pod 生效。主机级熔断（NetworkPolicy / OS agent）暂未支持。
            </div>

            <div className="space-y-3 mb-4 text-sm">
              <div>
                <div className="eyebrow text-[10px] mb-1">影响范围预览（real-time）</div>
                <div className="p-3 rounded-xl bg-[#fdf6f1] border border-[#eadfd8] text-xs">
                  将影响 <strong>{runningInstances.length}</strong> 个 running 实例：
                  {runningInstances.length === 0 ? (
                    <span className="muted ml-1">（暂无 running 实例）</span>
                  ) : (
                    <ul className="mt-2 space-y-1">
                      {runningInstances.map((i) => (
                        <li key={i.id} className="font-mono">
                          [{i.id}] {i.name} <span className="badge badge-green ml-1">{i.status}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
              <div>
                <div className="eyebrow text-[10px] mb-1">熔断原因（必填）</div>
                <textarea
                  className="input"
                  rows={3}
                  placeholder="例如：发现可疑数据外传，先熔断排查"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  disabled={active || ksBusy}
                />
              </div>
              <div>
                <div className="eyebrow text-[10px] mb-1">
                  二次确认：在下框中一字不差地输入 <code className="text-[11px] text-[#b42318] bg-[#fdf6f1] px-1 rounded">CONFIRM</code>（大写）
                </div>
                <input
                  className="input"
                  placeholder='请输入 "CONFIRM"'
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  disabled={active || ksBusy}
                />
              </div>
            </div>
            <button
              className="inline-flex items-center justify-center gap-2 rounded-2xl px-5 py-3 text-sm font-semibold text-white w-full"
              style={{
                background: canExecute ? 'linear-gradient(135deg,#dc2626,#991b1b)' : '#d8c4b9',
                cursor: canExecute ? 'pointer' : 'not-allowed',
              }}
              disabled={!canExecute}
              onClick={doEnable}
              title={active ? '已启用，请先解除' : !reason.trim() ? '请填写原因' : confirmText.trim() !== 'CONFIRM' ? '请在确认框中输入大写 CONFIRM' : ''}
            >
              {ksBusy ? '下发中…' : active ? '已启用' : '执行系统熔断'}
            </button>
          </div>

          <div className="panel">
            <div className="eyebrow mb-3">解除熔断</div>
            <h3 className="section-title-lg mb-4">恢复正常防护</h3>
            <div className={`alert ${active ? 'alert-info' : 'alert-success'} mb-4`}>
              <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              {active
                ? '解除后 ClawAegisEx 将立刻恢复按 defense_toggle 规则的正常防护。'
                : '当前未处于熔断状态。'}
            </div>
            <div className="space-y-3 text-sm mb-4">
              <div className="p-3 rounded-xl border bg-[#fdf6f1]" style={{ borderColor: '#eadfd8' }}>
                <div className="flex items-center justify-between">
                  <span className="text-xs muted-strong">状态</span>
                  <span className={`badge ${active ? 'badge-red' : 'badge-green'}`}>
                    {active ? '🚨 已启用' : '✓ 已关闭'}
                  </span>
                </div>
                {active && (
                  <>
                    <div className="text-xs muted mt-2">
                      原因：<span className="text-[#171212]">{ks?.reason || '(无)'}</span>
                    </div>
                    <div className="text-xs muted">
                      启用时间：{ks?.set_at?.replace('T', ' ').slice(0, 19) ?? '-'}
                    </div>
                  </>
                )}
              </div>
            </div>
            <button
              className="btn-secondary w-full"
              disabled={!active || ksBusy}
              style={!active || ksBusy ? { opacity: 0.5, cursor: 'not-allowed' } : undefined}
              onClick={doDisable}
            >
              {ksBusy ? '处理中…' : active ? '解除熔断' : '当前未启用'}
            </button>
            <div className="text-xs muted mt-3 leading-5">
              <strong>后续规划</strong>：双人复核签字 / 主机级 NetworkPolicy 熔断 / 熔断审计历史表，当前未实现。
            </div>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default BreakerPage;
