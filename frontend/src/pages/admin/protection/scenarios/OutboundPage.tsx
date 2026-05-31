import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';
import { useSurfaceBackend } from '../../secplane/runtime/useSurfaceBackend';
import {
  secplaneService,
  type OutboundTrustedEndpoint,
} from '../../../../services/secplaneService';

// 出站治理 (scenario h) — 对齐 KSecForAIDemo/scenario-h-outbound.html
// 接 backend：require-https defense_toggle + "保存并应用" → dispatchAegisApply

const ALERT_PREFIXES = ['defense.requireHttps', 'defense.exfiltrationGuard', 'defense.outboundTrust'];

const OutboundPage: React.FC = () => {
  const { alerts, dispatching, dispatchMsg, modeOf, setMode, dispatchApply } = useSurfaceBackend(ALERT_PREFIXES);
  const httpsMode = modeOf('defense.requireHttps', 'enforce');
  const httpsHits = alerts.filter((a) => a.rule_id?.startsWith('defense.requireHttps')).length;
  const trustMode = modeOf('defense.outboundTrust', 'enforce');
  const trustHits = alerts.filter((a) => a.rule_id?.startsWith('defense.outboundTrust')).length;

  // --- 受信端点 CRUD ---
  const [trusted, setTrusted] = useState<OutboundTrustedEndpoint[]>([]);
  const [trustedLoading, setTrustedLoading] = useState(false);
  const [trustedError, setTrustedError] = useState<string | null>(null);
  const [newDomain, setNewDomain] = useState('');
  const [newFingerprint, setNewFingerprint] = useState('');
  const [newLabel, setNewLabel] = useState('');

  const loadTrusted = useCallback(async () => {
    setTrustedLoading(true);
    setTrustedError(null);
    try {
      const list = await secplaneService.listOutboundTrusted();
      setTrusted(list);
    } catch (e) {
      const err = e as { message?: string };
      setTrustedError(err.message ?? '加载失败');
    } finally {
      setTrustedLoading(false);
    }
  }, []);

  useEffect(() => { loadTrusted(); }, [loadTrusted]);

  const addTrusted = async () => {
    if (!newDomain.trim()) return;
    setTrustedError(null);
    try {
      await secplaneService.createOutboundTrusted({
        domain_pattern: newDomain.trim(),
        fingerprint_sha256: newFingerprint.trim() || undefined,
        label: newLabel.trim() || undefined,
      });
      setNewDomain('');
      setNewFingerprint('');
      setNewLabel('');
      loadTrusted();
    } catch (e) {
      const err = e as { response?: { data?: { error?: string } }; message?: string };
      setTrustedError(err.response?.data?.error ?? err.message ?? '保存失败');
    }
  };

  const removeTrusted = async (id: number) => {
    if (!window.confirm(`确认删除条目 #${id}？`)) return;
    try {
      await secplaneService.deleteOutboundTrusted(id);
      loadTrusted();
    } catch (e) {
      const err = e as { message?: string };
      setTrustedError(err.message ?? '删除失败');
    }
  };

  // 探测指纹：填表时点"探测"，后端 TLS 握手把摘要回填
  const [probing, setProbing] = useState(false);
  const [probeMsg, setProbeMsg] = useState<string | null>(null);
  const probeFingerprint = async () => {
    const host = newDomain.trim();
    if (!host) return;
    if (host.includes('*') || host.includes('?')) {
      setProbeMsg('通配域名（含 * 或 ?）无法探测，请用一个具体子域名');
      return;
    }
    setProbing(true);
    setProbeMsg(null);
    try {
      const r = await secplaneService.probeOutboundTrusted(host);
      setNewFingerprint(r.fingerprint_sha256);
      setProbeMsg(`subject=${r.subject_cn || '-'}, issuer=${r.issuer || '-'}, 过期=${(r.not_after || '').slice(0, 10)}`);
    } catch (e) {
      const err = e as { response?: { data?: { error?: string } }; message?: string };
      setProbeMsg('探测失败：' + (err.response?.data?.error ?? err.message ?? '未知错误'));
    } finally {
      setProbing(false);
    }
  };

  // 重新探测已存在条目：drift=true 时基线被自动刷为最新指纹
  const [reprobingId, setReprobingId] = useState<number | null>(null);
  const reprobeOne = async (id: number) => {
    setReprobingId(id);
    setTrustedError(null);
    try {
      const r = await secplaneService.reprobeOutboundTrusted(id);
      if (r.drift) {
        window.alert(
          `⚠️ 指纹漂移已记录\n域名: ${r.endpoint.domain_pattern}\n旧: ${r.previous_fingerprint.slice(0, 16)}…\n新: ${r.probe.fingerprint_sha256.slice(0, 16)}…\n（基线已更新；告警面板可查"出站可信端点指纹漂移"事件）`,
        );
      } else {
        setProbeMsg(`✓ ${r.endpoint.domain_pattern} 指纹一致 (subject=${r.probe.subject_cn || '-'})`);
      }
      loadTrusted();
    } catch (e) {
      const err = e as { response?: { data?: { error?: string } }; message?: string };
      setTrustedError('重探失败：' + (err.response?.data?.error ?? err.message ?? '未知错误'));
    } finally {
      setReprobingId(null);
    }
  };

  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/cat-trust">数据与组件可信</Link>
          <span>/</span>
          <span className="crumb-current">出站治理</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">智能体出站双向认证</div>
            <h2 className="h-title">出站治理</h2>
            <p className="h-subtitle">
              智能体出站调用（Agent↔Agent / Skill / Markdown URL / MCP / 外部 LLM）的白名单 + 客户端证书 + 网络层兜底三层联防。
            </p>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="stat-card">
              <div className="stat-card-label">白名单条目</div>
              <div className="stat-card-value">142</div>
              <div className="stat-card-sub muted-strong">5 类通道</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">24h 拦截</div>
              <div className="stat-card-value tone-red">38</div>
              <div className="stat-card-sub muted-strong">非白名单 + IOC</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">证书池</div>
              <div className="stat-card-value">28</div>
              <div className="stat-card-sub muted-strong">3 即将过期</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">命中白名单率</div>
              <div className="stat-card-value tone-green">98.2%</div>
              <div className="stat-card-sub muted-strong">合规目标 100%</div>
            </div>
          </div>
        </div>

        {/* --- 外联开启 TLS 总开关 (defense.requireHttps) --- */}
        <div className="panel">
          <div className="flex items-center justify-between mb-4 gap-4">
            <div>
              <div className="eyebrow">应用层强制</div>
              <h3 className="section-title-lg mt-1">外联开启 TLS（require-https）</h3>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs muted-strong">模式</span>
              <div className="mode-selector">
                <button className={httpsMode === 'enforce' ? 'active-enforce' : ''} onClick={() => setMode('defense.requireHttps', 'enforce')}>
                  拦截
                </button>
                <button className={httpsMode === 'observe' ? 'active-observe' : ''} onClick={() => setMode('defense.requireHttps', 'observe')}>
                  监控
                </button>
                <button className={httpsMode === 'off' ? 'active-off' : ''} onClick={() => setMode('defense.requireHttps', 'off')}>
                  停止
                </button>
              </div>
              <button className="btn-primary btn-sm" disabled={dispatching} onClick={dispatchApply}>
                {dispatching ? '下发中…' : '保存并应用'}
              </button>
              {dispatchMsg && <span className="text-xs muted ml-1">{dispatchMsg}</span>}
            </div>
          </div>
          <div className="grid grid-cols-[1fr_120px] gap-4 items-start">
            <div className="text-xs muted leading-6">
              在 ClawAegisEx <code className="text-[11px] text-[#7a4a30] bg-[#fdf6f1] px-1.5 py-0.5 rounded">before_tool_call</code> 钩子里扫描工具参数中所有 URL：
              一旦命中 <code className="text-[11px] text-[#b42318]">http://</code>、<code className="text-[11px] text-[#b42318]">ws://</code>、
              <code className="text-[11px] text-[#b42318]">ftp://</code> 等明文协议 →
              <strong className="text-[#171212]"> enforce 阻断 + 告警</strong>，
              <strong className="text-[#171212]">observe 仅告警</strong>，
              off 跳过。MCP / 外部 LLM / Skill 出站 / curl|wget 等都覆盖。
              建议配合 L3 K8s NetworkPolicy 兜底。
            </div>
            <div className="p-4 rounded-2xl border border-[#eadfd8] bg-[#fffaf7] text-right">
              <div className="text-[10px] muted-strong tracking-wider">24h 命中</div>
              <div className={`text-2xl font-bold mt-1 tone-${httpsHits > 0 ? 'red' : 'green'}`}>{httpsHits}</div>
              <div className="text-xs muted mt-0.5">enforce/observe 累计</div>
            </div>
          </div>
        </div>

        {/* === 出站可信端点白名单 (defense.outboundTrust) === */}
        <div className="panel">
          <div className="flex items-center justify-between mb-4 gap-4 flex-wrap">
            <div>
              <div className="eyebrow">证书池 · 出站可信端点白名单</div>
              <h3 className="section-title-lg mt-1">外联只允许列表内的域名（可选 cert pin）</h3>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs muted-strong">模式</span>
              <div className="mode-selector">
                <button className={trustMode === 'enforce' ? 'active-enforce' : ''} onClick={() => setMode('defense.outboundTrust', 'enforce')}>
                  拦截
                </button>
                <button className={trustMode === 'observe' ? 'active-observe' : ''} onClick={() => setMode('defense.outboundTrust', 'observe')}>
                  监控
                </button>
                <button className={trustMode === 'off' ? 'active-off' : ''} onClick={() => setMode('defense.outboundTrust', 'off')}>
                  停止
                </button>
              </div>
              <button className="btn-primary btn-sm" disabled={dispatching} onClick={dispatchApply}>
                {dispatching ? '下发中…' : '保存并应用'}
              </button>
              {dispatchMsg && <span className="text-xs muted ml-1">{dispatchMsg}</span>}
              <span className={`text-xs font-bold tone-${trustHits > 0 ? 'red' : 'green'}`}>24h 拦截 {trustHits}</span>
            </div>
          </div>

          {/* 新增表单 */}
          <div className="grid gap-2 mb-3 items-center" style={{ gridTemplateColumns: '1.4fr 2fr 1.2fr auto' }}>
            <input
              className="input"
              placeholder="域名 (如 api.openai.com 或 *.openai.com)"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
            />
            <input
              className="input"
              placeholder="可选 cert SHA256 fingerprint (64 hex) — 留空表示仅域名"
              value={newFingerprint}
              onChange={(e) => setNewFingerprint(e.target.value)}
            />
            <button
              className="btn-secondary btn-sm"
              disabled={!newDomain.trim() || probing}
              onClick={probeFingerprint}
              title="后端对 domain:443 做 TLS 握手，把 leaf cert SHA256 填进指纹框"
            >
              {probing ? '探测中…' : '🔍 探测指纹'}
            </button>
            <input
              className="input"
              placeholder="备注 (可选)"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
            />
            <button className="btn-primary btn-sm" disabled={!newDomain.trim()} onClick={addTrusted}>
              + 添加
            </button>
          </div>
          {probeMsg && <div className="text-xs muted mb-2">{probeMsg}</div>}
          {trustedError && (
            <div className="alert alert-danger mb-3">
              <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01" />
              </svg>
              {trustedError}
            </div>
          )}

          {/* 列表 */}
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 70 }}>状态</th>
                <th>域名 / Pattern</th>
                <th>SHA256 Fingerprint</th>
                <th>备注</th>
                <th style={{ width: 90 }}>添加时间</th>
                <th style={{ width: 60 }}></th>
              </tr>
            </thead>
            <tbody>
              {trustedLoading && (
                <tr>
                  <td colSpan={6} className="muted text-sm py-4 text-center">加载中…</td>
                </tr>
              )}
              {!trustedLoading && trusted.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted text-sm py-4 text-center">
                    白名单为空。当前 mode={trustMode}：
                    {trustMode === 'enforce' && trusted.length === 0
                      ? ' 由于列表为空，enforce 模式下所有 https 出站会被拦截（建议先加几条再切到 enforce）'
                      : ' 添加你信任的对端域名后，点"保存并应用"下发到 pod'}
                  </td>
                </tr>
              )}
              {trusted.map((t) => (
                <tr key={t.id}>
                  <td>
                    <span className={`badge badge-${t.status === 'active' ? 'green' : 'slate'}`}>{t.status}</span>
                  </td>
                  <td>
                    <code className="text-sm font-mono text-[#171212]">{t.domain_pattern}</code>
                  </td>
                  <td>
                    {t.fingerprint_sha256 ? (
                      <code className="text-[10px] muted-strong">{t.fingerprint_sha256.slice(0, 32)}…</code>
                    ) : (
                      <span className="text-xs muted italic">仅域名（无 pinning）</span>
                    )}
                  </td>
                  <td>
                    <span className="text-xs">{t.label ?? '—'}</span>
                  </td>
                  <td>
                    <span className="text-xs muted">{t.created_at?.slice(0, 10)}</span>
                  </td>
                  <td>
                    <div className="flex gap-2 items-center">
                      {!t.domain_pattern.includes('*') && (
                        <button
                          className="text-xs text-[#0369a1] font-semibold hover:underline disabled:opacity-50"
                          disabled={reprobingId === t.id}
                          onClick={() => reprobeOne(t.id)}
                          title="重新 TLS 握手，与已存基线对比；不一致则告警 + 自动更新基线"
                        >
                          {reprobingId === t.id ? '探测中…' : '重探'}
                        </button>
                      )}
                      <button className="text-xs text-[#dc2626] font-semibold hover:underline" onClick={() => removeTrusted(t.id)}>
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="text-xs muted mt-3 leading-5">
            <strong className="text-[#171212]">行为</strong>：ClawAegisEx 在 <code className="text-[11px] text-[#7a4a30] bg-[#fdf6f1] px-1.5 py-0.5 rounded">before_tool_call</code> 钩子扫描工具参数中的 https/wss URL，
            <code className="text-[11px] text-[#b42318]">host 不在表里 → 阻断</code>；observe 仅告警。支持 <code className="text-[11px] text-[#7a4a30]">*.openai.com</code> 这样的通配域名。改完点"保存并应用"，pod 内 1 秒内 hot-reload 生效。
            <br />
            <strong className="text-[#171212]">证书指纹（Phase 2a）</strong>：新增条目时点"探测指纹"，后端 TLS 握手抓 leaf cert SHA256 并填入；后台每小时自动重探所有 pinned 条目，发现指纹漂移时写入告警并刷新基线（通配条目不参与）。
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default OutboundPage;
