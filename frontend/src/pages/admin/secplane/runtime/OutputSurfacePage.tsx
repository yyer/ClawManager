import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';
import ApplyDispatchButton from '../../../../components/secplane/ApplyDispatchButton';
import { useInstanceHealth } from './useInstanceHealth';
import { useSurfaceBackend } from './useSurfaceBackend';
import { FEATURES } from '../../../../config/features';

// 输出面防护 (scenario d) — 对齐 KSecForAIDemo/scenario-d-output.html
// 接 backend：defense.outputRedaction toggle + apply + 实时脱敏 alerts

const ALERT_PREFIXES = ['defense.outputRedaction', 'output_redaction'];

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green' | 'slate';

type Category = '凭据' | 'PII' | 'PCI' | '网络';

const PRIVACY_RULES: Array<[string, string, Category, string, Tone, string, string]> = [
  ['api-key',     'API Key',     '凭据',  'OpenAI / Anthropic / AWS / GCP API 密钥',     'red',    '严重', 'sk-***  /  sk-ant-***'],
  ['jwt',         'JWT Token',   '凭据',  'JSON Web Token (3 段 base64)',                 'red',    '严重', 'eyJ***.***.***'],
  ['aws-secret',  'AWS Secret',  '凭据',  'aws_access_key_id / aws_secret_access_key',    'red',    '严重', 'AKIA***'],
  ['ssh-key',     'SSH Key',     '凭据',  '私钥头部 / passphrase',                         'red',    '严重', '-----BEGIN ***-----'],
  ['id-card',     '身份证号',     'PII',  '中国大陆 18 位身份证（含校验位）',                'red',    '严重', '310***********X'],
  ['email',       'Email',       'PII',   '邮箱地址（含用户名 / 域名）',                    'orange', '高',   '***@***.com'],
  ['phone',       'Phone',       'PII',   '中国 / 国际手机号',                              'orange', '高',   '138****5678'],
  ['credit-card', 'Credit Card', 'PCI',   'Visa / Master / Amex / 银联卡号（Luhn 校验）',   'red',    '严重', '****-****-****-1234'],
  ['ip-addr',     'IP 地址',      '网络',  '内网 IP / 公网 IP / IPv6',                      'amber',  '中',   '10.***.***.***'],
];

const CRED_ALERTS: Array<[string, string, string, Tone, string]> = [
  ['openclaw-prod-east-12', '/etc/openclaw/config.yaml:42', 'AWS Secret', 'red', '严重'],
  ['openclaw-finance-svc', '~/.openai-config.json:8', 'API Key', 'red', '严重'],
  ['openclaw-finance-svc', 'skill-finance/handler.js:87', 'API Key', 'red', '严重'],
  ['openclaw-ops-bot-3', 'secret/db-conn.env:12', 'DB Password', 'orange', '高'],
  ['openclaw-staging-7', 'skills/qa-bot/keys.txt:1', 'JWT', 'red', '严重'],
];

const catBadge = (c: Category) => (c === '凭据' || c === 'PCI' ? 'badge-red' : c === 'PII' ? 'badge-orange' : 'badge-slate');

const OutputSurfacePage: React.FC = () => {
  const { alerts, dispatching, dispatchMsg, modeOf, setMode, dispatchApply } = useSurfaceBackend(ALERT_PREFIXES);
  const { instances, healthy } = useInstanceHealth();
  const enabled = modeOf('defense.outputRedaction', 'enforce') !== 'off';
  const toggleEnabled = () => setMode('defense.outputRedaction', enabled ? 'off' : 'enforce');
  const [resolved, setResolved] = useState<Set<number>>(new Set());

  const exportJsonl = () => {
    const text = alerts.map((a) => JSON.stringify(a)).join('\n');
    const blob = new Blob([text], { type: 'application/jsonl' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `output-surface-alerts-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.jsonl`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AdminLayout title="安全防护">
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/runtime">智能体运行时安全</Link>
          <span>/</span>
          <span className="crumb-current">输出面防护</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">凭据/隐私脱敏</div>
            <h2 className="h-title">输出面防护</h2>
            <p className="h-subtitle">智能体输出返回用户/写入日志前自动遮蔽敏感数据；持续监控凭据泄露与明文存储。</p>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="stat-card">
              <div className="stat-card-label">脱敏开关</div>
              <div className={`stat-card-value ${enabled ? 'tone-green' : 'tone-orange'}`}>{enabled ? '已启用' : '已关闭'}</div>
              <div className="stat-card-sub muted-strong">outputRedaction · before_message_write</div>
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
              <div className="eyebrow">输出脱敏 · 二态总开关 · 9 类敏感数据</div>
              <h3 className="section-title-lg mt-1">敏感数据自动识别与脱敏</h3>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs muted-strong">脱敏开关</span>
              <button
                role="switch"
                aria-checked={enabled}
                onClick={toggleEnabled}
                style={{ width: 38, height: 22, borderRadius: 11, background: enabled ? '#2563eb' : '#cbd5e1', position: 'relative', cursor: 'pointer', flexShrink: 0, transition: 'background .15s', border: 'none' }}
              >
                <div style={{ width: 18, height: 18, borderRadius: 9, background: 'white', position: 'absolute', top: 2, left: enabled ? 18 : 2, transition: 'left .15s', boxShadow: '0 1px 3px rgba(0,0,0,0.15)' }} />
              </button>
              <ApplyDispatchButton onDispatch={dispatchApply} busy={dispatching} className="btn-primary btn-sm" triggerLabel="保存并应用" />
              {dispatchMsg && <span className="text-xs muted ml-2">{dispatchMsg}</span>}
            </div>
          </div>
          <div className="space-y-2.5">
            {PRIVACY_RULES.map(([key, name, category, desc, tone, sev, mask]) => (
              <div key={key} className="flex items-center gap-4 p-4 rounded-2xl border border-[#eadfd8] bg-white">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-semibold text-[#171212]">{name}</span>
                    <span className={`badge ${catBadge(category)} text-[9px]`}>{category}</span>
                    <span className={`badge badge-${tone} text-[9px]`}>{sev}</span>
                  </div>
                  <div className="text-xs muted mb-1">{desc}</div>
                  <code className="block text-[10px] muted-strong bg-[#fdf6f1] px-2 py-1 rounded font-mono truncate" style={{ maxWidth: 420 }}>
                    脱敏示例：{mask}
                  </code>
                </div>
              </div>
            ))}
          </div>
        </div>

        {FEATURES.credentialInventory && <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="eyebrow">存量凭据巡检</div>
              <h3 className="section-title-lg mt-1">本地存储明文凭据告警</h3>
            </div>
            <button className="btn-primary btn-sm">立即扫描</button>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {CRED_ALERTS.map(([inst, loc, type, tone, sev], i) => {
              const isResolved = resolved.has(i);
              return (
                <div
                  key={i}
                  className="p-3 rounded-xl border border-[#f4b6b3] bg-[#fdeded]"
                  style={isResolved ? { opacity: 0.55, background: '#f5f5f4', textDecoration: 'line-through' } : {}}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[9px] muted-strong tracking-wider">实例</span>
                    <code className="text-[11px] font-mono text-[#7a4a30]">{inst}</code>
                  </div>
                  <code className="text-xs text-[#b42318] font-mono break-all block">{loc}</code>
                  <div className="flex items-center justify-between mt-2">
                    <div className="flex items-center gap-1.5">
                      <span className={`badge badge-${tone} text-[9px]`}>{sev}</span>
                      <span className="text-xs muted-strong">{type}</span>
                    </div>
                    <button
                      className="text-xs tone-red font-semibold hover:underline"
                      onClick={() =>
                        setResolved((s) => {
                          const n = new Set(s);
                          if (n.has(i)) n.delete(i);
                          else n.add(i);
                          return n;
                        })
                      }
                      style={isResolved ? { color: '#059669', textDecoration: 'none' } : {}}
                    >
                      {isResolved ? '已处置 ✓ · 撤销' : '标记为已处理'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>}

        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="eyebrow">实时脱敏事件流</div>
              <h3 className="section-title-lg mt-1">智能体输出脱敏日志</h3>
            </div>
            <button
              className="btn-secondary btn-sm"
              onClick={exportJsonl}
              disabled={alerts.length === 0}
            >
              导出 JSONL
            </button>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 80 }}>时间</th>
                <th>实例</th>
                <th>规则</th>
                <th>原文 / 证据</th>
                <th style={{ width: 80 }}>动作</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 && (
                <tr>
                  <td colSpan={5} className="text-xs muted" style={{ textAlign: 'center', padding: 20 }}>
                    暂无脱敏事件
                  </td>
                </tr>
              )}
              {alerts.slice(0, 50).map((a) => (
                <tr key={a.id}>
                  <td><span className="muted-strong text-xs">{a.ts?.replace('T', ' ').slice(11, 19)}</span></td>
                  <td><span className="font-mono text-xs">{a.agent_id ?? '—'}</span></td>
                  <td><span className="badge badge-red">{a.rule_name ?? a.rule_id ?? '—'}</span></td>
                  <td><code className="text-xs text-[#171212] truncate inline-block" style={{ maxWidth: 340 }}>{a.evidence ?? '—'}</code></td>
                  <td><span className={`badge badge-${a.action === 'block' ? 'red' : a.action === 'redact' ? 'orange' : 'slate'}`}>{a.action}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {alerts.length > 0 && (
            <div className="text-xs muted mt-3 text-center">
              共 {alerts.length} 条 · 表中最多展示 50 行
            </div>
          )}
        </div>
      </div>

    </AdminLayout>
  );
};

export default OutputSurfacePage;
