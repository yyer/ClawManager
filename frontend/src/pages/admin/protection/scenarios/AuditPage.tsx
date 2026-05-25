import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';

// 全链路审计 (scenario j) — 对齐 KSecForAIDemo/scenario-j-audit.html
// 数据：当前为 mock，后续接 secplaneService.listAlerts + 跨产品聚合 endpoint

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green';

const TABS = ['实时事件流 (12.8k)', '合规报告', 'Trace 链路查询', '日志归档'] as const;

const EVENTS: Array<[string, string, string, string, string, string, string, Tone]> = [
  ['刚刚', '运行时层', '输入面防护', 'jailbreak-dan-v3', 'openclaw-prod-east-12', '7a3f9c1e', 'BLOCK', 'red'],
  ['1m', '主机层', '容器隔离', 'container-escape-setns', 'openclaw-prod-east-12', '7a3f9c1e', 'BLOCK', 'red'],
  ['1m', '审计', '输出面防护', 'credential-monitor-aws', 'openclaw-finance-svc', 'b2e8d4a7', 'WARN', 'orange'],
  ['2m', '运行时层', '决策面防护', 'dangerous-sql-drop', 'openclaw-ops-bot-3', 'c4f7a1e8', 'APPROVAL', 'orange'],
  ['3m', '主机层', '宿主加固', 'ransomware-yara-hit', 'node-east-3', 'd5c1e8f3', 'KILL', 'red'],
  ['4m', '运行时层', '出站治理', 'outbound-non-allowlist', 'openclaw-mcp-router', 'e9b3d2a6', 'BLOCK', 'red'],
  ['5m', '审计', '组件可信扫描', '供应链 IOC 库-hit', 'skill-prod-v3.1', 'f8a2b9c4', 'BLOCK', 'red'],
  ['7m', '运行时层', '输出面防护', 'output-api-key-redact', 'openclaw-dev-test-1', 'a1b2c3d4', 'REDACT', 'amber'],
];

const SOURCES: Array<[string, Tone, number, string]> = [
  ['运行时层 · 事件流', 'red', 8243, '64%'],
  ['主机层 · feeder gRPC', 'blue', 3104, '24%'],
  ['审计 · 安全审计', 'purple', 1500, '12%'],
];

const SCENE_HITS: Array<[string, number, Tone]> = [
  ['输入面', 2412, 'red'],
  ['决策面', 1872, 'red'],
  ['出站治理', 1234, 'red'],
  ['宿主异常', 847, 'orange'],
  ['组件可信', 623, 'orange'],
  ['输出面', 412, 'orange'],
];

const REPORTS = ['OWASP ASI 覆盖报告', 'MITRE ATLAS 覆盖', 'CSA MAESTRO 报告', '等保 2.0 三级'];

const sourceBadgeTone = (src: string) =>
  src === '运行时层' ? 'badge-red' : src === '主机层' ? 'badge-blue' : 'badge-purple';

const barGradient = (tone: Tone) =>
  tone === 'red'
    ? 'linear-gradient(90deg, #ef6b4a, #dc2626)'
    : tone === 'blue'
    ? 'linear-gradient(90deg, #3b82f6, #1d4ed8)'
    : 'linear-gradient(90deg, #a855f7, #6b21a8)';

const AuditPage: React.FC = () => {
  const [tab, setTab] = useState(0);

  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/cat-govern">监管与运营治理</Link>
          <span>/</span>
          <span className="crumb-current">全链路审计</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">事件流聚合与回溯</div>
            <h2 className="h-title">全链路审计</h2>
            <p className="h-subtitle">安全模块事件流统一聚合到 审计事件 模型。</p>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="stat-card">
              <div className="stat-card-label">24h 事件总数</div>
              <div className="stat-card-value">12,847</div>
              <div className="stat-card-sub muted-strong">运行时层 8.2k + 主机层 3.1k + 审计 1.5k</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">高危事件</div>
              <div className="stat-card-value tone-red">847</div>
              <div className="stat-card-sub muted-strong">已聚合关联</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">Trace 覆盖</div>
              <div className="stat-card-value tone-green">100%</div>
              <div className="stat-card-sub muted-strong">跨产品关联完整</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">事件持久化延迟</div>
              <div className="stat-card-value">3.2s</div>
              <div className="stat-card-sub muted-strong">目标 ≤ 10s</div>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="tabs">
            {TABS.map((t, i) => (
              <button key={i} className={`tab${i === tab ? ' tab-active' : ''}`} onClick={() => setTab(i)}>
                {t}
              </button>
            ))}
          </div>
          <div className="flex items-center justify-between mb-3">
            <h3 className="section-title-lg">{TABS[tab].replace(/\s*\(.*\)\s*$/, '')}</h3>
            <div className="flex gap-2">
              <select className="input" style={{ width: 140 }}>
                <option>全部来源</option>
                <option>运行时层</option>
                <option>主机层</option>
                <option>审计层</option>
              </select>
              <select className="input" style={{ width: 140 }}>
                <option>全部场景</option>
                <option>输入面</option>
                <option>决策面</option>
                <option>输出面</option>
                <option>出站治理</option>
                <option>宿主加固</option>
              </select>
              <select className="input" style={{ width: 140 }}>
                <option>全部严重度</option>
                <option>严重</option>
                <option>高</option>
                <option>中</option>
                <option>观察</option>
              </select>
              <input className="input" style={{ width: 240 }} placeholder="🔍 Trace ID / 实例..." />
              <button className="btn-secondary btn-sm">导出 JSONL</button>
            </div>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 80 }}>时间</th>
                <th style={{ width: 90 }}>来源</th>
                <th style={{ width: 120 }}>防护场景</th>
                <th>规则</th>
                <th>实例</th>
                <th>Trace ID</th>
                <th style={{ width: 90 }}>动作</th>
                <th style={{ width: 50 }}></th>
              </tr>
            </thead>
            <tbody>
              {EVENTS.map(([t, src, sc, rule, inst, trace, act, tone], i) => (
                <tr key={i}>
                  <td>
                    <span className="muted-strong text-xs">{t}</span>
                  </td>
                  <td>
                    <span className={`badge ${sourceBadgeTone(src)}`}>{src}</span>
                  </td>
                  <td>
                    <span className="text-xs font-medium text-[#171212]">{sc}</span>
                  </td>
                  <td>
                    <code className="text-xs">{rule}</code>
                  </td>
                  <td>
                    <span className="font-mono text-xs">{inst}</span>
                  </td>
                  <td>
                    <code className="text-xs muted">{trace}</code>
                  </td>
                  <td>
                    <span className={`badge badge-${tone === 'amber' ? 'orange' : tone}`}>{act}</span>
                  </td>
                  <td>
                    <button className="icon-btn" aria-label="详情">
                      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div className="panel">
            <div className="eyebrow mb-3">事件来源分布</div>
            <h3 className="section-title-lg mb-4">安全模块事件比例</h3>
            <div className="space-y-3">
              {SOURCES.map(([name, tone, count, pct]) => (
                <div key={name}>
                  <div className="flex justify-between mb-1">
                    <span className="text-sm font-semibold text-[#171212]">{name}</span>
                    <span className={`text-sm font-bold tone-${tone}`}>
                      {count.toLocaleString()} ({pct})
                    </span>
                  </div>
                  <div className="mini-bar-track">
                    <div
                      className="mini-bar-fill"
                      style={{ width: pct, background: barGradient(tone) }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <div className="eyebrow mb-3">攻击链场景分布</div>
            <h3 className="section-title-lg mb-4">防护场景命中次数</h3>
            <div className="space-y-2 text-sm">
              {SCENE_HITS.map(([name, n, tone]) => (
                <div key={name} className="flex items-center justify-between p-2 rounded-lg hover:bg-[#fdf6f1]">
                  <span className="text-[#171212]">{name}</span>
                  <span className={`font-bold tone-${tone}`}>{n}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <div className="eyebrow mb-3">合规导出</div>
            <h3 className="section-title-lg mb-4">审计报告生成</h3>
            <div className="space-y-2 mb-4">
              {REPORTS.map((r) => (
                <button key={r} className="btn-secondary btn-sm w-full justify-start">
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2"
                      d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"
                    />
                  </svg>
                  {r}
                </button>
              ))}
            </div>
            <div className="alert alert-success">
              <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4" />
              </svg>
              OWASP ASI 10/10 完整覆盖
            </div>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default AuditPage;
