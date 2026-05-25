import React from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';

// 容器隔离 (scenario k) — 对齐 KSecForAIDemo/scenario-k-container.html

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green';

const DIMENSIONS: Array<[string, string, Tone, string, string, number]> = [
  ['进程白名单', 'process', 'red', '⚙', '只允许 openclaw-runtime / node / python', 12],
  ['文件路径访问', 'file', 'orange', '📁', '禁止写 /etc/*，允许读 /etc/ssl/*', 24],
  ['网络 5-tuple', 'network', 'blue', '🌐', '仅允许出站到白名单 FQDN/IP', 8],
  ['能力限制 (capabilities)', 'cap', 'purple', '⚡', 'drop ALL，仅保留 NET_BIND_SERVICE', 4],
];

const POLICIES: Array<[string, string, string, number, Tone]> = [
  ['agent-prod-east-12-strict', '综合', '实例 · openclaw-prod-east-12', 98, 'red'],
  ['agent-finance-svc-baseline', '综合', '实例 · openclaw-finance-svc', 64, 'orange'],
  ['agent-ops-bot-no-shell', '进程', '实例 · openclaw-ops-bot-3', 45, 'red'],
  ['agent-mcp-router-net', '网络', '实例 · openclaw-mcp-router', 74, 'blue'],
  ['agent-prod-west-fs-readonly', '文件', '实例 · openclaw-prod-west-8', 38, 'orange'],
  ['agent-dev-test-1-caps', '能力', '实例 · openclaw-dev-test-1', 12, 'purple'],
  ['agent-staging-7-observe', '综合 (observe)', '实例 · openclaw-staging-7', 24, 'amber'],
];

const ESCAPES: Array<[string, string, string, Tone]> = [
  ['setns', 'openclaw-prod-east-12', '2m', 'red'],
  ['mount', 'openclaw-finance-svc', '15m', 'red'],
  ['unshare', 'openclaw-ops-bot-3', '1h', 'red'],
  ['clone (CLONE_NEWNS)', 'openclaw-staging-7', '2h', 'red'],
];

type MatrixCell = '✓' | 'observe' | '—';
const MATRIX: Array<[string, string, MatrixCell, MatrixCell, MatrixCell, MatrixCell, MatrixCell, Tone]> = [
  ['openclaw-prod-east-12', 'node-east-2', '✓', '✓', '✓', '✓', '✓', 'green'],
  ['openclaw-finance-svc', 'node-east-1', '✓', '✓', '✓', '—', '✓', 'amber'],
  ['openclaw-ops-bot-3', 'node-west-1', '✓', '✓', '✓', '✓', '✓', 'green'],
  ['openclaw-mcp-router', 'node-west-2', '✓', '✓', '✓', '✓', '✓', 'green'],
  ['openclaw-staging-7', 'node-staging-1', 'observe', 'observe', '—', '—', 'observe', 'amber'],
];

const cellClass = (v: MatrixCell) =>
  v === '✓' ? 'tone-green' : v === 'observe' ? 'tone-orange' : 'muted-strong';

const dimBg = (t: Tone) =>
  t === 'red' ? 'bg-red-100' : t === 'orange' ? 'bg-orange-100' : t === 'blue' ? 'bg-blue-100' : 'bg-purple-100';

const ContainerPage: React.FC = () => (
  <AdminLayout>
    <div className="cm-content space-y-6">
      <div className="crumb">
        <Link to="/admin/secplane">安全防护</Link>
        <span>/</span>
        <Link to="/admin/secplane/cat-isolate">环境隔离与安全增强</Link>
        <span>/</span>
        <span className="crumb-current">容器隔离</span>
      </div>

      <div className="panel">
        <div className="hero-block">
          <div className="h-eyebrow">容器策略引擎 / Docker 策略</div>
          <h2 className="h-title">容器隔离</h2>
          <p className="h-subtitle">容器策略（内核级强制）：进程白名单、文件路径访问、网络 5-tuple、能力限制。</p>
        </div>
        <div className="grid grid-cols-4 gap-3 mt-5">
          <div className="stat-card">
            <div className="stat-card-label">受策略保护 Pod</div>
            <div className="stat-card-value">142</div>
            <div className="stat-card-sub muted-strong">覆盖率 100%</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">24h syscall 拦截</div>
            <div className="stat-card-value tone-red">847</div>
            <div className="stat-card-sub muted-strong">内核层强制</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">逃逸尝试</div>
            <div className="stat-card-value tone-red">3</div>
            <div className="stat-card-sub muted-strong">已阻断</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">策略数</div>
            <div className="stat-card-value">28</div>
            <div className="stat-card-sub muted-strong">8 模板 + 20 自定义</div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="eyebrow">容器策略 4 维</div>
            <h3 className="section-title-lg mt-1">进程 + 文件 + 网络 + 能力</h3>
          </div>
          <button className="btn-primary btn-sm">+ 新建策略</button>
        </div>
        <div className="grid grid-cols-4 gap-3">
          {DIMENSIONS.map(([name, , tone, icon, desc, rules]) => (
            <div key={name} className="p-4 rounded-2xl border border-[#eadfd8] bg-white">
              <div className="flex items-center gap-2 mb-2">
                <div className={`w-8 h-8 rounded-xl ${dimBg(tone)} flex items-center justify-center font-bold tone-${tone}`}>{icon}</div>
                <span className="font-semibold text-[#171212]">{name}</span>
              </div>
              <div className="text-xs muted leading-5 mb-2">{desc}</div>
              <div className="flex items-baseline justify-between">
                <span className="text-xs muted-strong">活跃规则</span>
                <span className={`font-bold tone-${tone}`}>{rules}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid gap-4" style={{ gridTemplateColumns: '1fr 360px' }}>
        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="eyebrow">策略列表</div>
              <h3 className="section-title-lg mt-1">活跃 容器策略</h3>
            </div>
            <input className="input" style={{ width: 240 }} placeholder="🔍 搜索策略名..." />
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th>策略名</th>
                <th>类型</th>
                <th>作用范围</th>
                <th>命中</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {POLICIES.map(([name, type, scope, hits, tone]) => (
                <tr key={name}>
                  <td>
                    <span className="font-mono text-sm font-bold text-[#171212]">{name}</span>
                  </td>
                  <td>
                    <span className={`badge badge-${tone === 'amber' ? 'orange' : tone}`}>{type}</span>
                  </td>
                  <td>
                    <span className="text-xs muted">{scope}</span>
                  </td>
                  <td>
                    <span className={`font-bold tone-${tone}`}>{hits}</span>
                  </td>
                  <td>
                    <button className="text-xs text-[#dc2626] font-semibold hover:underline">编辑</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <div className="eyebrow mb-3">容器逃逸监控</div>
          <h3 className="section-title-lg mb-4">高危 syscall 实时</h3>
          <div className="alert alert-danger mb-3">
            <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01" />
            </svg>
            3 次逃逸尝试已拦截
          </div>
          <div className="space-y-2">
            {ESCAPES.map(([sc, inst, time, tone]) => (
              <div key={sc} className="p-2.5 rounded-xl border border-red-200 bg-red-50">
                <div className="flex items-center justify-between">
                  <code className={`text-xs font-bold tone-${tone}`}>{sc}</code>
                  <span className="text-xs muted-strong">{time}</span>
                </div>
                <div className="text-xs muted mt-1 truncate">{inst}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="eyebrow">策略下发矩阵</div>
            <h3 className="section-title-lg mt-1">Pod × 策略生效状态</h3>
          </div>
        </div>
        <table className="tbl">
          <thead>
            <tr>
              <th>实例 (Pod)</th>
              <th>所在主机</th>
              <th>进程白名单</th>
              <th>文件只读</th>
              <th>网络白名单</th>
              <th>能力限制</th>
              <th>逃逸监控</th>
              <th>合规</th>
            </tr>
          </thead>
          <tbody>
            {MATRIX.map(([pod, host, c1, c2, c3, c4, c5, complianceTone]) => (
              <tr key={pod}>
                <td>
                  <span className="font-mono text-xs font-bold">{pod}</span>
                </td>
                <td>
                  <code className="text-xs muted">{host}</code>
                </td>
                {[c1, c2, c3, c4, c5].map((v, i) => (
                  <td key={i}>
                    <span className={`${cellClass(v)} font-bold`}>{v}</span>
                  </td>
                ))}
                <td>
                  <span className={`badge badge-${complianceTone === 'amber' ? 'orange' : complianceTone}`}>
                    {complianceTone === 'green' ? '✓ 100%' : '⚠ 部分'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="text-xs muted text-center mt-3">
          每个实例独立策略下发（实例级），所在主机仅作为元数据展示，不下发命名空间/集群级策略
        </div>
      </div>
    </div>
  </AdminLayout>
);

export default ContainerPage;
