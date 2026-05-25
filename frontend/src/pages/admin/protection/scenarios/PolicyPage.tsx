import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';

// 策略治理 (scenario m) — 对齐 KSecForAIDemo/scenario-m-policy.html

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green' | 'teal' | 'slate';

const SCOPES: Array<[string, string, Tone, string, number, string, string]> = [
  ['1', '主机级 Host', 'blue', '下发到节点：CIS 加固 / 勒索软件防护 / 挖矿检测 / 入侵检测 / 文件保护', 12, '#1d4ed8', '本期范围 · 主机策略'],
  ['2', '实例级 Instance', 'orange', '下发到单个智能体 Pod：输入/状态/决策/输出/出站/容器策略', 22, '#b45309', '本期范围 · 运行时层 安全策略配置 + 容器策略'],
];

const TARGETS: Array<[string, string]> = [
  ['运行时层', '安全策略配置.toolCallGov[]'],
  ['主机层', 'gRPC containerPolicy.yaml'],
  ['审计', '安全基线配置.rules[]'],
];

const TABS = ['活跃策略 (34)', '策略模板 (12)', '变更审计 (本周 12)', '一致性校验'] as const;

type Mode = 'enforce' | 'observe' | 'off';
const POLICIES: Array<[string, string, 'host' | 'instance', string, Mode, string, string]> = [
  ['cis-host-baseline', '宿主加固', 'host', 'node-east-1, node-east-2, +6', 'enforce', '✓ 同步', '2h 前 / 张三'],
  ['ransome-host-guard', '宿主加固', 'host', '所有节点 (8)', 'enforce', '✓ 同步', '5h 前 / 李四'],
  ['agent-prod-strict', '输入面 · 决策面 · 输出面', 'instance', 'openclaw-prod-east-12', 'enforce', '✓ 同步', '1h 前 / 张三'],
  ['agent-finance-bot', '决策面 · 出站治理', 'instance', 'openclaw-finance-svc', 'enforce', '✓ 同步', '1d 前 / 李四'],
  ['observation-mode-test', '输入面 · 决策面 · 输出面', 'instance', 'openclaw-staging-7', 'observe', '✓ 同步', '3d 前 / 王五'],
  ['emergency-deny-east12', '应急熔断', 'instance', 'openclaw-prod-east-12', 'enforce', '✓ 同步', '23m 前 / SYSTEM'],
];

const TEMPLATES: Array<[string, string, Tone, number]> = [
  ['金融严格模板', '含 SQL/审批/出站白名单完整规则集', 'red', 12],
  ['生产标准模板', '基线安全 + 日志审计', 'blue', 8],
  ['开发观察模式', '所有规则 observe，便于调试', 'amber', 6],
  ['测试沙箱模板', '宽松限制 + 行为记录', 'slate', 4],
  ['MCP 服务模板', 'MCP 协议专用 + 客户端证书', 'teal', 5],
  ['多 Agent 协同', 'agent-mesh + 双向认证', 'purple', 7],
];

const RULE_JSON = `{
  "rule_id": "block-sql-drop",
  "scope": {
    "type": "instance",
    "target": "openclaw-finance-svc"
  },
  "match": {
    "tool": "mysql_exec",
    "pattern": "DROP\\\\s+TABLE\\\\s+.*"
  },
  "action": "block",
  "severity": "high"
}`;

const targetBadge = (t: string) => (t === '运行时层' ? 'badge-red' : t === '主机层' ? 'badge-blue' : 'badge-purple');
const modeBadge = (m: Mode) => (m === 'enforce' ? 'badge-red' : m === 'observe' ? 'badge-orange' : 'badge-slate');

const PolicyPage: React.FC = () => {
  const [tab, setTab] = useState(0);
  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/cat-policy">安全策略与模板</Link>
          <span>/</span>
          <span className="crumb-current">策略治理</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">统一策略中心 + 模板</div>
            <h2 className="h-title">策略治理</h2>
            <p className="h-subtitle">
              统一聚合安全模块策略到 统一风险规则 体系。<strong>两层作用域（主机级 + 实例级）</strong>+ 策略编译器 → 异构格式协议。
            </p>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="stat-card">
              <div className="stat-card-label">活跃策略</div>
              <div className="stat-card-value">34</div>
              <div className="stat-card-sub muted-strong">12 模板 + 22 自定义</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">同步</div>
              <div className="stat-card-value tone-green">100%</div>
              <div className="stat-card-sub muted-strong">99.5% 一致性</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">本周变更</div>
              <div className="stat-card-value tone-orange">12</div>
              <div className="stat-card-sub muted-strong">含完整审计</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">策略模板</div>
              <div className="stat-card-value">12</div>
              <div className="stat-card-sub muted-strong">基于 审计 baseline</div>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="eyebrow mb-3">两层作用域</div>
          <h3 className="section-title-lg mb-4">策略下发结构（仅主机级 + 实例级）</h3>
          <div className="grid grid-cols-2 gap-4">
            {SCOPES.map(([n, name, , desc, count, color, tip]) => (
              <div key={n} className="p-5 rounded-2xl border-2 bg-white" style={{ borderColor: color }}>
                <div className="flex items-center gap-2 mb-3">
                  <div
                    className="w-9 h-9 rounded-xl flex items-center justify-center font-bold text-white text-sm"
                    style={{ background: color }}
                  >
                    {n}
                  </div>
                  <span className="font-bold text-[#171212]">{name}</span>
                </div>
                <div className="text-xs muted leading-5 mb-3">{desc}</div>
                <div className="flex items-baseline justify-between">
                  <span className="text-xs muted-strong">活跃规则</span>
                  <span className="text-3xl font-bold" style={{ color }}>
                    {count}
                  </span>
                </div>
                <div className="text-[10px] muted-strong mt-2 italic">{tip}</div>
              </div>
            ))}
          </div>
          <div className="alert alert-info mt-4">
            <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            本期范围：仅做主机级与实例级防护。命名空间级 / 集群级策略下发不在当前实现范围（后续版本扩展）。
          </div>
        </div>

        <div className="panel">
          <div className="eyebrow mb-3">策略编译器</div>
          <h3 className="section-title-lg mb-4">统一 风险规则 → 异构格式协议</h3>
          <div className="grid gap-6 items-center" style={{ gridTemplateColumns: '1fr auto 1fr' }}>
            <div className="panel-warm">
              <div className="eyebrow text-[10px] mb-2">输入：风险规则（ClawManager 统一格式）</div>
              <pre className="code-block text-[11px]">{RULE_JSON}</pre>
            </div>
            <svg width="40" height="40" fill="none" viewBox="0 0 24 24" stroke="currentColor" className="muted">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
            </svg>
            <div className="space-y-2">
              {TARGETS.map(([key, path]) => (
                <div key={key} className="p-3 rounded-xl bg-white border border-[#eadfd8] flex items-center gap-2">
                  <span className={`badge ${targetBadge(key)}`}>{key}</span>
                  <code className="text-xs flex-1">{path}</code>
                  <span className="text-xs tone-green font-bold">✓ 同步</span>
                </div>
              ))}
            </div>
          </div>
          <div className="alert alert-info mt-4">
            <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            每 5 分钟自动校验各配置一致性，发现漂移自动重发并告警
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
            <h3 className="section-title-lg">策略清单</h3>
            <div className="flex gap-2">
              <select className="input" style={{ width: 140 }}>
                <option>全部作用域</option>
                <option>主机级</option>
                <option>实例级</option>
              </select>
              <select className="input" style={{ width: 140 }}>
                <option>全部场景</option>
                <option>输入面</option>
                <option>决策面</option>
                <option>出站治理</option>
                <option>宿主加固</option>
              </select>
              <input className="input" style={{ width: 240 }} placeholder="🔍 搜索规则..." />
              <button className="btn-primary btn-sm">+ 新建策略</button>
            </div>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th>策略名</th>
                <th style={{ width: 180 }}>防护场景</th>
                <th>作用域</th>
                <th>目标</th>
                <th>模式</th>
                <th>同步</th>
                <th>最近更新</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {POLICIES.map(([name, sc, scope, target, mode, sync, upd]) => (
                <tr key={name}>
                  <td>
                    <span className="font-semibold text-[#171212]">{name}</span>
                  </td>
                  <td>
                    <span className="text-xs font-medium text-[#171212]">{sc}</span>
                  </td>
                  <td>
                    <span className={`badge ${scope === 'host' ? 'badge-blue' : 'badge-orange'}`}>
                      {scope === 'host' ? '主机级' : '实例级'}
                    </span>
                  </td>
                  <td>
                    <span className="text-xs font-mono muted truncate inline-block" style={{ maxWidth: 200 }}>
                      {target}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${modeBadge(mode)}`}>{mode.toUpperCase()}</span>
                  </td>
                  <td>
                    <span className="text-xs tone-green font-semibold">{sync}</span>
                  </td>
                  <td>
                    <span className="text-xs muted">{upd}</span>
                  </td>
                  <td>
                    <button className="icon-btn">
                      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 5v.01M12 12v.01M12 19v.01" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="eyebrow">安全策略模板库</div>
              <h3 className="section-title-lg mt-1">基于 安全审计引擎 安全基线配置 派生</h3>
            </div>
          </div>
          <div className="grid grid-cols-4 gap-3">
            {TEMPLATES.map(([name, desc, tone, refs]) => (
              <div
                key={name}
                className="p-4 rounded-2xl border border-[#eadfd8] bg-white hover:border-[#ef6b4a] hover:shadow-md transition cursor-pointer"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-[#171212] text-sm">{name}</span>
                  <span className={`badge badge-${tone === 'teal' ? 'green' : tone}`}>{refs} 规则</span>
                </div>
                <div className="text-xs muted leading-5">{desc}</div>
                <div className="divider" />
                <button className="btn-secondary btn-sm w-full text-xs">一键应用</button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default PolicyPage;
