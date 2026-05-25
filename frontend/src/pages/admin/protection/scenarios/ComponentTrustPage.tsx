import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';

// 组件可信扫描 (scenario e) — 对齐 KSecForAIDemo/scenario-e-trust.html

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green' | 'teal' | 'yellow';

const SCANNERS: Array<[string, string, string, Tone, number, number]> = [
  ['运行时层', '技能毒化防护', '静态语义扫描技能内容', 'red', 5, 12],
  ['审计层', '技能扫描脚本 + IOC', '供应链 IOC 库 比对+漏洞情报', 'purple', 7, 8],
  ['主机层', '镜像策略推荐', '容器镜像策略推荐 + CVE 扫描', 'blue', 2, 18],
];

const TABS = ['扫描结果 (472)', '可信清单 (412)', 'IOC 数据库 (1,247)', 'CVE 情报 (3,892)'] as const;

const ASSETS: Array<[string, string, 'skill' | 'plugin' | 'image', string, Tone, string, string, number]> = [
  ['prod-skill-v3.1', '含 supply-chain IOC + base64 反向 shell', 'skill', 'CRITICAL', 'purple', '运行时层:1·审计:2·主机层:0', '5m', 12],
  ['finance-handler-2.0', '明文 API Key + JWT 硬编码', 'skill', 'HIGH', 'red', '运行时层:1·审计:1·主机层:0', '12m', 8],
  ['mcp-data-proxy:1.4.2', '含 log4j-mock CVE-2021-44228', 'image', 'CRITICAL', 'purple', '运行时层:0·审计:1·主机层:5', '18m', 3],
  ['claude-skill-v2', '已通过完整扫描', 'skill', 'SAFE', 'green', '无', '1h', 42],
  ['vector-search-plugin', '含已知 CVE-2024-1234 (LOW)', 'plugin', 'LOW', 'yellow', '审计:1', '2h', 15],
  ['internal-rag-bot-v1', '已通过完整扫描', 'skill', 'SAFE', 'green', '无', '3h', 28],
];

const typeBadge = (t: 'skill' | 'plugin' | 'image') => (t === 'skill' ? 'badge-purple' : t === 'plugin' ? 'badge-green' : 'badge-blue');
const typeLabel = (t: 'skill' | 'plugin' | 'image') => (t === 'skill' ? 'Skill' : t === 'plugin' ? 'Plugin' : 'Image');

const ComponentTrustPage: React.FC = () => {
  const [tab, setTab] = useState(0);
  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/cat-trust">数据与组件可信</Link>
          <span>/</span>
          <span className="crumb-current">组件可信扫描</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">技能/插件/依赖/镜像供应链</div>
            <h2 className="h-title">组件可信扫描</h2>
            <p className="h-subtitle">
              智能体加载前的异步扫描调度。三扫描器并行：技能毒化防护 + 技能扫描 + 镜像策略推荐。结果作为实例启动准入条件。
            </p>
          </div>
          <div className="grid grid-cols-4 gap-3 mt-5">
            <div className="stat-card">
              <div className="stat-card-label">总资产</div>
              <div className="stat-card-value">486</div>
              <div className="stat-card-sub muted-strong">技能 312 · 插件 92 · 镜像 82</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">已扫描</div>
              <div className="stat-card-value tone-green">472</div>
              <div className="stat-card-sub muted-strong">覆盖率 97.1%</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">CRITICAL</div>
              <div className="stat-card-value tone-purple">3</div>
              <div className="stat-card-sub muted-strong">阻断启动</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">HIGH</div>
              <div className="stat-card-value tone-red">18</div>
              <div className="stat-card-sub muted-strong">需关注</div>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="eyebrow">扫描引擎并行</div>
              <h3 className="section-title-lg mt-1">扫描器状态与队列</h3>
            </div>
            <button className="btn-primary btn-sm">
              <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              触发全量扫描
            </button>
          </div>
          <div className="grid grid-cols-3 gap-3">
            {SCANNERS.map(([key, name, desc, tone, running, queued]) => (
              <div key={name} className="p-5 rounded-2xl border border-[#eadfd8] bg-white">
                <div className="flex items-center gap-2 mb-3">
                  <span className={`badge badge-${tone}`}>{key}</span>
                  <span className="dot bg-green-500" />
                  <span className="text-xs muted-strong">运行中</span>
                </div>
                <div className="font-semibold text-[#171212] mb-1">{name}</div>
                <div className="text-xs muted mb-3 leading-5">{desc}</div>
                <div className="flex gap-4 text-xs">
                  <div>
                    <span className="muted">进行中</span> <span className="font-bold tone-orange ml-1">{running}</span>
                  </div>
                  <div>
                    <span className="muted">队列</span> <span className="font-bold ml-1">{queued}</span>
                  </div>
                </div>
                <div className="divider" />
                <button className="btn-secondary btn-sm w-full">查看队列</button>
              </div>
            ))}
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
            <div>
              <h3 className="section-title-lg">所有扫描资产</h3>
            </div>
            <div className="flex gap-2">
              <select className="input" style={{ width: 140 }}>
                <option>全部类型</option>
                <option>技能 (Skill)</option>
                <option>插件 (Plugin)</option>
                <option>镜像 (Image)</option>
                <option>依赖 (Dependency)</option>
              </select>
              <select className="input" style={{ width: 140 }}>
                <option>全部严重度</option>
                <option>CRITICAL</option>
                <option>HIGH</option>
                <option>MEDIUM</option>
                <option>SAFE</option>
              </select>
              <input className="input" style={{ width: 240 }} placeholder="🔍 搜索资产名/key..." />
            </div>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th>资产</th>
                <th style={{ width: 90 }}>类型</th>
                <th style={{ width: 120 }}>综合结论</th>
                <th style={{ width: 160 }}>扫描器命中</th>
                <th style={{ width: 110 }}>最近扫描</th>
                <th style={{ width: 90 }}>实例引用</th>
                <th style={{ width: 60 }}></th>
              </tr>
            </thead>
            <tbody>
              {ASSETS.map(([name, desc, type, sev, sevTone, hits, time, inst], i) => (
                <tr key={i}>
                  <td>
                    <div className="font-semibold text-[#171212]">{name}</div>
                    <div className="text-xs muted mt-0.5">{desc}</div>
                  </td>
                  <td>
                    <span className={`badge ${typeBadge(type)}`}>{typeLabel(type)}</span>
                  </td>
                  <td>
                    <span className={`badge ${sev === 'CRITICAL' ? 'badge-purple' : 'badge-' + sevTone}`}>{sev}</span>
                  </td>
                  <td>
                    <code className="text-xs muted-strong">{hits}</code>
                  </td>
                  <td>
                    <span className="text-xs muted-strong">{time}</span>
                  </td>
                  <td>
                    <span className="font-bold text-[#171212]">{inst}</span>
                  </td>
                  <td>
                    <button className="icon-btn">
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
      </div>
    </AdminLayout>
  );
};

export default ComponentTrustPage;
