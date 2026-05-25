import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';

// 宿主加固 (scenario l) — 对齐 KSecForAIDemo/scenario-l-host.html
// 5 tabs: CIS 基线矩阵 + 勒索防护 + 挖矿检测 + 入侵检测 + 文件保护
// 当前为静态展示版，后续接 host-side agent 实时 metrics

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green' | 'slate';
type CISStat = 'ok' | 'warn' | 'fail';

const NODES = ['east-1', 'east-2', 'east-3', 'west-1', 'west-2', 'staging', 'test', 'canary'];

const CIS_ITEMS: Array<[string, string, string, CISStat[]]> = [
  ['1.1', 'PAM 最小密码长度', 'PAM', ['ok', 'ok', 'fail', 'ok', 'warn', 'ok', 'ok', 'ok']],
  ['1.2', 'PAM 复杂度要求', 'PAM', ['ok', 'ok', 'fail', 'ok', 'ok', 'ok', 'ok', 'ok']],
  ['2.1', '账户失败锁定', '账户', ['ok', 'warn', 'fail', 'ok', 'ok', 'ok', 'ok', 'ok']],
  ['2.2', '密码最大有效期', '账户', ['ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok']],
  ['3.1', 'SSH 禁用 root 登录', 'SSH', ['ok', 'warn', 'fail', 'fail', 'ok', 'warn', 'ok', 'ok']],
  ['3.2', 'SSH 禁用密码登录', 'SSH', ['ok', 'ok', 'fail', 'ok', 'ok', 'ok', 'ok', 'ok']],
  ['3.3', 'SSH 协议仅 v2', 'SSH', ['ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok']],
  ['4.1', 'sysctl 内核加固', '内核', ['ok', 'ok', 'warn', 'ok', 'ok', 'ok', 'ok', 'ok']],
  ['4.2', '内核模块签名', '内核', ['ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok']],
];

const RANSOM_DIRS: Array<[string, 'enforce' | 'observe', number, string, Tone]> = [
  ['/var/lib/openclaw/memory', 'enforce', 8, '2 分钟前', 'red'],
  ['/var/lib/openclaw/skills', 'enforce', 5, '15 分钟前', 'red'],
  ['/etc/openclaw/*', 'enforce', 3, '1 小时前', 'orange'],
  ['/root/*.key', 'enforce', 2, '3 小时前', 'orange'],
  ['/home/*/personal/*', 'observe', 0, '-', 'slate'],
  ['/var/backup', 'enforce', 0, '-', 'green'],
];

const RANSOM_HITS: Array<[string, string, string, string, string, string, Tone]> = [
  ['刚刚', 'node-east-3', 'suspicious-encryptor', '/tmp/.cache/abc', '247 次 unlink/分钟', 'BLOCK + KILL pid 8721', 'red'],
  ['15 分钟前', 'node-canary-1', 'curl-rename-batch', '/tmp/x.sh', '可疑批量文件重命名 (146 次)', 'OBSERVE → 待处置', 'orange'],
  ['2 小时前', 'node-east-2', 'xmrig-variant', '/var/tmp/proc1', 'XMRig YARA 签名命中', 'BLOCK + KILL pid 4231', 'red'],
  ['5 小时前', 'node-west-1', 'python-encrypt', '/usr/bin/python3', '短时间内 50 次 .lock 写入', 'OBSERVE', 'amber'],
];

const MINING_ITEMS: Array<[string, string, boolean, number]> = [
  ['矿池域名解析', '枚举已知矿池域名 IOC', true, 142],
  ['矿池 IP 连接', 'TCP 连接已知矿池端口', true, 38],
  ['CPU 异常占用', '持续 >95% 异常', true, 7],
  ['病毒签名匹配', 'XMRig/Coinhive YARA', true, 5],
];

const INTRUSION_RULES: Array<[string, string, number, string, Tone]> = [
  ['SSH 暴力破解', '同 IP 5 分钟内 ≥10 次失败', 24, '刚刚', 'red'],
  ['可疑命令执行', 'wget|curl 下载 + chmod +x + exec', 12, '5m', 'orange'],
  ['敏感目录写入', 'cron / systemd unit 文件修改', 8, '20m', 'red'],
  ['提权尝试', 'sudo + suid 异常执行', 5, '1h', 'orange'],
  ['可疑端口监听', 'bind 到非常用端口（>1024 持续）', 3, '2h', 'amber'],
];

const FILE_PROT: Array<[string, string, string, string, number, Tone]> = [
  ['/etc/passwd /etc/shadow', '主机', 'hash baseline', '✓ 漂移检测启用', 0, 'green'],
  ['/etc/openclaw/openclaw.json', '主机', 'hash baseline', '✓ 已基线', 0, 'green'],
  ['/var/lib/openclaw/memory/*', '实例', 'enforce', '⚠ 漂移 (差 5 个文件)', 5, 'orange'],
  ['/root/.ssh/authorized_keys', '主机', 'enforce', '✓ 已基线', 0, 'green'],
  ['~/.openclaw/skills/*', '实例', 'enforce', '⚠ 漂移 (差 2)', 2, 'orange'],
];

const TABS = [
  { id: 'cis', label: 'CIS 基线 (22)' },
  { id: 'ransom', label: '勒索防护' },
  { id: 'mining', label: '挖矿检测' },
  { id: 'invasion', label: '入侵检测' },
  { id: 'file', label: '文件保护' },
] as const;

type TabId = (typeof TABS)[number]['id'];

const cisCellClass: Record<CISStat, string> = {
  ok: 'bg-green-100 text-[#177245] border border-green-300',
  warn: 'bg-orange-100 text-[#b45309] border border-orange-300',
  fail: 'bg-red-100 text-[#b42318] border border-red-300',
};
const cisCellIcon: Record<CISStat, string> = { ok: '✓', warn: '!', fail: '✗' };

const HostHardeningPage: React.FC = () => {
  const [tab, setTab] = useState<TabId>('cis');
  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/cat-isolate">环境隔离与安全增强</Link>
          <span>/</span>
          <span className="crumb-current">宿主加固</span>
        </div>

        <div className="panel">
          <div className="flex items-start justify-between gap-6 mb-5">
            <div className="hero-block flex-1">
              <div className="h-eyebrow">CIS 基线 + 主机异常检测</div>
              <h2 className="h-title">宿主加固中心</h2>
              <p className="h-subtitle">
                CIS 风格主机加固基线 + 4 个安全模块（勒索防护 / 挖矿检测 / 入侵检测 / 文件保护）。所有加固操作遵循 Check → Reinforce → BackUp → RollBack 安全生命周期。
              </p>
            </div>
            <div className="flex flex-col gap-2 shrink-0">
              <button className="btn-secondary">全量 Check</button>
              <button className="btn-primary">批量加固</button>
            </div>
          </div>
          <div className="grid grid-cols-4 gap-3">
            <div className="stat-card">
              <div className="stat-card-label">集群节点</div>
              <div className="stat-card-value">8</div>
              <div className="stat-card-sub muted-strong">3 全加固 · 4 部分 · 1 未加固</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">CIS items</div>
              <div className="stat-card-value">22</div>
              <div className="stat-card-sub muted-strong">4 大类</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">24h 高危告警</div>
              <div className="stat-card-value tone-red">8</div>
              <div className="stat-card-sub muted-strong">勒索 3 · 挖矿 2 · 入侵 3</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">受保护文件</div>
              <div className="stat-card-value tone-green">238</div>
              <div className="stat-card-sub muted-strong">主机+实例</div>
            </div>
          </div>
        </div>

        <div className="panel" style={{ paddingBottom: 0 }}>
          <div className="tabs">
            {TABS.map((t) => (
              <button key={t.id} className={`tab${t.id === tab ? ' tab-active' : ''}`} onClick={() => setTab(t.id)}>
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {tab === 'cis' && (
          <div className="panel">
            <div className="flex items-center justify-between mb-3">
              <h3 className="section-title-lg">CIS 加固矩阵 · 22 items × 8 节点</h3>
              <div className="flex gap-2">
                <button className="btn-secondary btn-sm">仅 Check</button>
                <button className="btn-primary btn-sm">批量 Reinforce</button>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table>
                <thead>
                  <tr>
                    <th className="text-left text-xs uppercase tracking-wider text-[#8f8681] font-bold p-3" style={{ width: 260 }}>
                      基线项
                    </th>
                    {NODES.map((n) => (
                      <th key={n} className="text-center text-xs text-[#8f8681] font-bold p-2" style={{ minWidth: 60 }}>
                        node-{n}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {CIS_ITEMS.map(([id, name, cat, stats]) => (
                    <tr key={id} className="border-t border-[#f1e2d9] hover:bg-[#fffaf7]">
                      <td className="p-3">
                        <div className="flex items-baseline gap-2">
                          <code className="text-xs font-mono text-[#b46c50]">{id}</code>
                          <div>
                            <div className="text-sm font-semibold text-[#171212]">{name}</div>
                            <div className="text-xs muted">{cat}</div>
                          </div>
                        </div>
                      </td>
                      {stats.map((s, i) => (
                        <td key={i} className="p-2 text-center">
                          <div className={`inline-flex items-center justify-center w-8 h-8 rounded-lg ${cisCellClass[s]} font-bold text-sm`}>
                            {cisCellIcon[s]}
                          </div>
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="text-xs muted text-center mt-3">显示 1-9 / 共 22 items · 展开全部 22 项</div>
          </div>
        )}

        {tab === 'ransom' && (
          <div className="panel">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="eyebrow">勒索防护</div>
                <h3 className="section-title-lg mt-1">勒索软件防护 · 基于 YARA + LSM hook</h3>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs muted-strong">全局状态</span>
                <div className="toggle toggle-on"><div className="toggle-thumb" /></div>
                <span className="text-xs font-bold tone-green">已启用</span>
                <button className="btn-secondary btn-sm">编辑策略</button>
              </div>
            </div>
            <div className="text-xs muted mb-4">
              监控 unlink/rmdir/truncate/rename 等高频文件操作，结合 YARA 签名识别勒索家族行为。检测到异常立即 BLOCK + kill 进程。
            </div>
            <div className="grid grid-cols-4 gap-3 mb-5">
              {[
                ['受保护目录', '42', '含通配符 8 条', ''],
                ['24h 拦截', '3', '2 BLOCK · 1 KILL', 'tone-red'],
                ['YARA 规则', '156', '8 家族签名', ''],
                ['告警状态', '3', '待处置', 'tone-red'],
              ].map(([label, val, sub, tone]) => (
                <div key={label} className="card-warm">
                  <div className="eyebrow text-[10px]">{label}</div>
                  <div className={`text-2xl font-bold mt-1 ${tone || 'text-[#171212]'}`}>{val}</div>
                  <div className="text-xs muted">{sub}</div>
                </div>
              ))}
            </div>
            <div className="mb-5">
              <h4 className="font-semibold text-[#171212] text-sm mb-3">受保护目录列表</h4>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>目录路径</th>
                    <th style={{ width: 120 }}>防护模式</th>
                    <th style={{ width: 120 }}>命中次数</th>
                    <th style={{ width: 120 }}>最后命中</th>
                  </tr>
                </thead>
                <tbody>
                  {RANSOM_DIRS.map(([path, mode, hits, last]) => (
                    <tr key={path}>
                      <td><code className="text-sm font-mono text-[#171212]">{path}</code></td>
                      <td><span className={`badge badge-${mode === 'enforce' ? 'red' : 'orange'}`}>{mode.toUpperCase()}</span></td>
                      <td><span className={`font-bold ${hits > 0 ? 'tone-red' : 'muted-strong'}`}>{hits}</span></td>
                      <td><span className="text-xs muted-strong">{last}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <h4 className="font-semibold text-[#171212] text-sm mb-3">最近可疑进程拦截</h4>
            <div className="space-y-2">
              {RANSOM_HITS.map(([t, node, pname, ppath, desc, act, tone]) => (
                <div key={pname} className={`p-3 rounded-2xl border bg-${tone}-50 border-${tone}-200`}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <code className="text-xs font-bold">{node}</code>
                      <code className="text-sm font-mono text-[#171212]">{pname}</code>
                      <code className="text-xs muted">{ppath}</code>
                    </div>
                    <span className="muted-strong text-xs">{t}</span>
                  </div>
                  <div className="text-xs text-[#171212] mt-1">{desc}</div>
                  <div className={`text-xs tone-${tone === 'amber' ? 'orange' : tone} font-bold mt-2`}>{act}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 'mining' && (
          <div className="panel">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="eyebrow">挖矿检测</div>
                <h3 className="section-title-lg mt-1">挖矿病毒检测 · 矿池连接 + 进程行为</h3>
              </div>
              <button className="btn-primary btn-sm">立即检测</button>
            </div>
            <div className="text-xs muted mb-4">
              实时检测矿池域名解析、矿池 IP 连接、CPU 占用异常、已知挖矿病毒签名（XMRig / Coinhive 等）。检测项可配置。
            </div>
            <div className="grid grid-cols-4 gap-3 mb-5">
              {MINING_ITEMS.map(([name, desc, enabled, hits]) => (
                <div key={name} className="card-warm">
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-xs font-bold text-[#171212]">{name}</div>
                    <div className={`toggle${enabled ? ' toggle-on' : ''}`}><div className="toggle-thumb" /></div>
                  </div>
                  <div className="text-xs muted mb-2 leading-5">{desc}</div>
                  <div className="flex justify-between">
                    <span className="text-xs muted-strong">24h 命中</span>
                    <span className={`font-bold tone-${hits > 0 ? 'red' : 'green'}`}>{hits}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 'invasion' && (
          <div className="panel">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="eyebrow">入侵检测</div>
                <h3 className="section-title-lg mt-1">主机入侵检测 · 行为规则</h3>
              </div>
              <button className="btn-primary btn-sm">+ 新增规则</button>
            </div>
            <table className="tbl">
              <thead>
                <tr>
                  <th>规则</th>
                  <th>判定</th>
                  <th style={{ width: 90 }}>24h 命中</th>
                  <th style={{ width: 100 }}>最近</th>
                </tr>
              </thead>
              <tbody>
                {INTRUSION_RULES.map(([name, judge, hits, last, tone]) => (
                  <tr key={name}>
                    <td><span className="font-semibold text-[#171212]">{name}</span></td>
                    <td><span className="text-xs muted">{judge}</span></td>
                    <td><span className={`font-bold tone-${tone === 'amber' ? 'orange' : tone}`}>{hits}</span></td>
                    <td><span className="text-xs muted-strong">{last}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'file' && (
          <div className="panel">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="eyebrow">文件保护</div>
                <h3 className="section-title-lg mt-1">关键文件 hash 漂移监测</h3>
              </div>
              <button className="btn-primary btn-sm">+ 新增基线</button>
            </div>
            <table className="tbl">
              <thead>
                <tr>
                  <th>受保护资源</th>
                  <th style={{ width: 90 }}>类型</th>
                  <th style={{ width: 120 }}>模式</th>
                  <th>状态</th>
                  <th style={{ width: 90 }}>漂移</th>
                </tr>
              </thead>
              <tbody>
                {FILE_PROT.map(([path, type, mode, status, drift, tone]) => (
                  <tr key={path}>
                    <td><code className="text-xs font-mono">{path}</code></td>
                    <td><span className={`badge ${type === '主机' ? 'badge-blue' : 'badge-orange'}`}>{type}</span></td>
                    <td><span className="text-xs">{mode}</span></td>
                    <td><span className={`text-xs tone-${tone === 'amber' ? 'orange' : tone} font-semibold`}>{status}</span></td>
                    <td><span className={`font-bold tone-${drift > 0 ? 'red' : 'green'}`}>{drift}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AdminLayout>
  );
};

export default HostHardeningPage;
