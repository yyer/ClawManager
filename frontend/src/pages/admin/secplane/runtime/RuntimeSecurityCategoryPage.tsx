import React from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';

interface Scenario {
  letter: string;
  label: string;
  sub: string;
  desc: string;
  route: string;
  defenses: string;
}

const SCENARIOS: Scenario[] = [
  {
    letter: 'A',
    label: '输入面防护',
    sub: 'INPUT SURFACE',
    desc: '面向用户输入与工具结果，检测注入模式、越狱、二级注入。',
    route: '/admin/secplane/runtime/input',
    defenses: 'UserRiskScan · PromptGuard · ToolCallEnforcement · ToolResultScan',
  },
  {
    letter: 'B',
    label: '状态面防护',
    sub: 'STATE SURFACE',
    desc: '内存路径保护、完整性 Hash 校验、会话隔离。',
    route: '/admin/secplane/runtime/state',
    defenses: 'MemoryGuard · SelfProtection',
  },
  {
    letter: 'C',
    label: '决策面防护',
    sub: 'DECISION SURFACE',
    desc: '工具调用前静态扫描危险命令、编码混淆、来源不可信脚本。',
    route: '/admin/secplane/runtime/decision',
    defenses: 'CommandBlock · EncodingGuard · ScriptProvenanceGuard',
  },
  {
    letter: 'D',
    label: '输出面防护',
    sub: 'OUTPUT SURFACE',
    desc: '出栈自动脱敏：API Key/JWT/邮箱/电话/身份证等 9 类隐私规则。',
    route: '/admin/secplane/runtime/output',
    defenses: 'OutputRedaction',
  },
  {
    letter: 'F',
    label: '资产防篡改',
    sub: 'ASSET PROTECTION',
    desc: '受保护路径/技能/插件清单，运行时层拦截写入与篡改。',
    route: '/admin/secplane/runtime/asset',
    defenses: 'SelfProtection · ProtectedPaths/Skills/Plugins',
  },
];

const RuntimeSecurityCategoryPage: React.FC = () => {
  return (
    <AdminLayout title="安全防护">
      <div className="secp-scope space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <span className="crumb-current">智能体运行时安全</span>
        </div>

        {/* Hero */}
        <div className="panel">
          <div className="hero-block mb-5">
            <div className="h-eyebrow">AGENT RUNTIME SECURITY</div>
            <h2 className="h-title">智能体运行时安全</h2>
            <p className="h-subtitle">
              面向单智能体从初始化、输入、推理、决策到执行的完整运行时链路，覆盖输入面、状态面、决策面、输出面、资产保护
              5 个场景，构建运行时层纵深防御主链路。底层由 ClawAegisEx 插件强制执行，配置变更通过
              <code className="mx-1 px-1 py-0.5 rounded bg-[#fdf6f1] text-[#7a4a30] text-xs">install_skill</code>
              下发到 pod，插件在 ≤1s 内 hot-reload user_config.json 生效。
            </p>
          </div>
          <div className="grid grid-cols-4 gap-3">
            <div className="stat-card">
              <div className="stat-card-label">场景数</div>
              <div className="stat-card-value">{SCENARIOS.length}</div>
              <div className="stat-card-sub muted-strong">五个攻击面</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">支撑防御</div>
              <div className="stat-card-value">14</div>
              <div className="stat-card-sub muted-strong">ClawAegisEx defense</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">下发通道</div>
              <div className="stat-card-value tone-green">install_skill</div>
              <div className="stat-card-sub muted-strong">bundle → workspace → hot-reload</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">规则覆盖</div>
              <div className="stat-card-value tone-green">100%</div>
              <div className="stat-card-sub muted-strong">运行时全链路</div>
            </div>
          </div>
        </div>

        {/* Scenario cards */}
        <div className="grid grid-cols-2 gap-4">
          {SCENARIOS.map((s) => (
            <Link key={s.letter} to={s.route} className="scenario-card">
              <div className="flex items-start gap-3 mb-3">
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: 12,
                    background: 'linear-gradient(135deg, #fdf6f1, #f5e9df)',
                    border: '1px solid #eadfd8',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '1rem',
                    fontWeight: 700,
                    color: '#7d5744',
                    flexShrink: 0,
                  }}
                >
                  {s.letter}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="eyebrow" style={{ color: '#ef6b4a' }}>{s.sub}</div>
                  <div className="text-lg font-bold text-[#171212]">{s.label}</div>
                  <div className="text-xs muted mt-1">{s.desc}</div>
                </div>
              </div>
              <div className="divider"></div>
              <div className="flex items-center justify-between text-xs">
                <span className="muted-strong" style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.6875rem' }}>
                  {s.defenses}
                </span>
                <span style={{ color: '#ef6b4a', fontWeight: 600 }}>查看 →</span>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </AdminLayout>
  );
};

export default RuntimeSecurityCategoryPage;
