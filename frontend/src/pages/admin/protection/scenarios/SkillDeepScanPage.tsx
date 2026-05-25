import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../../components/AdminLayout';

// Skill 深度扫描 (scenario sds) — 对齐 KSecForAIDemo/scenario-skill-deepscan.html
// 简化版：保留 hero + 6 分析器并行卡 + 当前 skill 摘要 + finding cards
// 完整版的扫描动画 / 圆环图等留待 后续 polish

type Tone = 'red' | 'orange' | 'amber' | 'blue' | 'purple' | 'green';

const ANALYZERS: Array<[string, string, string, Tone, boolean]> = [
  ['Static-Rule', '正则 / IOC 静态规则', '基于已知风险特征匹配', 'red', true],
  ['Bytecode-Hash', '字节码完整性', '签名校验 + diff', 'blue', true],
  ['Call-Taint', '调用链污点', '污染源 → sink 路径追踪', 'orange', true],
  ['AST-Behavior', 'AST 行为推演', '语义级行为模型', 'purple', true],
  ['LLM-Semantic', 'LLM 语义分析', 'gpt-4o-mini · 意图判定', 'amber', true],
  ['Meta-Aggregate', 'Meta 聚合', 'gpt-4o · 多分析器仲裁', 'green', true],
];

const FINDINGS: Array<[string, Tone, string, string, string, string]> = [
  ['HIGH', 'red', 'Static-Rule', '硬编码 OpenAI API Key', '在 skill 入口文件第 47 行检测到 sk-proj-xxxxx 明文常量', 'fix: 移到环境变量 OPENAI_API_KEY 并通过 secret 注入'],
  ['HIGH', 'red', 'Call-Taint', 'user_input → eval() 污染路径', '完整污染链路：handler.py:23 → utils.py:12 → eval(line 78)', 'fix: 替换 eval() 为 ast.literal_eval 或显式 schema 校验'],
  ['MEDIUM', 'orange', 'AST-Behavior', '可疑文件批量重命名', 'AST 检测到循环内 os.rename 调用，疑似勒索行为模式', 'fix: 添加用户确认 + 速率限制'],
  ['MEDIUM', 'orange', 'LLM-Semantic', 'prompt 中含越狱模板片段', 'gpt-4o-mini 判定：包含 "ignore previous instructions" 类指令', 'fix: 移除该 prompt 片段或加 sanitizer'],
  ['LOW', 'amber', 'Bytecode-Hash', '依赖未签名', 'requests-2.31.0 lib 包未通过 sigstore 验证', 'fix: 升级到签名版本或加入 trust list'],
  ['INFO', 'green', 'Meta-Aggregate', '其余 14 项检查均通过', '6 分析器共识：本 skill 主体逻辑安全', '建议归档为 SAFE 列表'],
];

const SkillDeepScanPage: React.FC = () => {
  const [tab, setTab] = useState<'findings' | 'rules' | 'history'>('findings');
  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <Link to="/admin/secplane/cat-trust">数据与组件可信</Link>
          <span>/</span>
          <span className="crumb-current">Skill 深度扫描</span>
        </div>

        <div className="panel">
          <div className="flex items-start justify-between gap-6 mb-5">
            <div className="hero-block flex-1">
              <h2 className="h-title">Skill 深度扫描</h2>
              <p className="h-subtitle">
                对单个技能（Skill）开展代码级深度安全分析。六分析器并行 —— 静态规则 / 字节码完整性 / 调用链污点 / AST 行为推演 / LLM 语义 / Meta 聚合 —— 输出可执行修复建议。
              </p>
              <p className="text-xs muted mt-2">
                当前扫描模式：<strong>Deep · 6 分析器全开</strong> · 主 LLM gpt-4o-mini · Meta LLM gpt-4o · 最近全量 12 分钟前完成
              </p>
            </div>
            <div className="flex flex-col gap-2 shrink-0">
              <button className="btn-secondary">快速扫描</button>
              <button className="btn-primary">全量扫描</button>
            </div>
          </div>
          <div className="grid grid-cols-4 gap-3">
            <div className="stat-card">
              <div className="stat-card-label">总技能</div>
              <div className="stat-card-value">312</div>
              <div className="stat-card-sub muted-strong">用户上传 218 / 实例发现 94</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">深度扫描覆盖</div>
              <div className="stat-card-value tone-green">96%</div>
              <div className="stat-card-sub muted-strong">300/312</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">HIGH/CRITICAL</div>
              <div className="stat-card-value tone-red">11</div>
              <div className="stat-card-sub muted-strong">需立即修复</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-label">平均扫描耗时</div>
              <div className="stat-card-value">2:14</div>
              <div className="stat-card-sub muted-strong">6 分析器并行</div>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="eyebrow">6 分析器并行架构</div>
              <h3 className="section-title-lg mt-1">扫描器矩阵 · 互为校验</h3>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            {ANALYZERS.map(([key, name, desc, tone, enabled]) => (
              <div key={key} className="p-4 rounded-2xl border border-[#eadfd8] bg-white">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`badge badge-${tone}`}>{key}</span>
                    {enabled && (
                      <>
                        <span className="dot bg-green-500" />
                        <span className="text-xs muted-strong">就绪</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="font-semibold text-[#171212] mb-1">{name}</div>
                <div className="text-xs muted leading-5">{desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="eyebrow">当前扫描目标</div>
              <h3 className="section-title-lg mt-1">
                Skill <code className="text-lg">finance-handler-2.0</code>
              </h3>
              <div className="text-xs muted mt-1">作者 user_8842 · 上传 2026-05-19 · 引用实例 8 个 · 体积 142KB · 文件数 12</div>
            </div>
            <div className="flex gap-2">
              <button className="btn-secondary btn-sm">查看源码</button>
              <button className="btn-primary btn-sm">重新扫描</button>
            </div>
          </div>

          <div className="tabs">
            <button className={`tab${tab === 'findings' ? ' tab-active' : ''}`} onClick={() => setTab('findings')}>
              本轮发现 ({FINDINGS.length})
            </button>
            <button className={`tab${tab === 'rules' ? ' tab-active' : ''}`} onClick={() => setTab('rules')}>
              规则库 (487)
            </button>
            <button className={`tab${tab === 'history' ? ' tab-active' : ''}`} onClick={() => setTab('history')}>
              扫描历史
            </button>
          </div>

          {tab === 'findings' && (
            <div className="space-y-3">
              {FINDINGS.map(([sev, tone, analyzer, name, evidence, fix], i) => (
                <div key={i} className="finding-card">
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`badge badge-${tone}`}>{sev}</span>
                      <span className="text-xs muted-strong">{analyzer}</span>
                      <span className="font-semibold text-[#171212]">{name}</span>
                    </div>
                  </div>
                  <div className="text-xs muted mb-2">{evidence}</div>
                  <div className="text-xs">
                    <span className="text-[#15803d] font-semibold">修复建议:</span> <span className="muted">{fix}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {tab === 'rules' && (
            <div className="text-sm muted">
              487 条静态规则 + 156 条 YARA + 89 条 AST 模式 + 12 类 LLM 提示模板。规则库管理请到「数据与组件可信」类目下「组件可信扫描」子页面。
            </div>
          )}

          {tab === 'history' && (
            <table className="tbl">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>触发方式</th>
                  <th>耗时</th>
                  <th>新增发现</th>
                  <th>结论</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ['12m', '自动 · 上传完成', '2:14', '6', 'HIGH'],
                  ['2h', '手动 · admin', '1:48', '0', '无变化'],
                  ['1d', '自动 · 每日全量', '2:32', '11', 'HIGH'],
                  ['3d', '手动 · 上传 v1.9', '2:01', '8', 'HIGH'],
                ].map(([t, src, dur, found, conc], i) => (
                  <tr key={i}>
                    <td><span className="muted-strong text-xs">{t}</span></td>
                    <td><span className="text-xs">{src}</span></td>
                    <td><code className="text-xs">{dur}</code></td>
                    <td><span className="font-bold">{found}</span></td>
                    <td><span className={`badge badge-${conc === 'HIGH' ? 'red' : 'green'}`}>{conc}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </AdminLayout>
  );
};

export default SkillDeepScanPage;
