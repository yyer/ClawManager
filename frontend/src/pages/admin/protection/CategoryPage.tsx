import React from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../components/AdminLayout';
import { CATEGORIES, getScenariosByCategory } from './_data';

// 每个类目页头部的统计卡 (mock，后续接 secplaneService stats API)
const CAT_STATS: Record<string, { label: string; value: string; tone?: string; sub: string }[]> = {
  'cat-1': [
    { label: '场景数', value: '6', sub: '六层运行时防护' },
    { label: '24h 拦截', value: '624', tone: 'tone-red', sub: '含输入/工具/输出' },
    { label: '防护层数', value: '5', sub: '五层纵深防御' },
    { label: '规则覆盖', value: '100%', tone: 'tone-green', sub: '运行时全链路' },
  ],
  'cat-4': [
    { label: '场景数', value: '2', sub: '组件可信扫描 + 出站治理' },
    { label: '24h 风险拦截', value: '38', tone: 'tone-red', sub: '供应链 IOC + 出站违规' },
    { label: '受管组件', value: '124', sub: 'skill / plugin / 镜像' },
    { label: '出站白名单', value: '36', tone: 'tone-green', sub: '已批准域名' },
  ],
  'cat-2': [
    { label: '场景数', value: '1', sub: '统一身份与权限' },
    { label: '24h 权限拒绝', value: '12', tone: 'tone-red', sub: 'RBAC + 最小权限' },
    { label: '受管身份', value: '48', sub: '智能体 + agent token' },
    { label: '过期策略', value: '24h', tone: 'tone-green', sub: 'agent token 默认 TTL' },
  ],
  'cat-6': [
    { label: '场景数', value: '2', sub: '容器隔离 + 宿主加固' },
    { label: '24h 异常', value: '21', tone: 'tone-red', sub: '逃逸尝试 + 入侵' },
    { label: '主机数', value: '8', sub: '已纳管节点' },
    { label: 'CIS 基线分', value: '92', tone: 'tone-green', sub: '加固达标' },
  ],
  'cat-5': [
    { label: '场景数', value: '2', sub: '熔断 + 全链路审计' },
    { label: '24h 熔断', value: '3', tone: 'tone-red', sub: '应急处置' },
    { label: '审计事件', value: '3.2K', sub: '24h 跨产品' },
    { label: '健康分', value: '92', tone: 'tone-green', sub: '运营驾驶舱' },
  ],
  'cat-7': [
    { label: '场景数', value: '1', sub: '策略治理' },
    { label: '模板', value: '14', sub: '内置策略模板' },
    { label: '已应用实例', value: '124', sub: '策略下发' },
    { label: '配置版本', value: 'r4', tone: 'tone-green', sub: '最新策略修订' },
  ],
  'cat-3': [
    { label: '场景数', value: '0', sub: '协同接入与通信' },
    { label: '当前状态', value: '本期未开放', tone: 'tone-muted', sub: '后续版本规划' },
    { label: '替代承接', value: 'AI 网关', sub: '资源配额 + 速率' },
    { label: '路线图', value: '2026 H2', sub: '多智能体协作' },
  ],
};

const CAT_DESC: Record<string, string> = {
  'cat-1': '面向单智能体从初始化、输入、推理、决策到执行的完整运行时链路，覆盖输入面、状态面、决策面、输出面、资产保护、人因审批 6 个场景，构建运行时层纵深防御主链路。',
  'cat-4': '面向智能体所依赖的技能、插件、镜像与外部通信，校验供应链可信、阻断未授权出站、保障"装得对、跑得直"。',
  'cat-2': '智能体身份签发、调用授权、最小权限策略；agent token 生命周期管理，强制最小权限访问。',
  'cat-6': '智能体运行环境的纵深加固：容器逃逸防护 + CIS 基线 + 勒索/挖矿/入侵检测 + 关键文件保护。',
  'cat-5': '面向运营与合规的审计回溯与应急处置：全链路事件聚合、风险评分、熔断处置、运营驾驶舱。',
  'cat-7': '统一策略中心：策略模板、版本管理、灰度发布与回滚；批量应用到实例与命名空间。',
  'cat-3': '多智能体协作、对等接入、消息总线鉴权与速率治理。本期由 AI 网关 承担资源配额与速率限制，独立"协同接入"模块将在后续版本开放。',
};

export type CategoryPageProps = { catId: string };

const CategoryPage: React.FC<CategoryPageProps> = ({ catId }) => {
  const cat = CATEGORIES.find((c) => c.id === catId);
  if (!cat) {
    return (
      <AdminLayout>
        <div className="cm-content">
          <div className="panel">未知类目 {catId}</div>
        </div>
      </AdminLayout>
    );
  }
  const scs = getScenariosByCategory(catId);
  const stats = CAT_STATS[catId] ?? [];
  const desc = CAT_DESC[catId] ?? '';

  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          <span className="crumb-current">{cat.label}</span>
        </div>

        <div className="panel">
          <div className="flex items-start justify-between gap-6 mb-5">
            <div className="hero-block flex-1">
              <div className="h-eyebrow">{cat.sub}</div>
              <h2 className="h-title">{cat.label}</h2>
              <p className="h-subtitle">{desc}</p>
            </div>
          </div>
          {stats.length > 0 && (
            <div className="grid grid-cols-4 gap-3">
              {stats.map((s, i) => (
                <div key={i} className="stat-card">
                  <div className="stat-card-label">{s.label}</div>
                  <div className={`stat-card-value ${s.tone ?? ''}`}>{s.value}</div>
                  <div className="stat-card-sub muted-strong">{s.sub}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {scs.length > 0 ? (
          <div className="grid grid-cols-2 gap-4">
            {scs.map((s) => (
              <Link key={s.id} to={s.path} className="cat-overview-card">
                <div className="flex items-start gap-3 mb-3">
                  <div className="flex-1 min-w-0">
                    <div className="text-lg font-bold text-[#171212]">{s.label}</div>
                    <div className="text-xs muted mt-1">{s.subtitle}</div>
                  </div>
                </div>
                <div className="divider" />
                <div className="flex items-center justify-between text-xs">
                  <span className="muted-strong">点击进入场景</span>
                  <span style={{ color: cat.color, fontWeight: 600 }}>查看 →</span>
                </div>
              </Link>
            ))}
          </div>
        ) : (
          <div className="panel">
            <div className="text-sm muted">本类目暂未开放，由其他模块承接（详见上方说明）。</div>
          </div>
        )}
      </div>
    </AdminLayout>
  );
};

export default CategoryPage;
