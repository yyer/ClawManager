// 7 大类别 + 13 个 scenario 数据定义 (移植自 KSecForAIDemo/assets/layout.js)
// React 路由路径已 wired 到 ClawManager 的 /admin/secplane/* 命名空间

export type ProtectionCategory = {
  id: string;
  code: string;
  label: string;
  sub: string;
  path: string;
  color: string;
  count?: number;
  disabled?: boolean;
};

export type ProtectionScenario = {
  id: string;
  code: string;
  label: string;
  subtitle: string;
  path: string;
  cat: string;
};

export const CATEGORIES: ProtectionCategory[] = [
  { id: 'overview', code: '总览', label: '总览', sub: 'OVERVIEW', path: '/admin/secplane', color: '#dc2626' },
  { id: 'cat-1', code: '1', label: '智能体运行时安全', sub: 'RUNTIME', path: '/admin/secplane/runtime', color: '#dc2626', count: 6 },
  { id: 'cat-4', code: '2', label: '数据与组件可信', sub: 'TRUST', path: '/admin/secplane/cat-trust', color: '#6b21a8', count: 1 },
  { id: 'cat-2', code: '3', label: '统一身份与权限', sub: 'IDENTITY', path: '/admin/secplane/cat-identity', color: '#1d4ed8', count: 1 },
  { id: 'cat-6', code: '4', label: '环境隔离与安全增强', sub: 'ISOLATE', path: '/admin/secplane/cat-isolate', color: '#0f766e', count: 2 },
  { id: 'cat-5', code: '5', label: '监管与运营治理', sub: 'GOVERN', path: '/admin/secplane/cat-govern', color: '#b45309', count: 2 },
  { id: 'cat-7', code: '6', label: '安全策略与模板', sub: 'POLICY', path: '/admin/secplane/cat-policy', color: '#7d5744', count: 1 },
  { id: 'cat-3', code: '7', label: '协同接入与通信', sub: 'COMM', path: '/admin/secplane/cat-comm', color: '#94a3b8', count: 0, disabled: true },
  { id: 'events', code: '事件', label: '安全事件', sub: 'EVENTS', path: '/admin/secplane/events', color: '#dc2626' },
];

export const SCENARIOS: ProtectionScenario[] = [
  { id: 'a', code: 'A', label: '输入面防护', subtitle: 'Prompt 注入与上下文劫持', path: '/admin/secplane/runtime/input', cat: 'cat-1' },
  { id: 'b', code: 'B', label: '状态面防护', subtitle: '记忆污染与会话隔离', path: '/admin/secplane/runtime/state', cat: 'cat-1' },
  { id: 'c', code: 'C', label: '决策面防护', subtitle: '危险工具调用管控', path: '/admin/secplane/runtime/decision', cat: 'cat-1' },
  { id: 'd', code: 'D', label: '输出面防护', subtitle: '凭据/隐私脱敏', path: '/admin/secplane/runtime/output', cat: 'cat-1' },
  { id: 'f', code: 'F', label: '资产防篡改', subtitle: '关键文件/配置保护', path: '/admin/secplane/runtime/asset', cat: 'cat-1' },
  { id: 'g', code: 'G', label: '人因审批', subtitle: '高风险操作审批回路', path: '/admin/secplane/runtime/approval', cat: 'cat-1' },
  { id: 'h', code: 'H', label: '出站治理', subtitle: '智能体出站白名单+TLS', path: '/admin/secplane/trust/outbound', cat: 'cat-2' },
  { id: 'sk', code: 'SK', label: 'SKILL 技能扫描', subtitle: '技能仓库扫描 / 报告 / Scanner 配置', path: '/admin/security', cat: 'cat-4' },
  { id: 'i', code: 'I', label: '应急熔断', subtitle: '主机/实例熔断+双人复核', path: '/admin/secplane/govern/breaker', cat: 'cat-5' },
  { id: 'j', code: 'J', label: '全链路审计', subtitle: '事件流聚合与回溯', path: '/admin/secplane/govern/audit', cat: 'cat-5' },
  { id: 'k', code: 'K', label: '容器隔离', subtitle: '容器策略与防逃逸', path: '/admin/secplane/isolate/container', cat: 'cat-6' },
  { id: 'l', code: 'L', label: '宿主加固', subtitle: 'CIS基线+勒索+挖矿+入侵+文件保护', path: '/admin/secplane/isolate/host', cat: 'cat-6' },
  { id: 'm', code: 'M', label: '策略治理', subtitle: '统一策略中心+模板', path: '/admin/secplane/policy/governance', cat: 'cat-7' },
];

// 类目对应的场景列表
export function getScenariosByCategory(catId: string): ProtectionScenario[] {
  return SCENARIOS.filter((s) => s.cat === catId);
}

// 一些总览页/类目页用的色调映射
export const TONE_TO_BADGE: Record<string, string> = {
  red: 'badge badge-red',
  orange: 'badge badge-orange',
  amber: 'badge badge-orange',
  purple: 'badge badge-purple',
  green: 'badge badge-green',
  blue: 'badge badge-blue',
  slate: 'badge badge-slate',
};
