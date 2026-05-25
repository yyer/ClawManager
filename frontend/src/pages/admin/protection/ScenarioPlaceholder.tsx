import React from 'react';
import { Link } from 'react-router-dom';
import AdminLayout from '../../../components/AdminLayout';
import { CATEGORIES, SCENARIOS } from './_data';

export type ScenarioPlaceholderProps = { scenarioId: string };

// 用于尚未做完的 scenario 页 — 显示场景元信息 + "本期未开放" 提示 + 返回类目入口
const ScenarioPlaceholder: React.FC<ScenarioPlaceholderProps> = ({ scenarioId }) => {
  const sc = SCENARIOS.find((s) => s.id === scenarioId);
  if (!sc) {
    return (
      <AdminLayout>
        <div className="cm-content">
          <div className="panel">未知场景 {scenarioId}</div>
        </div>
      </AdminLayout>
    );
  }
  const cat = CATEGORIES.find((c) => c.id === sc.cat);
  return (
    <AdminLayout>
      <div className="cm-content space-y-6">
        <div className="crumb">
          <Link to="/admin/secplane">安全防护</Link>
          <span>/</span>
          {cat && <Link to={cat.path}>{cat.label}</Link>}
          {cat && <span>/</span>}
          <span className="crumb-current">{sc.label}</span>
        </div>

        <div className="panel">
          <div className="hero-block">
            <div className="h-eyebrow">场景 {sc.code}</div>
            <h2 className="h-title">{sc.label}</h2>
            <p className="h-subtitle">{sc.subtitle}</p>
          </div>
          <div className="divider my-5" />
          <div className="flex items-center gap-3">
            <span className="badge badge-slate">建设中</span>
            <span className="text-sm muted">
              此场景按 KSecForAIDemo 原型规划，待与后端 API 对齐后填充实装界面。点击下面按钮可查看原型设计。
            </span>
          </div>
          <div className="flex flex-wrap gap-2 mt-5">
            {cat && (
              <Link to={cat.path} className="btn-secondary btn-sm" style={{ textDecoration: 'none' }}>
                ← 返回 {cat.label}
              </Link>
            )}
            <Link to="/admin/secplane" className="btn-secondary btn-sm" style={{ textDecoration: 'none' }}>
              安全防护总览
            </Link>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default ScenarioPlaceholder;
