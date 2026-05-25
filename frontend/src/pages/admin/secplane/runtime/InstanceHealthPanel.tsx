import React from 'react';
import { Link } from 'react-router-dom';
import type { Instance } from '../../../../types/instance';

interface Props {
  instances: Instance[];
  loading: boolean;
  error: string | null;
  onReload: () => void;
}

const statusBadge = (status: Instance['status']): string => {
  switch (status) {
    case 'running': return 'badge-green';
    case 'stopped': return 'badge-slate';
    case 'creating': return 'badge-blue';
    case 'deleting': return 'badge-amber';
    case 'error': return 'badge-red';
    default: return 'badge-slate';
  }
};

const InstanceHealthPanel: React.FC<Props> = ({ instances, loading, error, onReload }) => {
  const total = instances.length;
  const healthy = instances.filter((i) => i.status === 'running').length;
  const unhealthy = total - healthy;

  return (
    <div className="panel-warm" style={{ padding: 18 }}>
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="eyebrow">DISPATCH TARGETS · 目标实例健康</div>
          <div className="section-title mt-1">
            {loading ? '加载中…' : (
              <>
                共 <strong>{total}</strong> 个实例
                {total > 0 && (
                  <>
                    {' · '}
                    <span className="tone-green">{healthy} running</span>
                    {unhealthy > 0 && (
                      <>
                        {' · '}
                        <span className="tone-red">{unhealthy} 不健康</span>
                      </>
                    )}
                  </>
                )}
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link to="/admin/instances" className="muted text-xs hover:underline">实例管理 →</Link>
          <button type="button" className="btn-secondary btn-sm" onClick={onReload} disabled={loading}>刷新</button>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger mb-2" style={{ padding: '8px 12px', fontSize: 12 }}>
          实例列表加载失败：{error}
        </div>
      )}

      {!loading && total === 0 && !error && (
        <div className="muted text-sm">无实例。请先在「实例管理」创建至少一个 OpenClaw 实例。</div>
      )}

      {total > 0 && (
        <div className="grid grid-cols-3 gap-2">
          {instances.map((inst) => (
            <div
              key={inst.id}
              className="flex items-center gap-2 rounded-lg border border-[#eadfd8] bg-white px-3 py-2"
            >
              <span className={`badge ${statusBadge(inst.status)}`}>{inst.status}</span>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-[#171212] truncate" title={inst.name}>
                  {inst.name}
                </div>
                <div className="muted-strong text-xs font-mono">#{inst.id}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default InstanceHealthPanel;
