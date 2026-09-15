import { useEffect, useState } from 'react';
import api from '../services/api';

type Progress = { id: number; runtime_type: string; status: string; completed?: number; total?: number; current_pool?: string; error?: string };

export function RuntimeRolloutProgress({ runtimeType }: { runtimeType: string }) {
  const [items, setItems] = useState<Progress[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    let stopped = false;
    let busy = false;
    const refresh = async () => {
      if (busy || stopped) return;
      busy = true;
      try {
        const response = await api.get('/admin/runtime-rollouts', { params: { runtime_type: runtimeType } });
        if (!stopped) { setItems(response.data.data.items); setError(''); }
      } catch { if (!stopped) setError('更新进度暂时无法读取，请稍后刷新；不要重复提交。'); }
      finally { busy = false; }
    };
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 3000);
    const focus = () => { void refresh(); };
    window.addEventListener('focus', focus);
    return () => { stopped = true; window.clearInterval(timer); window.removeEventListener('focus', focus); };
  }, [runtimeType]);
  const labels: Record<string, string> = { pending: '等待执行', running: '逐池更新中', finished: '已完成', error: '已停止，请检查' };
  return <div className="mt-3 space-y-2 text-sm" aria-live="polite">
    {error && <p className="text-amber-700">{error}</p>}
    {items.slice(0, 3).map(item => <div key={item.id} className="rounded border border-gray-200 p-3">
      <span>更新 #{item.id}：{labels[item.status] ?? item.status}</span>
      {item.total !== undefined && <span> · 已完成 {item.completed ?? 0}/{item.total} 个池</span>}
      {item.current_pool && <p className="text-gray-600">当前池：{item.current_pool}</p>}
      {item.error && <p className="break-words text-red-600">{item.error}</p>}
    </div>)}
  </div>;
}
