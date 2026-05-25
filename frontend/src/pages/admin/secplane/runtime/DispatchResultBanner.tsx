import React from 'react';
import { type DispatchResult } from '../../../../services/secplaneService';

// Honest dispatch banner: a DispatchResult only means rows were inserted into
// instance_commands. Pod-side agent has to poll/execute/ack for the policy
// to actually take effect. If the OpenClaw pod is unreachable, rows stay
// `pending` indefinitely. We surface per-target status here so operators
// don't read "下发成功" and assume the policy is live on the pod.

interface Props {
  result: DispatchResult;
}

const DispatchResultBanner: React.FC<Props> = ({ result }) => {
  const counts: Record<string, number> = {};
  for (const t of result.targets) {
    const s = (t.status || 'unknown').toLowerCase();
    counts[s] = (counts[s] || 0) + 1;
  }

  const total = result.targets.length;
  const failed = counts['failed'] || 0;
  const succeeded = counts['succeeded'] || 0;
  const pending = counts['pending'] || 0;
  const dispatched = counts['dispatched'] || 0;
  const others = total - failed - succeeded - pending - dispatched;

  // tone: failure dominates; all-succeeded is the only green; mixed/pending → warning
  let alertClass = 'alert alert-warning';
  let headline = '已入队，等待 pod agent 拉取';
  if (failed > 0 && succeeded === 0 && pending === 0 && dispatched === 0) {
    alertClass = 'alert alert-danger';
    headline = '下发失败';
  } else if (succeeded === total && total > 0) {
    alertClass = 'alert alert-success';
    headline = '已下发并生效';
  } else if (failed > 0) {
    alertClass = 'alert alert-danger';
    headline = `部分失败（${failed}/${total}）`;
  }

  const failedTargets = result.targets.filter((t) => (t.status || '').toLowerCase() === 'failed');

  return (
    <div className={alertClass} style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
      <div className="flex items-center justify-between gap-3">
        <strong>{headline}</strong>
        <span className="text-xs muted-strong" style={{ fontFamily: 'ui-monospace, monospace' }}>
          revision {result.revision} · sha {result.sha256.slice(0, 16)}
        </span>
      </div>
      <div className="text-xs flex flex-wrap gap-x-4 gap-y-1">
        <span>共 <strong>{total}</strong> 个实例</span>
        {pending > 0 && <span>· pending <strong>{pending}</strong>（等待 agent 消费）</span>}
        {dispatched > 0 && <span>· dispatched <strong>{dispatched}</strong>（agent 已拉取，未确认）</span>}
        {succeeded > 0 && <span>· succeeded <strong className="tone-green">{succeeded}</strong></span>}
        {failed > 0 && <span>· failed <strong className="tone-red">{failed}</strong></span>}
        {others > 0 && <span>· other <strong>{others}</strong></span>}
      </div>
      {failedTargets.length > 0 && (
        <div className="text-xs">
          失败实例：
          {failedTargets.map((t, i) => (
            <span key={t.instance_id}>
              {i > 0 && '、'}
              <code className="font-mono">#{t.instance_id}</code>
              {t.error && <span className="muted ml-1">({t.error})</span>}
            </span>
          ))}
        </div>
      )}
      {(pending > 0 || dispatched > 0) && (
        <div className="text-xs muted">
          注：命令仅入队，**pod agent 拉取后才会真正生效**。若实例状态异常（stopped / error / 失联），
          命令会持续停留在 pending；可在「实例管理」确认实例健康，或查 instance_commands.status 转
          succeeded 后才表示生效。
        </div>
      )}
    </div>
  );
};

export default DispatchResultBanner;
