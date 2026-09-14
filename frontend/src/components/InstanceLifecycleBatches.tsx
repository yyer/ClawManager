import { useCallback, useEffect, useRef, useState } from "react";
import api from "../services/api";
import ConfirmDialog from "./ConfirmDialog";

type Batch = { batch_id: string; action: "restart" | "reset"; status: string; created_at: string };
type Detail = { batch: Batch; counts: Record<string, number>; total: number; page: number; page_size: number; items: { item: { source_id: number; source_name: string; state: string }; operation?: { instance_id?: number; error_message?: string } }[] };
const labels: Record<string, string> = { running: "执行中", paused: "已暂停", cancelling: "取消中（等待进行中的操作完成）", cancelled: "已取消", completed: "已完成", completed_with_errors: "已结束，有失败或待清理项", pending: "排队中", active: "操作中", succeeded: "成功", failed: "失败", warning: "成功，旧实例待清理" };
const unfinished = (b: Batch) => ["running", "paused", "cancelling"].includes(b.status);

// Progress is fetched from the server; navigation and failed HTTP requests do
// not create/retry operations. The submission key survives ambiguous responses.
export default function InstanceLifecycleBatches({ selectedIds, onChanged }: { selectedIds: number[]; onChanged: () => void }) {
  const [batches, setBatches] = useState<Batch[]>([]);
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState<Detail | null>(null);
  const [page, setPage] = useState(1);
  const [error, setError] = useState("");
  const [confirm, setConfirm] = useState<"restart" | "reset" | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const request = useRef<{ signature: string; key: string } | null>(null);
  const changed = useRef(onChanged);
  changed.current = onChanged;
  const previous = useRef("");
  const refresh = useCallback(async () => {
    const result = await api.get("/instances/batch/lifecycle");
    const list = result.data.data as Batch[];
    setBatches(list);
    const id = selected || list.find(unfinished)?.batch_id || list[0]?.batch_id;
    if (!id) return;
    const response = await api.get(`/instances/batch/lifecycle/${id}`, { params: { page } });
    const next = response.data.data as Detail;
    setDetail(next);
    const fingerprint = JSON.stringify([id, next.counts]);
    if (previous.current && previous.current !== fingerprint) changed.current();
    previous.current = fingerprint;
    setError("");
  }, [selected, page]);
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try { await refresh(); } catch { if (!stopped) setError("暂时无法查询进度，后台任务不会因此停止；请勿重复提交。"); }
      if (!stopped) timer = setTimeout(() => void poll(), 3000);
    };
    const focus = () => { if (!stopped) void refresh().catch(() => {}); };
    void poll();
    window.addEventListener("focus", focus);
    return () => { stopped = true; clearTimeout(timer); window.removeEventListener("focus", focus); };
  }, [refresh]);
  const submit = async () => {
    if (!confirm || !selectedIds.length || submitting) return;
    const signature = JSON.stringify([confirm, [...selectedIds].sort((a, b) => a - b)]);
    if (request.current?.signature !== signature) request.current = { signature, key: crypto.randomUUID() };
    setSubmitting(true);
    try {
      const response = await api.post("/instances/batch/lifecycle", { instance_ids: selectedIds, action: confirm, request_id: request.current.key, confirm_data_deletion: confirm === "reset" });
      setSelected(response.data.data.batch_id);
      setPage(1);
      setConfirm(null);
      request.current = null;
      await refresh();
    } catch (e: unknown) {
      const message = (e as { response?: { data?: { message?: string } } }).response?.data?.message;
      setError(message || "提交结果暂未确认。请先查看任务列表；再次确认将使用相同请求编号，避免重复执行。");
    } finally { setSubmitting(false); }
  };
  const control = async (action: string) => {
    if (!detail) return;
    try { await api.post(`/instances/batch/lifecycle/${detail.batch.batch_id}/${action}`); await refresh(); }
    catch { setError("操作未确认，请刷新查询任务状态。"); }
  };
  return <div className="mb-4 rounded-xl border border-slate-200 bg-white p-3">
    <div className="flex flex-wrap items-center gap-2">
      <button className="app-button-secondary text-blue-700" disabled={!selectedIds.length || submitting} onClick={() => setConfirm("restart")}>批量重启{selectedIds.length ? `（${selectedIds.length}）` : ""}</button>
      <button className="app-button-secondary border-red-200 bg-red-50 text-red-600" disabled={!selectedIds.length || submitting} onClick={() => setConfirm("reset")}>批量重置{selectedIds.length ? `（${selectedIds.length}）` : ""}</button>
      <span className="text-xs text-slate-500">仅处理已勾选 Lite；全局最多 5 个，重置最多 2 个。切换页面不影响执行。</span>
    </div>
    {error && <p role="alert" className="mt-2 text-sm text-red-600">{error}</p>}
    {!!batches.length && <div className="mt-3 text-sm">
      <select aria-label="批任务" className="max-w-full rounded border p-1" value={selected || detail?.batch.batch_id || ""} onChange={e => { setSelected(e.target.value); setPage(1); }}>
        {batches.map(b => <option key={b.batch_id} value={b.batch_id}>{b.action === "reset" ? "重置" : "重启"} · {new Date(b.created_at).toLocaleString()} · {labels[b.status] || b.status}</option>)}
      </select>
      {detail && <>
        <p className="my-2">{labels[detail.batch.status]} · 共 {detail.total} 个 · {Object.entries(detail.counts).map(([state, count]) => `${labels[state] || state} ${count}`).join(" / ")}</p>
        {unfinished(detail.batch) && <div className="mb-2 flex gap-2">
          {detail.batch.status !== "cancelling" && <button className="app-button-secondary" onClick={() => void control(detail.batch.status === "paused" ? "resume" : "pause")}>{detail.batch.status === "paused" ? "继续剩余任务" : "暂停派发"}</button>}
          {detail.batch.status !== "cancelling" && <button className="app-button-secondary" onClick={() => void control("cancel")}>取消未开始的任务</button>}
        </div>}
        <details><summary className="cursor-pointer">查看逐项结果（重置成功后显示新实例 ID）</summary>
          {detail.items.map(({ item, operation }) => <div key={item.source_id} className="border-b py-1">#{item.source_id} {item.source_name} · {labels[item.state] || item.state}{operation?.instance_id && operation.instance_id !== item.source_id ? ` → #${operation.instance_id}` : ""}{operation?.error_message ? ` · ${operation.error_message}` : ""}</div>)}
          <div className="mt-2 flex gap-3"><button disabled={page <= 1} onClick={() => setPage(p => p - 1)}>上一页</button><span>{page} / {Math.max(1, Math.ceil(detail.total / detail.page_size))}</span><button disabled={page * detail.page_size >= detail.total} onClick={() => setPage(p => p + 1)}>下一页</button></div>
        </details>
      </>}
    </div>}
    <ConfirmDialog open={confirm !== null} cancelLabel="取消" destructive={confirm === "reset"} title={confirm === "reset" ? "确认批量重置" : "确认批量重启"} message={confirm === "reset" ? `将分批重置 ${selectedIds.length} 个 Lite 实例。重置会删除旧实例的全部数据、对话和配置，无法撤销，请提前自行备份。新实例未就绪时不会删除旧实例；任务成功后旧数据不会保留。` : `将分批重启 ${selectedIds.length} 个 Lite 实例。工作区数据保留，但运行中的任务和连接会中断，尚未保存的内容可能丢失。`} confirmLabel={confirm === "reset" ? "确认删除数据并重置" : "确认重启"} onConfirm={() => void submit()} onCancel={() => !submitting && setConfirm(null)} loading={submitting} />
  </div>;
}
