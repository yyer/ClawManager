import type {
  AgentStatus,
  FilePolicy,
  InvasionPolicy,
  LogEntry,
  RansomPolicy,
} from '../types/hostHardening';

// All endpoints same-origin via Nginx (or vite dev proxy → ksec-bridge :9101).
// MVP: no auth headers — bridge has KSEC_BRIDGE_AUTH_ENABLED=false.
const base = '/api/host';

async function jsonOrThrow<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail =
      typeof (body as { details?: unknown }).details === 'string'
        ? (body as { details: string }).details
        : '';
    const msg = (body as { error?: string }).error ?? `HTTP ${res.status}`;
    throw new Error(detail ? `${msg}: ${detail}` : msg);
  }
  return res.json() as Promise<T>;
}

export async function getStatus(): Promise<AgentStatus> {
  return jsonOrThrow(await fetch(`${base}/status`));
}

export async function getRansomPolicy(): Promise<RansomPolicy> {
  return jsonOrThrow(await fetch(`${base}/policy/ransome`));
}

/** PUT result. `warning` set when the master switch flipped OK but policy load failed. */
export interface PutResult {
  success: boolean;
  warning?: string;
}

export async function putRansomPolicy(pol: RansomPolicy): Promise<PutResult> {
  return jsonOrThrow<PutResult>(
    await fetch(`${base}/policy/ransome`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pol),
    }),
  );
}

export async function getFilePolicy(): Promise<FilePolicy> {
  return jsonOrThrow(await fetch(`${base}/policy/file`));
}

export async function putFilePolicy(pol: FilePolicy): Promise<PutResult> {
  return jsonOrThrow<PutResult>(
    await fetch(`${base}/policy/file`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pol),
    }),
  );
}

export async function getInvasionPolicy(): Promise<InvasionPolicy> {
  return jsonOrThrow(await fetch(`${base}/policy/invasion`));
}

export async function putInvasionPolicy(pol: InvasionPolicy): Promise<PutResult> {
  return jsonOrThrow<PutResult>(
    await fetch(`${base}/policy/invasion`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pol),
    }),
  );
}

export async function getLogs(module: string, limit = 50): Promise<LogEntry[]> {
  return jsonOrThrow(
    await fetch(
      `${base}/logs?module=${encodeURIComponent(module)}&limit=${limit}`,
    ),
  );
}

/** Open an EventSource on `/api/host/logs/stream`. Caller must `close()` on unmount. */
export function openLogStream(module: string): EventSource {
  return new EventSource(`${base}/logs/stream?module=${encodeURIComponent(module)}`);
}
