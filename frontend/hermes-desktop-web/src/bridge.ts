export type ApiRequest = {
  path: string; method?: string; body?: unknown; profile?: string | null; connectionId?: string | null
}
export type SessionDescriptor = {
  available: boolean; instance_id: number; reason?: string; capabilities: string[]
  versions: { bridge_version: string; hermes_commit?: string }
}
type Envelope<T> = { success: boolean; data: T }

const API_PATH = /^\/api\/[A-Za-z0-9_.:-]+(?:\/[A-Za-z0-9_.:-]+)*$/
const QUERY_KEY = /^[A-Za-z0-9_-]{1,80}$/
const PROFILE_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/
const PATH_QUERY_KEYS = new Set(['cwd', 'path', 'directory', 'dir', 'folder', 'folders', 'file', 'files', 'primary_path', 'workspace', 'workspace_path', 'root', 'root_path', 'repo_path', 'project_path', 'file_path', 'filename'])

export function validateApiRequest(request: ApiRequest): string {
  if (request.connectionId) throw new Error('此页面不支持外部连接。')
  const method = request.method || 'GET'
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) throw new Error('不支持此 API 操作。')
  if (method === 'GET' && request.body !== undefined) throw new Error('读取请求不能携带正文。')
  if (!request.path.startsWith('/api/') || /[\\#]/.test(request.path) || request.path.split('?').length > 2 || request.path.length > 4096) throw new Error('非法 API 路径。')
  const [pathname, query = ''] = request.path.split('?')
  if (pathname.includes('%') || !API_PATH.test(pathname) || pathname.split('/').some(segment => segment === '.' || segment === '..')) throw new Error('非法 API 路径。')
  if (pathname === '/api/auth' || pathname.startsWith('/api/auth/')) throw new Error('禁止代理 Runtime 认证接口。')
  const params = new URLSearchParams(query)
  for (const [key, value] of params) {
    if (!QUERY_KEY.test(key) || value.length > 4096 || params.getAll(key).length !== 1) throw new Error('非法 API 参数。')
    if (key === 'connectionId') throw new Error('此页面不支持外部连接。')
    if ((key === 'profile' || key === 'recents_profile') && !PROFILE_NAME.test(value)) throw new Error('不支持其他 Profile。')
    if (PATH_QUERY_KEYS.has(key.toLowerCase()) && (value.includes('\\') || value.split('/').includes('..'))) {
      throw new Error('路径必须位于当前实例 workspace。')
    }
  }
  return request.path
}

export function createBridge(instanceId: number, origin: string, requestFetch: typeof fetch = fetch) {
  if (!Number.isSafeInteger(instanceId) || instanceId <= 0) throw new Error('无效的实例 ID。')
  const base = `/api/v1/instances/${instanceId}/hermes-desktop`
  async function read<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
    const response = await requestFetch(`${base}${path}`, {
      method, credentials: 'same-origin', redirect: 'error', cache: 'no-store',
      headers: method === 'GET' ? {} : { 'Content-Type': 'application/json' },
      body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
      signal: AbortSignal.timeout(60_000)
    })
    if (!response.ok) {
      if (response.status === 401) throw new Error('访问会话已失效，请在 ClawManager 中重新打开 Desktop Web。')
      throw new Error(`Hermes 服务请求失败（HTTP ${response.status}），可切回经典 Dashboard。`)
    }
    return response.json() as Promise<T>
  }
  const unsupported = (name: string) => async () => { throw new Error(`Desktop Web 未开放原生能力：${name}`) }
  return Object.freeze({
    async session(): Promise<SessionDescriptor> {
      const response = await read<Envelope<SessionDescriptor>>('/session')
      if (!response.success || response.data.instance_id !== instanceId || !response.data.available) throw new Error('当前实例暂不支持 Desktop Web。')
      if (response.data.versions.bridge_version !== '1') throw new Error('Desktop Web 协议版本不兼容。')
      return response.data
    },
    async getConnection() { return { baseUrl: `${origin}${base}`, mode: 'remote', authMode: 'oauth' } },
    async getGatewayWsUrl() {
      const response = await read<Envelope<{ url: string }>>('/ws-ticket', 'POST')
      if (!response.success) throw new Error('无法建立 WebSocket 会话。')
      const url = new URL(response.data.url, origin)
      const page = new URL(origin)
      if (url.host !== page.host || url.pathname !== `${base}/ws` || url.username || url.password || url.hash ||
        !['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol) ||
        [...url.searchParams.keys()].some(key => key !== 'ticket') || url.searchParams.getAll('ticket').length !== 1 || !url.searchParams.get('ticket')) {
        throw new Error('拒绝非当前实例的 WebSocket 地址。')
      }
      url.protocol = page.protocol === 'https:' ? 'wss:' : 'ws:'
      return { url: url.toString(), authMode: 'oauth' as const }
    },
    async api<T>(request: ApiRequest): Promise<T> {
      return read<T>(validateApiRequest(request), request.method || 'GET', request.body)
    },
    readFileDataUrl: unsupported('readFileDataUrl'), readFileText: unsupported('readFileText'),
    readDir: unsupported('readDir'), selectPaths: unsupported('selectPaths'), selectSavePath: unsupported('selectSavePath'),
    openSessionWindow: unsupported('openSessionWindow'), openSessionInTerminal: unsupported('openSessionInTerminal'),
    openWindow: unsupported('openWindow'), getConnections: unsupported('getConnections'),
    setConnectionConfig: unsupported('setConnectionConfig'), updateApp: unsupported('updateApp')
  })
}
export type BrowserBridge = ReturnType<typeof createBridge>
