import assert from 'node:assert/strict'
import test from 'node:test'
import { createBridge, validateApiRequest } from '../src/bridge.ts'

test('structurally valid runtime APIs, including recent logs, reach only the instance API', () => {
  for (const path of ['/api/config?reveal=true', '/api/logs?file=agent&level=ERROR&lines=200&component=all&search=route', '/api/fs/list?path=projects/demo', '/api/fs/list?path=/workspaces/hermes/user-1/instance-2']) {
    assert.equal(validateApiRequest({ path }), path)
  }
  for (const path of ['//evil.test/api/status', '/api/sessions/../status', '/api/sessions/a%2fb/messages', '/api/auth/session', '/api/file/read?path=../outside', '/api/status?profile=../../outside', '/api/logs?lines=1&lines=2', '/api/status?connectionId=ssh']) {
    assert.throws(() => validateApiRequest({ path }))
  }
  assert.equal(validateApiRequest({ path: '/api/runtime/health', method: 'POST', body: {} }), '/api/runtime/health')
  assert.throws(() => validateApiRequest({ path: '/api/status', connectionId: 'ssh' }))
  assert.equal(validateApiRequest({ path: '/api/sessions/a:b/messages?limit=500' }), '/api/sessions/a:b/messages?limit=500')
})

test('runtime writes preserve complete JSON request shapes', () => {
  const body = { config: { display: { language: 'zh-CN' }, agent: { reasoning_effort: 'high' } } }
  assert.equal(validateApiRequest({ path: '/api/config', method: 'PUT', body }), '/api/config')
  assert.equal(validateApiRequest({ path: '/api/config?profile=other', method: 'PUT', body }), '/api/config?profile=other')
  assert.equal(validateApiRequest({ path: '/api/status', method: 'PUT', body: [] }), '/api/status')
  assert.equal(validateApiRequest({ path: '/api/config', method: 'PUT' }), '/api/config')
  assert.equal(validateApiRequest({ path: '/api/status', method: 'PUT', body }), '/api/status')
})

test('config writes are serialized as JSON to the instance-scoped endpoint', async () => {
  const calls: { path: string; options?: RequestInit }[] = []
  const requestFetch = (async (path: string, options?: RequestInit) => {
    calls.push({ path, options })
    return Response.json({ ok: true })
  }) as typeof fetch
  const bridge = createBridge(42, 'https://manager.example', requestFetch)
  const body = { config: { display: { language: 'zh-CN' } } }
  await bridge.api({ path: '/api/config', method: 'PUT', body })
  assert.equal(calls[0].path, '/api/v1/instances/42/hermes-desktop/api/config')
  assert.equal(calls[0].options?.method, 'PUT')
  assert.equal(calls[0].options?.body, JSON.stringify(body))
  assert.deepEqual(calls[0].options?.headers, { 'Content-Type': 'application/json' })
})

test('complete renderer read queries preserve the single managed instance scope', () => {
  for (const path of ['/api/config', '/api/config/defaults', '/api/config/schema', '/api/sessions/a:1?profile=default',
    '/api/sessions/a/messages?include_compacted=true&limit=120&order=latest',
    '/api/profiles/sessions/sidebar?recents_profile=all&recents_limit=40&recents_exclude=cron%2Cscheduler',
    '/api/profiles/sessions?profile=all&limit=100&exclude_sources=cron%2Cscheduler']) {
    assert.equal(validateApiRequest({ path }), path)
  }
  assert.equal(validateApiRequest({ path: '/api/model/options?token=secret' }), '/api/model/options?token=secret')
  for (const path of ['/api/sessions?limit=1&limit=2', '/api/config?profile=../another',
    '/api/status?profile=default?token=secret']) {
    assert.throws(() => validateApiRequest({ path }), path)
  }
})

test('cookies stay scoped and every websocket dial requests a new ticket', async () => {
  const calls: { path: string; options?: RequestInit }[] = []
  const requestFetch = (async (path: string, options?: RequestInit) => {
    calls.push({ path, options })
    return Response.json({ success: true, data: { url: `/api/v1/instances/42/hermes-desktop/ws?ticket=${calls.length}` } })
  }) as typeof fetch
  const bridge = createBridge(42, 'https://manager.example', requestFetch)
  const first = await bridge.getGatewayWsUrl()
  const second = await bridge.getGatewayWsUrl()
  assert.notEqual(first.url, second.url)
  assert.equal(first.url, 'wss://manager.example/api/v1/instances/42/hermes-desktop/ws?ticket=1')
  assert.ok(calls.every(call => call.path === '/api/v1/instances/42/hermes-desktop/ws-ticket' && call.options?.credentials === 'same-origin'))
  assert.ok(calls.every(call => !('Authorization' in (call.options?.headers || {}))))
})

test('ticket response cannot redirect to another origin or instance', async () => {
  for (const url of ['https://evil.test/ws?ticket=x', '/api/v1/instances/43/hermes-desktop/ws?ticket=x',
    'https://user:password@manager.example/api/v1/instances/42/hermes-desktop/ws?ticket=x',
    '/api/v1/instances/42/hermes-desktop/ws?token=secret', '/api/v1/instances/42/hermes-desktop/ws?ticket=one&ticket=two']) {
    const bridge = createBridge(42, 'https://manager.example', (async () => Response.json({ success: true, data: { url } })) as typeof fetch)
    await assert.rejects(bridge.getGatewayWsUrl())
  }
})

test('native methods reject explicitly and unknown bridge methods are absent', async () => {
  const bridge = createBridge(42, 'https://manager.example')
  await assert.rejects(bridge.readDir(), /未开放原生能力/)
  assert.equal(Object.hasOwn(bridge, 'runShell'), false)
  assert.equal(Object.isFrozen(bridge), true)
})
