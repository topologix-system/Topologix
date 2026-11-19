import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import { afterEach, describe, expect, it, vi } from 'vitest'

type Client = typeof import('./api')

const clientModules: Record<string, () => Promise<Client>> = {
  api: () => import('./api'),
  api_secure: () => import('./api_secure') as unknown as Promise<Client>,
}

const identityHeaders = {
  'x-topologix-snapshot-id': 'snapshot-id-1',
  'x-topologix-content-hash': 'a'.repeat(64),
  'x-topologix-cache': 'hit',
}

async function loadClient(moduleName: string, authEnabled: boolean) {
  vi.resetModules()
  window.__TOPOLOGIX_CONFIG__ = { authEnabled, apiBaseUrl: '' }
  if (authEnabled) {
    localStorage.setItem('user', JSON.stringify({ username: 'alice', roles: ['viewer'], email: 'alice@example.test' }))
    localStorage.setItem('token_expires_at', String(Date.now() + 3600 * 1000))
  }
  const requests: InternalAxiosRequestConfig[] = []
  const { default: axios } = await import('axios')
  axios.defaults.adapter = (config) => {
    const path = (config.url ?? '').replace(/^.*\/api/, '')
    if (path === '/auth/csrf-token') {
      return Promise.resolve({ data: { data: { csrf_token: 'csrf' } }, status: 200, statusText: 'OK', headers: {}, config })
    }
    requests.push(config)
    const response: AxiosResponse = {
      data: { status: 'success', data: { ok: true } },
      status: 200,
      statusText: 'OK',
      headers: identityHeaders,
      config,
    }
    return Promise.resolve(response)
  }
  return { client: await clientModules[moduleName](), requests }
}

const requestHeader = (config: InternalAxiosRequestConfig, name: string) => config.headers?.get?.(name) ?? undefined

const cases: [string, boolean][] = [
  ['api', false],
  ['api', true],
  ['api_secure', true],
]

const versioningSnapshotMethods = [
  'activate',
  'getVersionState',
  'listVersions',
  'getVersion',
  'commitVersion',
  'getVersionDiff',
  'getVersionFileDiff',
  'restoreVersion',
  'deleteVersion',
  'deleteVersions',
  'clearResultCache',
] as const

const identityNetworkMethods = ['getAllData', 'getNodes', 'getInterfaces', 'getRoutes', 'getVlans', 'getIPOwners'] as const

describe('api and api_secure versioning parity', () => {
  afterEach(() => {
    delete window.__TOPOLOGIX_CONFIG__
    localStorage.clear()
    sessionStorage.clear()
  })

  it('expose every snapshot versioning method and identity-returning network getter as a function', async () => {
    for (const moduleName of Object.keys(clientModules)) {
      const { client } = await loadClient(moduleName, true)
      for (const method of versioningSnapshotMethods) {
        expect(typeof client.snapshotAPI[method], `${moduleName}.snapshotAPI.${method}`).toBe('function')
      }
      for (const method of identityNetworkMethods) {
        expect(typeof client.networkAPI[method], `${moduleName}.networkAPI.${method}`).toBe('function')
      }
    }
  })
})

describe.each(cases)('%s (auth=%s) versioning requests', (moduleName, authEnabled) => {
  afterEach(() => {
    delete window.__TOPOLOGIX_CONFIG__
    localStorage.clear()
    sessionStorage.clear()
  })

  it('sends no Cache-Control or Pragma request headers to cached endpoints and returns the identity headers', async () => {
    const { client, requests } = await loadClient(moduleName, authEnabled)

    const responses = await Promise.all([
      client.networkAPI.getAllData(),
      client.networkAPI.getNodes(),
      client.networkAPI.getInterfaces(),
      client.networkAPI.getRoutes(),
      client.networkAPI.getVlans(),
      client.networkAPI.getIPOwners(),
    ])
    await client.ospfAPI.getProcesses()
    await client.validationAPI.getUnusedStructures()

    expect(requests).toHaveLength(8)
    for (const config of requests) {
      expect(requestHeader(config, 'Cache-Control')).toBeUndefined()
      expect(requestHeader(config, 'Pragma')).toBeUndefined()
    }
    for (const response of responses) {
      expect(response.identity).toEqual({
        snapshotId: 'snapshot-id-1',
        contentHash: 'a'.repeat(64),
        cacheStatus: 'hit',
      })
    }
  })

  it('sends the if_stale activation body only when the flag is set', async () => {
    const { client, requests } = await loadClient(moduleName, authEnabled)

    await client.snapshotAPI.activate('snap-a')
    await client.snapshotAPI.activate('snap-a', { if_stale: true })

    expect(requests[0].url).toContain('/snapshots/snap-a/activate')
    expect(requests[0].data).toBeUndefined()
    expect(JSON.parse(requests[1].data)).toEqual({ if_stale: true })
  })

  it('builds the version route requests with the documented shapes', async () => {
    const { client, requests } = await loadClient(moduleName, authEnabled)

    await client.snapshotAPI.getVersionState('snap-a')
    await client.snapshotAPI.listVersions('snap-a', { limit: 50, offset: 50 })
    await client.snapshotAPI.getVersion('snap-a', 'v-1')
    await client.snapshotAPI.commitVersion('snap-a', { message: 'm', expected_head: null })
    await client.snapshotAPI.getVersionDiff('snap-a', 'v-1', 'working')
    await client.snapshotAPI.getVersionFileDiff('snap-a', 'v-1', 'working', 'configs/a b.cfg')
    await client.snapshotAPI.restoreVersion('snap-a', 'v-1', { expected_working_hash: 'w' })
    await client.snapshotAPI.deleteVersion('snap-a', 'v-1', { expected_head: 'v-2' })
    await client.snapshotAPI.deleteVersions('snap-a', { mode: 'all', expected_unavailable: 'missing_objects' })
    await client.snapshotAPI.clearResultCache('snap-a')

    const summary = requests.map((config) => [
      config.method,
      config.url?.replace(/^.*\/api/, ''),
      config.params,
      config.data ? JSON.parse(config.data) : undefined,
    ])
    expect(summary).toEqual([
      ['get', '/snapshots/snap-a/version-state', undefined, undefined],
      ['get', '/snapshots/snap-a/versions', { limit: 50, offset: 50 }, undefined],
      ['get', '/snapshots/snap-a/versions/v-1', undefined, undefined],
      ['post', '/snapshots/snap-a/versions', undefined, { message: 'm', expected_head: null }],
      ['get', '/snapshots/snap-a/versions/v-1/diff', { against: 'working' }, undefined],
      ['get', '/snapshots/snap-a/versions/v-1/diff/file', { against: 'working', path: 'configs/a b.cfg' }, undefined],
      ['post', '/snapshots/snap-a/versions/v-1/restore', undefined, { expected_working_hash: 'w' }],
      ['delete', '/snapshots/snap-a/versions/v-1', undefined, { expected_head: 'v-2' }],
      ['delete', '/snapshots/snap-a/versions', undefined, { mode: 'all', expected_unavailable: 'missing_objects' }],
      ['post', '/snapshots/snap-a/cache/clear', undefined, undefined],
    ])
  })
})
