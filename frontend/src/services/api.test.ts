import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

interface AuthClient {
  authAPI: {
    logout(): Promise<void>
    isAuthenticated(): boolean
  }
  usersAPI: {
    getMe(): Promise<unknown>
  }
}

const clientModules: Record<string, () => Promise<AuthClient>> = {
  api: () => import('./api'),
  api_secure: () => import('./api_secure'),
}

// Answers after which a looping client is let through so the test ends
const LOOP_GUARD = 5

function reply(config: InternalAxiosRequestConfig, status: number, data: unknown): Promise<AxiosResponse> {
  const response: AxiosResponse = { data, status, statusText: String(status), headers: {}, config }
  if (status >= 400) {
    return Promise.reject(
      new AxiosError(`Request failed with status code ${status}`, AxiosError.ERR_BAD_REQUEST, config, null, response)
    )
  }
  return Promise.resolve(response)
}

async function loadClient(moduleName: string, unauthorizedPaths: string[]) {
  vi.resetModules()
  window.__TOPOLOGIX_CONFIG__ = { authEnabled: true, apiBaseUrl: '' }
  localStorage.setItem('user', JSON.stringify({ username: 'alice', roles: ['viewer'], email: 'alice@example.test' }))
  localStorage.setItem('token_expires_at', String(Date.now() + 3600 * 1000))

  const calls: string[] = []
  const { default: axios } = await import('axios')
  axios.defaults.adapter = (config) => {
    const path = (config.url ?? '').replace(/^.*\/api/, '')
    calls.push(path)
    if (path === '/auth/csrf-token') {
      return reply(config, 200, { data: { csrf_token: 'csrf-test-token' } })
    }
    const answered = calls.filter((call) => call === path).length
    if (unauthorizedPaths.includes(path) && answered <= LOOP_GUARD) {
      return reply(config, 401, { status: 'error', message: 'Invalid or expired token' })
    }
    return reply(config, 200, { status: 'success', data: { expires_in: 3600 } })
  }

  const client = await clientModules[moduleName]()
  const count = (path: string) => calls.filter((call) => call === path).length
  return { ...client, count }
}

describe.each(Object.keys(clientModules))('%s 401 handling for dead sessions', (moduleName) => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
  })

  afterEach(() => {
    delete window.__TOPOLOGIX_CONFIG__
    localStorage.clear()
    sessionStorage.clear()
  })

  it('sends logout once and clears the session when logout itself answers 401', async () => {
    const { authAPI, count } = await loadClient(moduleName, ['/auth/logout', '/auth/refresh'])

    await authAPI.logout()

    expect(count('/auth/logout')).toBe(1)
    expect(count('/auth/refresh')).toBe(0)
    expect(localStorage.getItem('user')).toBeNull()
    expect(localStorage.getItem('token_expires_at')).toBeNull()
    expect(authAPI.isAuthenticated()).toBe(false)
  })

  it('logs out once when a 401 cannot be refreshed and logout answers 401', async () => {
    const { authAPI, usersAPI, count } = await loadClient(moduleName, ['/users/me', '/auth/logout', '/auth/refresh'])

    await expect(usersAPI.getMe()).rejects.toMatchObject({ response: { status: 401 } })

    expect(count('/users/me')).toBe(1)
    expect(count('/auth/refresh')).toBe(1)
    expect(count('/auth/logout')).toBe(1)
    expect(localStorage.getItem('user')).toBeNull()
    expect(authAPI.isAuthenticated()).toBe(false)
  })
})
