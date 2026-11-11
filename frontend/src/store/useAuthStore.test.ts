import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import i18n from 'i18next'
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import en from '../i18n/locales/en.json'
import ja from '../i18n/locales/ja.json'
import { useAuthStore } from './useAuthStore'

const loginMock = vi.hoisted(() => vi.fn())

vi.mock('../services/api', () => ({
  authAPI: {
    getCurrentUser: () => null,
    isAuthenticated: () => false,
    login: loginMock,
    logout: vi.fn(),
  },
}))

function axiosErrorWithResponse(status: number, data: unknown): AxiosError {
  const config = { headers: new AxiosHeaders() }
  const response: AxiosResponse = { status, statusText: '', headers: {}, config, data }
  return new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_REQUEST', config, {}, response)
}

async function loginError(error: unknown) {
  loginMock.mockRejectedValueOnce(error)
  await expect(useAuthStore.getState().login('admin', 'wrong')).rejects.toBe(error)
  return useAuthStore.getState().error
}

beforeAll(async () => {
  await i18n.init({
    lng: 'en',
    resources: { en: { translation: en }, ja: { translation: ja } },
    interpolation: { escapeValue: false },
  })
})

describe('useAuthStore login errors', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en')
    loginMock.mockReset()
    useAuthStore.setState({ error: null, isLoading: false })
  })

  it('shows the localized login failure when the error body carries no message', async () => {
    expect(await loginError(axiosErrorWithResponse(401, ''))).toBe('Login failed. Please check your credentials.')

    await i18n.changeLanguage('ja')
    expect(await loginError(axiosErrorWithResponse(401, ''))).toBe(ja.auth.loginFailed)
  })

  it('shows the server message of a JSON error body', async () => {
    expect(await loginError(axiosErrorWithResponse(401, { message: 'Invalid username or password' }))).toBe(
      'Invalid username or password'
    )
  })

  it('shows the network error instead of the credentials message when the backend is unreachable', async () => {
    expect(await loginError(new AxiosError('Network Error', 'ERR_NETWORK'))).toBe('Network error occurred')
    expect(await loginError(new AxiosError('timeout of 30000ms exceeded', 'ECONNABORTED'))).toBe(
      'timeout of 30000ms exceeded'
    )
  })
})
