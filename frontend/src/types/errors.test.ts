import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import i18n from 'i18next'
import { beforeAll, describe, expect, it } from 'vitest'

import en from '../i18n/locales/en.json'
import ja from '../i18n/locales/ja.json'
import {
  extractAxiosErrorMessage,
  extractErrorMessage,
  extractResponseBodyMessage,
} from './errors'

beforeAll(async () => {
  await i18n.init({
    lng: 'en',
    resources: { en: { translation: en }, ja: { translation: ja } },
    interpolation: { escapeValue: false },
  })
})

function axiosErrorWithResponse(status: number, data: unknown): AxiosError {
  const config = { headers: new AxiosHeaders() }
  const response: AxiosResponse = { status, statusText: '', headers: {}, config, data }
  return new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_RESPONSE', config, {}, response)
}

describe('extractResponseBodyMessage', () => {
  it('prefers message, then error, then details.message / details.reason', () => {
    expect(extractResponseBodyMessage({ message: 'm', error: 'e' })).toBe('m')
    expect(extractResponseBodyMessage({ error: 'e' })).toBe('e')
    expect(extractResponseBodyMessage({ code: 'c', details: { message: 'dm', reason: 'dr' } })).toBe('dm')
    expect(extractResponseBodyMessage({ code: 'c', details: { reason: 'dr' } })).toBe('dr')
  })

  it('ignores empty strings, non-string fields and non-object bodies', () => {
    expect(extractResponseBodyMessage({ message: '  ', error: 'e' })).toBe('e')
    expect(extractResponseBodyMessage({ message: 42, error: { message: 'nested' } })).toBeNull()
    expect(extractResponseBodyMessage({ code: 'c' })).toBeNull()
    expect(extractResponseBodyMessage('<html><body>500</body></html>')).toBeNull()
    expect(extractResponseBodyMessage(['message'])).toBeNull()
    expect(extractResponseBodyMessage(null)).toBeNull()
    expect(extractResponseBodyMessage(undefined)).toBeNull()
  })
})

describe('extractAxiosErrorMessage', () => {
  it('returns the server message of a JSON error body', () => {
    const error = axiosErrorWithResponse(400, { status: 'error', message: 'Invalid or expired reset token', code: 'x' })
    expect(extractAxiosErrorMessage(error, 'fallback')).toBe('Invalid or expired reset token')
  })

  it('returns the fallback instead of the generic axios text for a non-JSON error body', () => {
    const error = axiosErrorWithResponse(500, '<html><body><h1>500 Internal Server Error</h1></body></html>')
    expect(extractAxiosErrorMessage(error, 'Localized fallback')).toBe('Localized fallback')
  })

  it('returns the axios message instead of the fallback when there is no response', () => {
    const timeout = new AxiosError('timeout of 120000ms exceeded', 'ECONNABORTED')
    expect(extractAxiosErrorMessage(timeout, 'Login failed. Please check your credentials.')).toBe('timeout of 120000ms exceeded')
  })

  it('returns the localized network error for ERR_NETWORK without a response', async () => {
    const error = new AxiosError('Network Error', 'ERR_NETWORK')
    await i18n.changeLanguage('en')
    expect(extractAxiosErrorMessage(error, 'Login failed. Please check your credentials.')).toBe('Network error occurred')
    await i18n.changeLanguage('ja')
    expect(extractAxiosErrorMessage(error, 'fallback')).toBe(ja.errors.networkError)
    await i18n.changeLanguage('en')
  })

  it('returns the axios message for ERR_NETWORK when no translation exists', async () => {
    await i18n.changeLanguage('xx')
    expect(extractAxiosErrorMessage(new AxiosError('Network Error', 'ERR_NETWORK'), 'fallback')).toBe('Network Error')
    await i18n.changeLanguage('en')
  })

  it('returns the fallback when there is neither a response nor an axios message', () => {
    expect(extractAxiosErrorMessage(new AxiosError(''), 'Localized fallback')).toBe('Localized fallback')
  })

  it('returns the axios message only when the fallback is empty', () => {
    const error = axiosErrorWithResponse(502, '')
    expect(extractAxiosErrorMessage(error, '')).toBe('Request failed with status code 502')
  })
})

describe('extractErrorMessage', () => {
  it('delegates AxiosError to the body-first precedence', () => {
    expect(extractErrorMessage(axiosErrorWithResponse(403, { error: 'Access forbidden' }), 'fb')).toBe('Access forbidden')
    expect(extractErrorMessage(axiosErrorWithResponse(404, {}), 'fb')).toBe('fb')
    expect(extractErrorMessage(new AxiosError('timeout of 120000ms exceeded', 'ECONNABORTED'), 'fb')).toBe('timeout of 120000ms exceeded')
  })

  it('uses the message of a plain Error and the fallback otherwise', () => {
    expect(extractErrorMessage(new Error('Authentication is not enabled'), 'fb')).toBe('Authentication is not enabled')
    expect(extractErrorMessage(new Error(''), 'fb')).toBe('fb')
    expect(extractErrorMessage('boom', 'fb')).toBe('fb')
    expect(extractErrorMessage(undefined, 'fb')).toBe('fb')
  })
})
