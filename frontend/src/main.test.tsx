import { isValidElement, type ReactElement } from 'react'
import { matchRoutes, Navigate, type RouteObject } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import { buildRoutes } from './main'

vi.mock('react-dom/client', () => ({
  default: { createRoot: () => ({ render: vi.fn() }) },
}))

function leafRoute(routes: RouteObject[], path: string) {
  const matches = matchRoutes(routes, path)
  return matches?.[matches.length - 1]?.route
}

function redirectsHome(route: RouteObject | undefined) {
  const element = route?.element
  return (
    isValidElement(element) &&
    element.type === Navigate &&
    (element as ReactElement<{ to: string }>).props.to === '/'
  )
}

const AUTH_ONLY_PATHS = [
  '/login',
  '/register',
  '/password-reset-request',
  '/password-reset/abc',
  '/password-reset',
  '/password-reset/',
  '/profile',
  '/admin/users',
  '/admin/users/1/edit',
  '/admin/security-logs',
  '/admin/snapshot-migrations',
]

const ALWAYS_PATHS = ['/', '/snapshots', '/snapshots/compare', '/snapshots/s1/layer1-editor', '/sidebar-popout']

describe('buildRoutes', () => {
  it('redirects auth-only pages home when authentication is disabled', () => {
    const routes = buildRoutes(false)
    for (const path of AUTH_ONLY_PATHS) {
      expect(redirectsHome(leafRoute(routes, path)), path).toBe(true)
    }
  })

  it('renders auth-only pages when authentication is enabled', () => {
    const routes = buildRoutes(true)
    for (const path of AUTH_ONLY_PATHS) {
      const route = leafRoute(routes, path)
      expect(route?.path, path).not.toBe('*')
      expect(redirectsHome(route), path).toBe(false)
    }
  })

  it.each([false, true])('keeps the application routes regardless of authentication (auth=%s)', (authEnabled) => {
    const routes = buildRoutes(authEnabled)
    for (const path of ALWAYS_PATHS) {
      const route = leafRoute(routes, path)
      expect(route?.path === '*' || redirectsHome(route), path).toBe(false)
    }
  })

  it.each([false, true])('routes /password-reset without a token through its own auth-only route (auth=%s)', (authEnabled) => {
    const routes = buildRoutes(authEnabled)
    for (const path of ['/password-reset', '/password-reset/']) {
      const route = leafRoute(routes, path)
      expect(route?.path, path).toBe('/password-reset')
      expect(redirectsHome(route), path).toBe(!authEnabled)
    }
  })

  it.each([false, true])('sends unknown paths home and has an application error element (auth=%s)', (authEnabled) => {
    const routes = buildRoutes(authEnabled)
    const route = leafRoute(routes, '/no-such-page')
    expect(route?.path).toBe('*')
    expect(redirectsHome(route)).toBe(true)
    expect(routes).toHaveLength(1)
    expect(routes[0].errorElement).toBeTruthy()
  })
})
