import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import { LoginPage } from './LoginPage'

vi.mock('../hooks', () => ({
  useAuthModeStatus: () => ({ authModeMismatch: false, frontendAuthEnabled: true, backendAuthEnabled: true }),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options?: { defaultValue?: string }) => {
      if (key === 'passwordReset.resetSuccess') return 'Your password has been reset successfully.'
      return options?.defaultValue ?? key
    },
  }),
}))

function LocationStateProbe() {
  const location = useLocation()
  return <div data-testid="location-state">{JSON.stringify(location.state)}</div>
}

function renderLogin(state?: unknown) {
  return render(
    <MemoryRouter initialEntries={[{ pathname: '/login', state }]}>
      <LoginPage />
      <LocationStateProbe />
    </MemoryRouter>
  )
}

describe('LoginPage navigation-state message', () => {
  it('renders the translated message key passed in navigation state as a status banner', () => {
    renderLogin({ message: 'passwordReset.resetSuccess' })
    expect(screen.getByRole('status')).toHaveTextContent('Your password has been reset successfully.')
  })

  it('renders no banner without a message', () => {
    renderLogin({ from: { pathname: '/snapshots' } })
    expect(screen.queryByRole('status')).toBeNull()
  })

  it('removes the message from history state while keeping the banner and the rest of the state', async () => {
    renderLogin({ message: 'passwordReset.resetSuccess', from: { pathname: '/snapshots' } })
    await waitFor(() =>
      expect(JSON.parse(screen.getByTestId('location-state').textContent ?? 'null')).toEqual({ from: { pathname: '/snapshots' } })
    )
    expect(screen.getByRole('status')).toHaveTextContent('Your password has been reset successfully.')
  })

  it('leaves history state without a message untouched', () => {
    renderLogin({ from: { pathname: '/snapshots' } })
    expect(JSON.parse(screen.getByTestId('location-state').textContent ?? 'null')).toEqual({ from: { pathname: '/snapshots' } })
  })

  it('renders no banner for a key without a translation', () => {
    renderLogin({ message: 'no.such.key' })
    expect(screen.queryByRole('status')).toBeNull()
  })
})
