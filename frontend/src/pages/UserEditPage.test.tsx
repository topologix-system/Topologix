import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import { UserEditPage } from './UserEditPage'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => `t:${key}` }),
}))

vi.mock('../services/api', () => ({
  authAPI: { hasRole: () => true },
}))

vi.mock('../hooks/useUsers', () => ({
  useUser: () => ({
    data: {
      id: 2,
      username: 'viewer1',
      email: 'viewer1@example.com',
      is_active: true,
      is_superuser: false,
      email_verified: true,
      created_at: '2026-01-01T00:00:00Z',
      roles: ['viewer'],
    },
    isLoading: false,
    error: null,
  }),
  useUpdateUser: () => ({ mutateAsync: vi.fn(), isPending: false, error: null }),
}))

describe('UserEditPage', () => {
  it('shows the localized Back link to the user list', () => {
    render(
      <MemoryRouter initialEntries={['/admin/users/2/edit']}>
        <Routes>
          <Route path="/admin/users/:id/edit" element={<UserEditPage />} />
        </Routes>
      </MemoryRouter>
    )

    expect(screen.getByRole('link', { name: 't:common.back' })).toHaveAttribute('href', '/admin/users')
  })
})
