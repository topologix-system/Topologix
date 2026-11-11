import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import type { User } from '../types'
import { UserTable } from './UserTable'

const i18n = vi.hoisted(() => ({ calls: [] as Array<[string, Record<string, unknown> | undefined]> }))

vi.mock('react-i18next', async () => {
  const { translateEn } = await import('../__tests__/translateEn')
  const t = (key: string, params?: Record<string, unknown>) => {
    i18n.calls.push([key, params])
    return translateEn(key, params)
  }
  return { useTranslation: () => ({ t }) }
})

const USERS: User[] = [
  { id: 1, username: 'admin', email: 'admin@example.com', is_active: true, is_superuser: true, email_verified: true, created_at: '2026-01-01T00:00:00Z', roles: ['admin'] },
  { id: 2, username: 'viewer1', email: 'viewer1@example.com', is_active: true, is_superuser: false, email_verified: true, created_at: '2026-01-01T00:00:00Z', roles: ['viewer'] },
]

describe('UserTable delete confirmation', () => {
  it('labels the confirm and cancel buttons from the locale and deletes only after Confirm', () => {
    const onDelete = vi.fn()
    render(
      <MemoryRouter>
        <UserTable users={USERS} currentUserId={1} onDelete={onDelete} isDeleting={false} />
      </MemoryRouter>
    )

    fireEvent.click(screen.getByRole('button', { name: 'Delete user viewer1' }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel delete' }))
    expect(onDelete).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Confirm delete' })).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Delete user viewer1' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }))
    expect(onDelete).toHaveBeenCalledWith(2)
  })
})

describe('UserTable row action labels', () => {
  it('names the edit link and delete button of each user from the locale', () => {
    i18n.calls.length = 0
    render(
      <MemoryRouter>
        <UserTable users={USERS} currentUserId={1} onDelete={vi.fn()} isDeleting={false} />
      </MemoryRouter>
    )

    expect(screen.getByRole('link', { name: 'Edit user viewer1' })).toHaveAttribute('href', '/admin/users/2/edit')
    expect(screen.getByRole('link', { name: 'Edit user admin' })).toHaveAttribute('href', '/admin/users/1/edit')
    expect(screen.getByRole('button', { name: 'Delete user viewer1' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Delete user admin' })).toBeDisabled()
    for (const name of ['admin', 'viewer1']) {
      expect(i18n.calls).toContainEqual(['users.editUserAria', { name }])
      expect(i18n.calls).toContainEqual(['users.deleteUserAria', { name }])
    }
  })
})

describe('UserTable column headers', () => {
  it('renders the six users.table headers from the locale', () => {
    i18n.calls.length = 0
    render(
      <MemoryRouter>
        <UserTable users={USERS} currentUserId={1} onDelete={vi.fn()} isDeleting={false} />
      </MemoryRouter>
    )

    expect(screen.getAllByRole('columnheader').map((header) => header.textContent)).toEqual([
      'ID',
      'Username',
      'Email',
      'Roles',
      'Status',
      'Actions',
    ])
    for (const key of ['id', 'username', 'email', 'roles', 'status', 'actions']) {
      expect(i18n.calls).toContainEqual([`users.table.${key}`, undefined])
    }
  })
})
