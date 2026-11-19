import { beforeEach, describe, expect, it, vi } from 'vitest'

import { INVALIDATION_SIGNAL_KEY, getSnapshotTriggerState } from '../hooks/snapshotTriggerState'
import { queryClient } from '../queryClient'
import { useAuthStore } from './useAuthStore'
import { useSnapshotStore } from './useSnapshotStore'

const authMocks = vi.hoisted(() => ({ login: vi.fn(), logout: vi.fn() }))

vi.mock('../services/api', () => ({
  authAPI: {
    getCurrentUser: () => null,
    isAuthenticated: () => false,
    login: authMocks.login,
    logout: authMocks.logout,
  },
}))

function seedPreviousUserState() {
  queryClient.setQueryData(['network', 'snap-a', 'a'.repeat(64), 'all-data'], { data: {}, legacy: false })
  queryClient.setQueryData(['snapshot-versions', 'snap-a', 'state'], { content_hash: 'a'.repeat(64) })
  getSnapshotTriggerState(queryClient, 'snap-a').workingHash = 'a'.repeat(64)
  getSnapshotTriggerState(queryClient, 'snap-a').noData = true
  useSnapshotStore.setState({ currentSnapshotName: 'snap-a', isSnapshotActivationInProgress: true, activatingSnapshotName: 'snap-a' })
  localStorage.setItem(INVALIDATION_SIGNAL_KEY, JSON.stringify({ name: 'snap-a', ts: 1, reason: 'edit' }))
}

function expectClientStateCleared() {
  expect(queryClient.getQueryCache().getAll()).toHaveLength(0)
  expect(getSnapshotTriggerState(queryClient, 'snap-a').workingHash).toBeUndefined()
  expect(getSnapshotTriggerState(queryClient, 'snap-a').noData).toBe(false)
  expect(useSnapshotStore.getState()).toMatchObject({
    currentSnapshotName: null,
    isSnapshotActivationInProgress: false,
    activatingSnapshotName: null,
  })
  expect(localStorage.getItem(INVALIDATION_SIGNAL_KEY)).toBeNull()
  expect(localStorage.getItem('topologix-snapshot-storage')).toBeNull()
}

describe('useAuthStore session boundaries', () => {
  beforeEach(() => {
    authMocks.login.mockReset()
    authMocks.logout.mockReset()
    localStorage.clear()
  })

  it('clears the query cache, the trigger state, the snapshot store and the invalidation signal on logout', async () => {
    seedPreviousUserState()
    authMocks.logout.mockResolvedValue(undefined)

    await useAuthStore.getState().logout()

    expectClientStateCleared()
  })

  it('clears the same client state on login', async () => {
    seedPreviousUserState()
    authMocks.login.mockResolvedValue({ user: { username: 'bob', roles: [], email: 'bob@example.test' } })

    await useAuthStore.getState().login('bob', 'secret')

    expectClientStateCleared()
  })
})
