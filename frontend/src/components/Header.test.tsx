import { act, render, screen, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { translateEn } from '../__tests__/translateEn'
import { createTestQueryClient, makeVersion, makeVersionState, versioningUnavailable } from '../__tests__/versioning'
import { refetchVersionState } from '../hooks/useSnapshotVersions'
import { networkAPI, snapshotAPI } from '../services/api'
import { useSnapshotStore } from '../store'
import type { SnapshotVersionState } from '../types'
import { Header } from './Header'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: translateEn }),
}))

vi.mock('./LanguageSwitcher', () => ({ LanguageSwitcher: () => null }))

const NAME = 'snap-a'

function renderHeader() {
  const queryClient = createTestQueryClient()
  const view = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/']}>
        <Header />
      </MemoryRouter>
    </QueryClientProvider>
  )
  return { queryClient, ...view }
}

const optionText = (name: string) =>
  (screen.getAllByRole('option') as HTMLOptionElement[]).find((option) => option.value === name)?.textContent

describe('Header snapshot version suffix', () => {
  beforeEach(() => {
    useSnapshotStore.setState({ currentSnapshotName: NAME, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    vi.spyOn(networkAPI, 'health').mockResolvedValue({ service: 'topologix', status: 'healthy', auth_enabled: false })
    vi.spyOn(snapshotAPI, 'list').mockResolvedValue([
      { name: NAME, file_count: 2, created_at: '2026-01-01T00:00:00Z', size_bytes: 10 },
      { name: 'snap-b', file_count: 1, created_at: '2026-01-01T00:00:00Z', size_bytes: 5 },
    ])
  })

  afterEach(() => vi.restoreAllMocks())

  it.each<[string, SnapshotVersionState, string]>([
    ['v<seq> and * when uncommitted', makeVersionState({ head: makeVersion({ seq: 3 }), uncommitted: true }), 'snap-a (2 files) v3*'],
    ['v<seq> alone on a clean tree', makeVersionState({ head: makeVersion({ seq: 3 }) }), 'snap-a (2 files) v3'],
    ['* alone with a null head and uncommitted: true', makeVersionState({ head: null, uncommitted: true }), 'snap-a (2 files) *'],
    ['no suffix while content_hash is null', makeVersionState({ content_hash: null, head: makeVersion({ seq: 3 }) }), 'snap-a (2 files)'],
  ])('appends %s for the current snapshot only', async (_label, state, expected) => {
    vi.spyOn(snapshotAPI, 'getVersionState').mockResolvedValue(state)
    renderHeader()

    await waitFor(() => expect(optionText(NAME)).toBe(expected))
    expect(optionText('snap-b')).toBe('snap-b (1 files)')
  })

  it('shows no suffix while version-state is pending or isError', async () => {
    const getVersionState = vi.spyOn(snapshotAPI, 'getVersionState').mockReturnValue(new Promise(() => {}))
    const pending = renderHeader()
    await waitFor(() => expect(optionText(NAME)).toBe('snap-a (2 files)'))
    pending.unmount()

    getVersionState.mockRejectedValue(versioningUnavailable('database'))
    renderHeader()
    await waitFor(() => expect(getVersionState).toHaveBeenCalledTimes(2))
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))
    expect(optionText(NAME)).toBe('snap-a (2 files)')
  })
})

describe('Header snapshot version suffix after a success', () => {
  beforeEach(() => {
    useSnapshotStore.setState({ currentSnapshotName: NAME, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    vi.spyOn(networkAPI, 'health').mockResolvedValue({ service: 'topologix', status: 'healthy', auth_enabled: false })
    vi.spyOn(snapshotAPI, 'list').mockResolvedValue([
      { name: NAME, file_count: 2, created_at: '2026-01-01T00:00:00Z', size_bytes: 10 },
    ])
  })

  afterEach(() => vi.restoreAllMocks())

  it('drops the suffix when version-state turns into isError while it still holds the earlier data', async () => {
    const getVersionState = vi
      .spyOn(snapshotAPI, 'getVersionState')
      .mockResolvedValue(makeVersionState({ head: makeVersion({ seq: 3 }), uncommitted: true }))
    const { queryClient } = renderHeader()
    await waitFor(() => expect(optionText(NAME)).toBe('snap-a (2 files) v3*'))

    getVersionState.mockRejectedValue(versioningUnavailable('database'))
    await act(async () => {
      await refetchVersionState(queryClient, NAME)
    })
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

    expect(queryClient.getQueryState(['snapshot-versions', NAME, 'state'])?.data).toBeDefined()
    expect(optionText(NAME)).toBe('snap-a (2 files)')
  })
})
