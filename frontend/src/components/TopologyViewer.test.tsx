import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { translateEn } from '../__tests__/translateEn'
import { translateJa } from '../__tests__/translateJa'
import { createTestQueryClient, hashKeyed, httpError, makeAllData, makeVersionState } from '../__tests__/versioning'
import ja from '../i18n/locales/ja.json'
import { networkAPI, snapshotAPI } from '../services/api'
import { useSnapshotStore } from '../store'
import { TopologyViewer } from './TopologyViewer'

const translation = vi.hoisted(() => ({ locale: 'en' as 'en' | 'ja' }))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, params?: Record<string, unknown>) =>
      translation.locale === 'ja' ? translateJa(key, params) : translateEn(key, params),
  }),
}))

const cytoscapeStub = vi.hoisted(() => ({
  cyRef: { current: null },
  isLoaded: false,
  initialize: vi.fn(async () => null),
  updateElements: vi.fn(),
  applyLayout: vi.fn(),
  fit: vi.fn(),
  zoomIn: vi.fn(),
  zoomOut: vi.fn(),
  destroy: vi.fn(),
  exportPNG: vi.fn(),
  saveNodePositions: vi.fn(),
  restoreNodePositions: vi.fn(),
  isLayoutRunning: vi.fn(() => false),
}))

vi.mock('../hooks/useCytoscapeLazy', () => ({
  useCytoscapeLazy: () => cytoscapeStub,
}))

const NAME = 'snap-a'

function renderViewer() {
  const queryClient = createTestQueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <TopologyViewer />
    </QueryClientProvider>
  )
}

describe('TopologyViewer loading and notices', () => {
  beforeEach(() => {
    useSnapshotStore.setState({ currentSnapshotName: NAME, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    translation.locale = 'en'
  })

  it('shows its spinner while version-state is pending and sends no all-data request', async () => {
    vi.spyOn(snapshotAPI, 'getVersionState').mockReturnValue(new Promise(() => {}))
    const allData = vi.spyOn(networkAPI, 'getAllData')
    renderViewer()
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

    expect(screen.getByText('Loading topology...')).toBeInTheDocument()
    expect(screen.queryByText('Activate a snapshot to view the topology.')).not.toBeInTheDocument()
    expect(allData).not.toHaveBeenCalled()
  })

  it('shows "No active snapshot" and never a spinner without a snapshot', async () => {
    useSnapshotStore.setState({ currentSnapshotName: null })
    const getVersionState = vi.spyOn(snapshotAPI, 'getVersionState')
    renderViewer()
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

    expect(screen.getByText('Activate a snapshot to view the topology.')).toBeInTheDocument()
    expect(screen.queryByText('Loading topology...')).not.toBeInTheDocument()
    expect(getVersionState).not.toHaveBeenCalled()
  })

  it('shows the snapshot mismatch notice with a forced reload action', async () => {
    vi.spyOn(snapshotAPI, 'getVersionState').mockResolvedValue(makeVersionState())
    vi.spyOn(networkAPI, 'getAllData').mockResolvedValue(
      hashKeyed(makeAllData('other'), { snapshotId: 'another-snapshot', contentHash: 'x', cacheStatus: 'hit' })
    )
    const activate = vi.spyOn(snapshotAPI, 'activate').mockReturnValue(new Promise(() => {}))
    renderViewer()

    expect(
      await screen.findByText('The server is serving another snapshot. Reload this snapshot to show its data.')
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Reload snapshot' }))

    await waitFor(() => expect(activate).toHaveBeenCalledWith(NAME))
  })

  it('shows the localized content mismatch text instead of the connection text for a ContentHashMismatchError under ja', async () => {
    translation.locale = 'ja'
    vi.spyOn(snapshotAPI, 'getVersionState').mockResolvedValue(makeVersionState())
    vi.spyOn(networkAPI, 'getAllData').mockResolvedValue(
      hashKeyed(makeAllData('other'), { snapshotId: 'snapshot-id-1', contentHash: 'f'.repeat(64), cacheStatus: 'hit' })
    )
    renderViewer()

    expect(await screen.findByText(ja.overview.version.contentMismatch)).toBeInTheDocument()
    expect(screen.getByText(ja.topologyViewer.errors.loadFailed)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: ja.topologyViewer.retry })).toBeInTheDocument()
    expect(screen.queryByText(ja.topologyViewer.errors.connectionIssue)).not.toBeInTheDocument()
  })

  it('shows the connection text for any other error under ja', async () => {
    translation.locale = 'ja'
    vi.spyOn(snapshotAPI, 'getVersionState').mockResolvedValue(makeVersionState())
    vi.spyOn(networkAPI, 'getAllData').mockRejectedValue(httpError(500, { status: 'error', message: 'failed' }))
    renderViewer()

    expect(await screen.findByText(ja.topologyViewer.errors.connectionIssue)).toBeInTheDocument()
    expect(screen.queryByText(ja.overview.version.contentMismatch)).not.toBeInTheDocument()
  })
})
