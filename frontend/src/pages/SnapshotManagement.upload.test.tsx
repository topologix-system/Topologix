import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { createTestQueryClient, hashKeyed, makeAllData, makeVersionState, versioningUnavailable } from '../__tests__/versioning'
import { useAllNetworkData } from '../hooks/useNetwork'
import { networkAPI, snapshotAPI, validationAPI } from '../services/api'
import { useSnapshotStore } from '../store'
import { SnapshotManagement } from './SnapshotManagement'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

vi.mock('../components/ConfigFileEditor', () => ({
  ConfigFileEditor: ({
    draft,
    onDraftChange,
    onSave,
  }: {
    draft: string
    onDraftChange: (content: string) => void
    onSave: () => void
  }) => (
    <>
      <textarea aria-label="editor" value={draft} onChange={(event) => onDraftChange(event.target.value)} />
      <button type="button" onClick={onSave}>
        save editor
      </button>
    </>
  ),
}))
vi.mock('../components/AdvancedArtifactPanel', () => ({ AdvancedArtifactPanel: () => null }))
vi.mock('../components/SnapshotFolderCombobox', () => ({ SnapshotFolderCombobox: () => null }))
vi.mock('../components/validation/ParseResultDetails', () => ({ ParseResultSummaryCard: () => null }))
vi.mock('../components/SnapshotHistoryPanel', () => ({ SnapshotHistoryPanel: () => null }))

const NAME = 'snap-a'

function TopologyObserver() {
  const { data } = useAllNetworkData()
  return <p>{data ? `topology:${data.node_properties[0].node}` : 'topology:none'}</p>
}

function renderPage() {
  const queryClient = createTestQueryClient()
  const router = createMemoryRouter(
    [
      {
        path: '/snapshots',
        element: (
          <>
            <SnapshotManagement />
            <TopologyObserver />
          </>
        ),
      },
    ],
    { initialEntries: ['/snapshots'] }
  )
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return queryClient
}

describe('SnapshotManagement upload batch', () => {
  beforeEach(() => {
    useSnapshotStore.setState({ currentSnapshotName: NAME, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    vi.spyOn(snapshotAPI, 'list').mockResolvedValue([{ name: NAME, file_count: 0, created_at: '2026-01-01T00:00:00Z', size_bytes: 0 }])
    vi.spyOn(snapshotAPI, 'getFiles').mockResolvedValue([])
    vi.spyOn(validationAPI, 'getFileParseStatus').mockResolvedValue([])
    vi.spyOn(validationAPI, 'getInitIssues').mockResolvedValue([])
    vi.spyOn(validationAPI, 'getParseWarnings').mockResolvedValue([])
    vi.spyOn(snapshotAPI, 'getVersionState').mockRejectedValue(versioningUnavailable('database'))
  })

  afterEach(() => vi.restoreAllMocks())

  it('uploads three files with the real mutation, activates once with if_stale and sends one all-data request after it', async () => {
    const allData = vi
      .spyOn(networkAPI, 'getAllData')
      .mockResolvedValueOnce(hashKeyed(makeAllData('before'), { snapshotId: 'snapshot-id-1', contentHash: '', cacheStatus: 'bypass' }))
      .mockResolvedValue(hashKeyed(makeAllData('after'), { snapshotId: 'snapshot-id-1', contentHash: '', cacheStatus: 'bypass' }))
    const upload = vi.spyOn(snapshotAPI, 'uploadFile').mockImplementation(async (_name, file) => ({
      name: file.name,
      size_bytes: 1,
      modified_at: '2026-01-01T00:00:00Z',
      requires_reinitialize: true,
    }))
    const activate = vi.spyOn(snapshotAPI, 'activate').mockResolvedValue({
      status: 'success',
      network: 'net',
      snapshot: NAME,
      file_parse_status: [],
      init_issues: [],
      parse_warnings: [],
      initialization_result: {},
      parsed: true,
    })
    renderPage()

    expect(await screen.findByText('topology:before')).toBeInTheDocument()
    expect(allData).toHaveBeenCalledTimes(1)
    fireEvent.click(await screen.findByRole('button', { name: /Snapshot snap-a / }))

    const files = ['r1.cfg', 'r2.cfg', 'r3.cfg'].map((name) => new File(['hostname x\n'], name, { type: 'text/plain' }))
    fireEvent.change(screen.getByLabelText('snapshots.chooseFilesAria'), { target: { files } })

    await waitFor(() => expect(activate).toHaveBeenCalledTimes(1))
    expect(upload).toHaveBeenCalledTimes(3)
    expect(activate).toHaveBeenCalledWith(NAME, { if_stale: true })
    expect(await screen.findByText('topology:after')).toBeInTheDocument()
    expect(allData).toHaveBeenCalledTimes(2)
    expect(allData.mock.invocationCallOrder[1]).toBeGreaterThan(activate.mock.invocationCallOrder[0])
    await waitFor(() => expect(screen.getByLabelText('snapshots.chooseFilesAria')).toBeEnabled())
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 50)))
    expect(activate).toHaveBeenCalledTimes(1)
    expect(allData).toHaveBeenCalledTimes(2)
  })
})

describe('SnapshotManagement editor save', () => {
  beforeEach(() => {
    useSnapshotStore.setState({ currentSnapshotName: NAME, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    vi.spyOn(snapshotAPI, 'list').mockResolvedValue([{ name: NAME, file_count: 1, created_at: '2026-01-01T00:00:00Z', size_bytes: 12 }])
    vi.spyOn(snapshotAPI, 'getFiles').mockResolvedValue([{ name: 'r1.cfg', size_bytes: 12, modified_at: '2026-01-01T00:00:00Z' }])
    vi.spyOn(validationAPI, 'getFileParseStatus').mockResolvedValue([])
    vi.spyOn(validationAPI, 'getInitIssues').mockResolvedValue([])
    vi.spyOn(validationAPI, 'getParseWarnings').mockResolvedValue([])
    vi.spyOn(snapshotAPI, 'getVersionState').mockResolvedValue(makeVersionState())
    vi.spyOn(networkAPI, 'getAllData').mockResolvedValue(
      hashKeyed(makeAllData('n1'), { snapshotId: 'snapshot-id-1', contentHash: '', cacheStatus: 'bypass' })
    )
    vi.spyOn(snapshotAPI, 'getConfigFileContent').mockResolvedValue({
      content: 'hostname r1\n',
      sha256: 'a'.repeat(64),
      size_bytes: 12,
    })
  })

  afterEach(() => vi.restoreAllMocks())

  it('re-activates the current snapshot once with if_stale after an editor save', async () => {
    const save = vi.spyOn(snapshotAPI, 'updateConfigFileContent').mockResolvedValue({
      name: 'r1.cfg',
      size_bytes: 14,
      modified_at: '2026-01-02T00:00:00Z',
      requires_reinitialize: true,
    })
    const activate = vi.spyOn(snapshotAPI, 'activate').mockResolvedValue({
      status: 'success',
      network: 'net',
      snapshot: NAME,
      file_parse_status: [],
      init_issues: [],
      parse_warnings: [],
      initialization_result: {},
      parsed: false,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /Snapshot snap-a / }))
    fireEvent.click(await screen.findByRole('button', { name: 'snapshots.configEditor.viewEditAria' }))
    fireEvent.change(await screen.findByRole('textbox', { name: 'editor' }), { target: { value: 'hostname r1b\n' } })
    fireEvent.click(screen.getByRole('button', { name: 'save editor' }))

    await waitFor(() => expect(activate).toHaveBeenCalledTimes(1))
    expect(save).toHaveBeenCalledWith({ name: NAME, filename: 'r1.cfg', content: 'hostname r1b\n', expectedSha256: 'a'.repeat(64) })
    expect(activate).toHaveBeenCalledWith(NAME, { if_stale: true })
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 50)))
    expect(activate).toHaveBeenCalledTimes(1)
  })
})
