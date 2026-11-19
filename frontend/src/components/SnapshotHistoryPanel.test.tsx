import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'

import { translateEn } from '../__tests__/translateEn'
import { translateJa } from '../__tests__/translateJa'
import {
  createTestQueryClient,
  hashOf,
  httpError,
  makeVersion,
  makeVersionState,
  versioningUnavailable,
} from '../__tests__/versioning'
import { refetchVersionState, snapshotVersionKeys } from '../hooks/useSnapshotVersions'
import { snapshotAPI } from '../services/api'
import { useSnapshotStore } from '../store'
import type { SnapshotVersion, SnapshotVersionState, VersionDiffResponse } from '../types'
import { SnapshotHistoryPanel } from './SnapshotHistoryPanel'

const translation = vi.hoisted(() => ({ locale: 'en' as 'en' | 'ja' }))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, params?: Record<string, unknown>) =>
      translation.locale === 'ja' ? translateJa(key, params) : translateEn(key, params),
  }),
}))

vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
)
Element.prototype.getAnimations = () => []

const NAME = 'snap-a'
const WORKING_HASH = hashOf('w1')
const baseline = makeVersion({ version_id: 'version-1', seq: 1, kind: 'baseline', message: 'stored english text' })
const manual = makeVersion({
  version_id: 'version-2',
  seq: 2,
  kind: 'manual',
  message: 'before OSPF cleanup',
  author: 'alice',
  parent: { version_id: 'version-1', seq: 1 },
})

let versionStateMock: MockInstance<typeof snapshotAPI.getVersionState>
let listMock: MockInstance<typeof snapshotAPI.listVersions>

function setVersionState(state: SnapshotVersionState | Error) {
  versionStateMock.mockImplementation(() => (state instanceof Error ? Promise.reject(state) : Promise.resolve(state)))
}

function setVersions(items: SnapshotVersion[], total = items.length) {
  listMock.mockResolvedValue({ items, total })
}

function renderPanel(props: Partial<Parameters<typeof SnapshotHistoryPanel>[0]> = {}) {
  const queryClient = createTestQueryClient()
  const view = render(
    <QueryClientProvider client={queryClient}>
      <SnapshotHistoryPanel snapshotName={NAME} {...props} />
    </QueryClientProvider>
  )
  return { queryClient, ...view }
}

const settle = () => act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

async function clickEnabled(name: string) {
  const button = await screen.findByRole('button', { name })
  await waitFor(() => expect(button).toBeEnabled())
  fireEvent.click(button)
}

const workingSummary: VersionDiffResponse = {
  from: 'version-1',
  against: 'working',
  working_content_hash: WORKING_HASH,
  files: [
    { path: 'configs/new.cfg', status: 'added', size: null, against_size: 4 },
    { path: 'configs/r1.cfg', status: 'modified', size: 10, against_size: 12 },
    { path: 'configs/gone.cfg', status: 'removed', size: 3, against_size: null },
    { path: 'configs/same.cfg', status: 'unchanged', size: 5, against_size: 5 },
  ],
}

describe('SnapshotHistoryPanel', () => {
  beforeEach(() => {
    translation.locale = 'en'
    useSnapshotStore.setState({ currentSnapshotName: null, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    versionStateMock = vi.spyOn(snapshotAPI, 'getVersionState')
    listMock = vi.spyOn(snapshotAPI, 'listVersions')
    setVersions([manual, baseline])
  })

  afterEach(() => vi.restoreAllMocks())

  it.each([
    ['there are no uncommitted changes', makeVersionState({ uncommitted: false }), 'There are no uncommitted changes to commit.'],
    [
      'the content hash is not settled',
      makeVersionState({ content_hash: null, uncommitted: false }),
      'The working files are still being scanned; commit is unavailable until the scan finishes.',
    ],
  ])('disables Commit with an explanation when %s', async (_label, state, explanation) => {
    setVersionState(state)
    renderPanel()

    const commit = await screen.findByRole('button', { name: 'Commit' })
    await waitFor(() => expect(screen.getByText(explanation)).toBeInTheDocument())
    expect(commit).toBeDisabled()
    expect(commit).toHaveAccessibleDescription(explanation)
  })

  it('enables Commit after a delete-all (null head, uncommitted) and sends the message with the displayed head', async () => {
    setVersionState(makeVersionState({ head: null, uncommitted: true }))
    setVersions([])
    const commit = vi.spyOn(snapshotAPI, 'commitVersion').mockResolvedValue(manual)
    renderPanel()

    const button = await screen.findByRole('button', { name: 'Commit' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    const dialog = await screen.findByRole('dialog', { name: 'Commit the working files' })
    fireEvent.change(within(dialog).getByRole('textbox', { name: 'Commit message' }), { target: { value: '  first manual  ' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Commit' }))

    await waitFor(() => expect(commit).toHaveBeenCalledWith(NAME, { message: 'first manual', expected_head: null }))
  })

  it.each([
    ['en', 'Initial state', 'System'],
    ['ja', '初期状態', 'システム'],
  ] as const)('renders the kind-derived label for system versions in %s, never the stored text', async (locale, label, author) => {
    translation.locale = locale
    setVersionState(makeVersionState({ head: manual }))
    renderPanel()

    const row = (await screen.findByText(label)).closest('tr') as HTMLElement
    expect(within(row).getByText(author)).toBeInTheDocument()
    expect(screen.queryByText('stored english text')).not.toBeInTheDocument()
    const manualRow = screen.getByText('before OSPF cleanup').closest('tr') as HTMLElement
    expect(within(manualRow).getByText(locale === 'en' ? 'Parent v1' : 'v1 から作成')).toBeInTheDocument()
  })

  it('shows "(deleted)" for a lineage reference whose version was deleted', async () => {
    setVersionState(makeVersionState({ head: manual }))
    setVersions([{ ...manual, parent: { version_id: null, seq: 1 } }])
    renderPanel()

    expect(await screen.findByText('Parent v1 (deleted)')).toBeInTheDocument()
  })

  it('loads the next 50 versions by offset while fewer than total are shown', async () => {
    setVersionState(makeVersionState({ head: manual }))
    const firstPage = Array.from({ length: 50 }, (_, index) =>
      makeVersion({ version_id: `version-${60 - index}`, seq: 60 - index, kind: 'manual', message: `change ${60 - index}` })
    )
    listMock.mockResolvedValueOnce({ items: firstPage, total: 51 })
    listMock.mockResolvedValueOnce({ items: [makeVersion({ version_id: 'version-10', seq: 10, kind: 'manual', message: 'oldest' })], total: 51 })
    renderPanel()

    expect(await screen.findByText('Showing 50 of 51 versions')).toBeInTheDocument()
    expect(listMock).toHaveBeenCalledWith(NAME, { limit: 50, offset: 0 })
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))

    expect(await screen.findByText('oldest')).toBeInTheDocument()
    expect(listMock).toHaveBeenLastCalledWith(NAME, { limit: 50, offset: 50 })
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument()
  })

  it('restores with a fresh working summary, listing added files as deleted and modified/removed ones as overwritten', async () => {
    setVersionState(makeVersionState({ head: manual }))
    const getDiff = vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    const restore = vi
      .spyOn(snapshotAPI, 'restoreVersion')
      .mockResolvedValue({ requires_reinitialize: true, restored_from: { version_id: 'version-1', seq: 1 } })
    const activate = vi.spyOn(snapshotAPI, 'activate')
    renderPanel()

    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })
    await within(dialog).findByText('configs/new.cfg')

    expect(getDiff).toHaveBeenCalledWith(NAME, 'version-1', 'working')
    const deleteList = within(dialog).getByText('Files to delete (1)').parentElement as HTMLElement
    expect(within(deleteList).getByText('configs/new.cfg')).toBeInTheDocument()
    const overwriteList = within(dialog).getByText('Files to overwrite (2)').parentElement as HTMLElement
    expect(within(overwriteList).getByText('configs/r1.cfg')).toBeInTheDocument()
    expect(within(overwriteList).getByText('configs/gone.cfg')).toBeInTheDocument()
    expect(within(dialog).queryByText('configs/same.cfg')).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: 'Commit first' })).not.toBeInTheDocument()

    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))

    await waitFor(() => expect(restore).toHaveBeenCalledWith(NAME, 'version-1', { expected_working_hash: WORKING_HASH }))
    await settle()
    expect(activate).not.toHaveBeenCalled()
  })

  it('re-activates with if_stale after a restore of the current snapshot only', async () => {
    useSnapshotStore.setState({ currentSnapshotName: NAME })
    setVersionState(makeVersionState({ head: manual }))
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    vi.spyOn(snapshotAPI, 'restoreVersion').mockResolvedValue({
      requires_reinitialize: true,
      restored_from: { version_id: 'version-1', seq: 1 },
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
    const start = vi.fn(() => true)
    const end = vi.fn()
    renderPanel({ onFileChangeStart: start, onFileChangeEnd: end })

    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })
    await within(dialog).findByText('configs/new.cfg')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))

    await waitFor(() => expect(activate).toHaveBeenCalledWith(NAME, { if_stale: true }))
    await waitFor(() => expect(end).toHaveBeenCalledWith(NAME))
    expect(start).toHaveBeenCalledWith(NAME)
  })

  it('warns about permanent loss with a Commit first action on an uncommitted tree', async () => {
    setVersionState(makeVersionState({ head: manual, uncommitted: true, pending_external: true }))
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    renderPanel()

    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })

    expect(
      within(dialog).getByText(
        'The working files have uncommitted changes. They were never saved as a version and will be permanently lost.'
      )
    ).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Commit first' }))
    expect(await screen.findByRole('dialog', { name: 'Commit the working files' })).toBeInTheDocument()
  })

  it('re-lists the files on a 409 without a reason and shows a non-retryable error naming the path on path_clash', async () => {
    setVersionState(makeVersionState({ head: manual }))
    const getDiff = vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    const restore = vi.spyOn(snapshotAPI, 'restoreVersion')
    restore.mockRejectedValueOnce(httpError(409, { status: 'error', message: 'changed', code: 'version_conflict' }))
    restore.mockRejectedValueOnce(
      httpError(409, {
        status: 'error',
        message: 'clash',
        code: 'version_conflict',
        details: { reason: 'path_clash', path: 'configs/dir' },
      })
    )
    renderPanel()

    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })
    await within(dialog).findByText('configs/new.cfg')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))

    expect(
      await within(dialog).findByText('The working files changed. Review the updated list and confirm again.')
    ).toBeInTheDocument()
    await waitFor(() => expect(getDiff).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Restore' })).toBeEnabled())

    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))
    expect(await within(dialog).findByText(/"configs\/dir" conflicts/)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Restore' })).toBeDisabled()
    expect(getDiff).toHaveBeenCalledTimes(2)
  })

  it('deletes a single version with the displayed head and explains the head move only when deleting head while uncommitted', async () => {
    setVersionState(makeVersionState({ head: manual, uncommitted: true }))
    const remove = vi.spyOn(snapshotAPI, 'deleteVersion').mockResolvedValue({ deleted: 1, head: { version_id: 'version-1', seq: 1 } })
    renderPanel()

    await clickEnabled('Delete v1')
    let dialog = await screen.findByRole('dialog', { name: 'Delete v1' })
    expect(within(dialog).getByText(/This cannot be undone/)).toHaveTextContent('garbage-collected')
    expect(within(dialog).queryByText(/head moves to/)).not.toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Delete v2' }))
    dialog = await screen.findByRole('dialog', { name: 'Delete v2' })
    expect(within(dialog).getByText(/the head moves to v1 and the working files stay uncommitted/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(remove).toHaveBeenCalledWith(NAME, 'version-2', { expected_head: 'version-2' }))
  })

  it('deletes the oldest N with the displayed head and total and asks again after a 409', async () => {
    setVersionState(makeVersionState({ head: manual }))
    const remove = vi.spyOn(snapshotAPI, 'deleteVersions')
    remove.mockRejectedValueOnce(httpError(409, { status: 'error', message: 'conflict', code: 'version_conflict' }))
    remove.mockResolvedValueOnce({ deleted: 1, head: { version_id: 'version-2', seq: 2 } })
    renderPanel()

    const open = await screen.findByRole('button', { name: 'Delete history' })
    await waitFor(() => expect(open).toBeEnabled())
    fireEvent.click(open)
    const dialog = await screen.findByRole('dialog', { name: 'Delete history' })
    expect(within(dialog).getByText('1 of 2 versions will be deleted.')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))

    await waitFor(() =>
      expect(remove).toHaveBeenCalledWith(NAME, { mode: 'oldest', count: 1, expected_head: 'version-2', expected_total: 2 })
    )
    expect(
      await within(dialog).findByText(
        'The history changed or a file change is still in progress. Review the dialog and confirm again.'
      )
    ).toBeInTheDocument()
    expect(listMock.mock.calls.length).toBeGreaterThanOrEqual(2)

    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('reloads the list on a version_not_found 404 from a delete but not on a snapshot_not_found 404', async () => {
    setVersionState(makeVersionState({ head: manual }))
    const remove = vi.spyOn(snapshotAPI, 'deleteVersion')
    remove.mockRejectedValueOnce(httpError(404, { status: 'error', message: 'gone', code: 'snapshot_not_found' }))
    remove.mockRejectedValueOnce(httpError(404, { status: 'error', message: 'gone', code: 'version_not_found' }))
    renderPanel()
    const open = await screen.findByRole('button', { name: 'Delete v1' })
    await waitFor(() => expect(open).toBeEnabled())
    await settle()
    listMock.mockClear()

    fireEvent.click(open)
    let dialog = await screen.findByRole('dialog', { name: 'Delete v1' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await within(dialog).findByText('This snapshot is not available anymore.')
    await settle()
    expect(listMock).not.toHaveBeenCalled()

    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(listMock).toHaveBeenCalled())
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    dialog = screen.getByText('This version no longer exists. The history was reloaded.')
    expect(dialog).toBeInTheDocument()
  })

  it.each(['storage', 'sidecar', 'database', 'namespace'])(
    'shows the versioning unavailable notice for reason %s, disables the actions and recovers on the next successful poll',
    async (reason) => {
      setVersionState(versioningUnavailable(reason))
      const { queryClient } = renderPanel()

      expect(await screen.findByText(/^Versioning is unavailable \(/)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Commit' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Clear cached results' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Delete history' })).toBeDisabled()
      expect(screen.queryByRole('button', { name: 'Restore v1' })).not.toBeInTheDocument()

      setVersionState(makeVersionState({ head: manual, uncommitted: true }))
      await act(async () => {
        await refetchVersionState(queryClient, NAME)
      })

      await waitFor(() => expect(screen.queryByText(/^Versioning is unavailable \(/)).not.toBeInTheDocument())
      await waitFor(() => expect(screen.getByRole('button', { name: 'Commit' })).toBeEnabled())
      expect(await screen.findByRole('button', { name: 'Restore v1' })).toBeEnabled()
    }
  )

  it('offers only Delete history (all) on missing_objects and reloads into the guarded dialog on a 409', async () => {
    setVersionState(versioningUnavailable('missing_objects'))
    const remove = vi.spyOn(snapshotAPI, 'deleteVersions').mockImplementation(async () => {
      setVersionState(makeVersionState({ head: manual }))
      throw httpError(409, { status: 'error', message: 'conflict', code: 'version_conflict' })
    })
    renderPanel()

    expect(await screen.findByText(/History objects are missing/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Commit' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Clear cached results' })).toBeDisabled()
    const deleteAll = screen.getByRole('button', { name: 'Delete history (all)' })
    expect(deleteAll).toBeEnabled()

    fireEvent.click(deleteAll)
    const dialog = await screen.findByRole('dialog', { name: 'Delete history (all)' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(remove).toHaveBeenCalledWith(NAME, { mode: 'all', expected_unavailable: 'missing_objects' }))
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Delete history' })).toBeInTheDocument())
    const guarded = screen.getByRole('dialog', { name: 'Delete history' })
    expect(within(guarded).getByRole('radio', { name: 'All versions' })).toBeChecked()
    expect(within(guarded).getByText('2 of 2 versions will be deleted.')).toBeInTheDocument()
  })

  it('clears the cached results of the snapshot and reports the outcome', async () => {
    setVersionState(makeVersionState({ head: manual }))
    const clear = vi.spyOn(snapshotAPI, 'clearResultCache').mockResolvedValue({ cleared: true })
    renderPanel()

    const button = await screen.findByRole('button', { name: 'Clear cached results' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)

    await waitFor(() => expect(clear).toHaveBeenCalledWith(NAME))
    expect(
      await screen.findByText('Cached results were cleared. They are recomputed the next time they are needed.')
    ).toBeInTheDocument()
  })
})

describe('SnapshotHistoryPanel commit, restore, delete and cache-clear outcomes, dialog Escape handling and version labels', () => {
  const external = makeVersion({
    version_id: 'version-3',
    seq: 3,
    kind: 'external',
    message: 'stored external text',
    parent: { version_id: 'version-2', seq: 2 },
  })
  const activation = {
    status: 'success',
    network: 'net',
    snapshot: NAME,
    file_parse_status: [],
    init_issues: [],
    parse_warnings: [],
    initialization_result: {},
    parsed: false,
  }

  function deferred<T>() {
    let resolve!: (value: T) => void
    const promise = new Promise<T>((res) => {
      resolve = res
    })
    return { promise, resolve }
  }

  async function poll(queryClient: ReturnType<typeof createTestQueryClient>, state: SnapshotVersionState | Error) {
    setVersionState(state)
    await act(async () => {
      await refetchVersionState(queryClient, NAME)
    })
    await settle()
  }

  beforeEach(() => {
    translation.locale = 'en'
    useSnapshotStore.setState({ currentSnapshotName: null, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    versionStateMock = vi.spyOn(snapshotAPI, 'getVersionState')
    listMock = vi.spyOn(snapshotAPI, 'listVersions')
    setVersions([manual, baseline])
    vi.spyOn(snapshotAPI, 'getVersion').mockResolvedValue({ ...manual, files: [] })
  })

  afterEach(() => vi.restoreAllMocks())

  it('removes a deleted non-head version from the list and updates the counts', async () => {
    setVersionState(makeVersionState({ head: manual }))
    vi.spyOn(snapshotAPI, 'deleteVersion').mockImplementation(async () => {
      setVersions([manual])
      return { deleted: 1, head: { version_id: 'version-2', seq: 2 } }
    })
    renderPanel()
    expect(await screen.findByText('Showing 2 of 2 versions')).toBeInTheDocument()

    await clickEnabled('Delete v1')
    const dialog = await screen.findByRole('dialog', { name: 'Delete v1' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))

    expect(await screen.findByText('Deleted 1 version.')).toBeInTheDocument()
    expect(await screen.findByText('Showing 1 of 1 version')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Restore v1' })).not.toBeInTheDocument()
  })

  it('keeps the restore dialog open with Commit first disabled while the restore runs and finishes once', async () => {
    useSnapshotStore.setState({ currentSnapshotName: NAME })
    setVersionState(makeVersionState({ head: manual, uncommitted: true }))
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    const restoring = deferred<{ requires_reinitialize: boolean; restored_from: { version_id: string; seq: number } }>()
    vi.spyOn(snapshotAPI, 'restoreVersion').mockReturnValue(restoring.promise)
    const activate = vi.spyOn(snapshotAPI, 'activate').mockResolvedValue(activation)
    const start = vi.fn(() => true)
    const end = vi.fn()
    renderPanel({ onFileChangeStart: start, onFileChangeEnd: end })

    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })
    await within(dialog).findByText('configs/new.cfg')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Commit first' })).toBeDisabled())

    fireEvent.click(within(dialog).getByRole('button', { name: 'Commit first' }))
    fireEvent.keyDown(document.activeElement ?? document, { key: 'Escape' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await settle()
    expect(screen.getByRole('dialog', { name: 'Restore v1' })).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'Commit the working files' })).not.toBeInTheDocument()

    await act(async () => restoring.resolve({ requires_reinitialize: true, restored_from: { version_id: 'version-1', seq: 1 } }))
    await waitFor(() => expect(end).toHaveBeenCalledTimes(1))
    await settle()

    expect(start).toHaveBeenCalledTimes(1)
    expect(activate).toHaveBeenCalledTimes(1)
    expect(activate).toHaveBeenCalledWith(NAME, { if_stale: true })
    expect(screen.queryByRole('dialog', { name: 'Restore v1' })).not.toBeInTheDocument()
  })

  it('finishes a long restore once when a version-state poll fails meanwhile', async () => {
    useSnapshotStore.setState({ currentSnapshotName: NAME })
    setVersionState(makeVersionState({ head: manual }))
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    const restoring = deferred<{ requires_reinitialize: boolean; restored_from: { version_id: string; seq: number } }>()
    vi.spyOn(snapshotAPI, 'restoreVersion').mockReturnValue(restoring.promise)
    const activate = vi.spyOn(snapshotAPI, 'activate').mockResolvedValue(activation)
    const end = vi.fn()
    const { queryClient } = renderPanel({ onFileChangeStart: () => true, onFileChangeEnd: end })

    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })
    await within(dialog).findByText('configs/new.cfg')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))
    await poll(queryClient, versioningUnavailable('database'))

    expect(screen.getByRole('dialog', { name: 'Restore v1' })).toBeInTheDocument()
    setVersionState(makeVersionState({ head: manual, uncommitted: true }))
    await act(async () => restoring.resolve({ requires_reinitialize: true, restored_from: { version_id: 'version-1', seq: 1 } }))
    await waitFor(() => expect(end).toHaveBeenCalledTimes(1))
    await settle()

    expect(activate).toHaveBeenCalledTimes(1)
    expect(end).toHaveBeenCalledTimes(1)
  })

  it.each([
    [
      false,
      NAME,
      'Nothing was cleared: the result cache is turned off on the server. To re-parse the snapshot, go back to Topology and use "Reload current snapshot" in its header.',
    ],
    [
      false,
      'another-snapshot',
      'Nothing was cleared: the result cache is turned off on the server. The snapshot is parsed when it is next activated.',
    ],
    [false, null, 'Nothing was cleared: the result cache is turned off on the server. The snapshot is parsed when it is next activated.'],
    [true, NAME, 'Nothing was cleared yet: the files are still being scanned. The snapshot is re-parsed on its next use.'],
    [true, 'another-snapshot', 'Nothing was cleared yet: the files are still being scanned. The snapshot is re-parsed on its next use.'],
  ])('explains a {cleared: false} answer with result_cache_enabled %s and current snapshot %s', async (enabled, current, message) => {
    useSnapshotStore.setState({ currentSnapshotName: current })
    setVersionState(makeVersionState({ head: manual, result_cache_enabled: enabled }))
    vi.spyOn(snapshotAPI, 'clearResultCache').mockResolvedValue({ cleared: false })
    renderPanel()

    await clickEnabled('Clear cached results')

    expect(await screen.findByText(message)).toBeInTheDocument()
  })

  it('keeps the commit dialog open when Escape ends an IME composition and closes it on a plain Escape', async () => {
    setVersionState(makeVersionState({ head: manual, uncommitted: true }))
    renderPanel()

    await clickEnabled('Commit')
    const textarea = within(await screen.findByRole('dialog', { name: 'Commit the working files' })).getByRole('textbox', {
      name: 'Commit message',
    })
    fireEvent.change(textarea, { target: { value: 'にほんご' } })
    fireEvent.keyDown(textarea, { key: 'Escape', isComposing: true })
    fireEvent.keyDown(textarea, { key: 'Escape', keyCode: 229 })
    await settle()
    expect(screen.getByRole('dialog', { name: 'Commit the working files' })).toBeInTheDocument()
    expect(textarea).toHaveValue('にほんご')

    fireEvent.keyDown(textarea, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Commit the working files' })).not.toBeInTheDocument())
  })

  it('keeps the delete history dialog open when Escape ends an IME composition in the count field', async () => {
    setVersionState(makeVersionState({ head: manual }))
    renderPanel()

    await clickEnabled('Delete history')
    const dialog = await screen.findByRole('dialog', { name: 'Delete history' })
    const count = within(dialog).getByRole('spinbutton', { name: 'Number of versions (N)' })
    fireEvent.keyDown(count, { key: 'Escape', isComposing: true })
    fireEvent.keyDown(count, { key: 'Escape', keyCode: 229 })
    await settle()

    expect(screen.getByRole('dialog', { name: 'Delete history' })).toBeInTheDocument()
  })

  it.each([
    ['en', 'External change detected', 'External', 'System'],
    ['ja', '外部での変更を検出', '外部', 'システム'],
  ] as const)('renders the external kind label in the list under %s', async (locale, message, kind, author) => {
    translation.locale = locale
    setVersionState(makeVersionState({ head: external }))
    setVersions([external, manual, baseline])
    renderPanel()

    const row = (await screen.findByText(message)).closest('tr') as HTMLElement
    expect(within(row).getByText(kind)).toBeInTheDocument()
    expect(within(row).getByText(author)).toBeInTheDocument()
    expect(screen.queryByText('stored external text')).not.toBeInTheDocument()
  })

  it('deletes the newest N with expected_total and states irreversibility and garbage collection', async () => {
    setVersionState(makeVersionState({ head: manual, uncommitted: true }))
    const remove = vi.spyOn(snapshotAPI, 'deleteVersions').mockResolvedValue({ deleted: 1, head: { version_id: 'version-1', seq: 1 } })
    renderPanel()

    await clickEnabled('Delete history')
    const dialog = await screen.findByRole('dialog', { name: 'Delete history' })
    fireEvent.click(within(dialog).getByRole('radio', { name: 'Newest N versions' }))
    expect(within(dialog).getByText(/This cannot be undone/)).toHaveTextContent('garbage-collected')
    expect(within(dialog).getByText(/the head moves to v1 and the working files stay uncommitted/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))

    await waitFor(() =>
      expect(remove).toHaveBeenCalledWith(NAME, { mode: 'newest', count: 1, expected_head: 'version-2', expected_total: 2 })
    )
  })

  it('does not explain a head move when deleting head on a clean tree', async () => {
    setVersionState(makeVersionState({ head: manual, uncommitted: false }))
    renderPanel()

    await clickEnabled('Delete v2')
    const dialog = await screen.findByRole('dialog', { name: 'Delete v2' })

    expect(within(dialog).queryByText(/head moves|no head version remains|newest remaining/)).not.toBeInTheDocument()
  })

  it('reloads the list on a version_not_found answer from a restore', async () => {
    setVersionState(makeVersionState({ head: manual }))
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    vi.spyOn(snapshotAPI, 'restoreVersion').mockRejectedValue(
      httpError(404, { status: 'error', message: 'gone', code: 'version_not_found' })
    )
    renderPanel()
    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })
    await within(dialog).findByText('configs/new.cfg')
    listMock.mockClear()

    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))

    await waitFor(() => expect(listMock).toHaveBeenCalled())
    expect(await screen.findByText('This version no longer exists. The history was reloaded.')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'Restore v1' })).not.toBeInTheDocument()
  })

  it('reloads the list on a version_not_found answer from a diff', async () => {
    setVersionState(makeVersionState({ head: manual }))
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockRejectedValue(
      httpError(404, { status: 'error', message: 'gone', code: 'version_not_found' })
    )
    renderPanel()
    await screen.findByRole('button', { name: 'Show details and differences of v1' })
    await settle()
    listMock.mockClear()

    fireEvent.click(screen.getByRole('button', { name: 'Show details and differences of v1' }))

    await waitFor(() => expect(listMock).toHaveBeenCalled())
    expect(await screen.findAllByText('This version no longer exists. The history was reloaded.')).not.toHaveLength(0)
  })

  it('commits with the displayed head and handles version_unchanged and version_conflict', async () => {
    setVersionState(makeVersionState({ head: manual, uncommitted: true }))
    const commit = vi.spyOn(snapshotAPI, 'commitVersion')
    commit.mockRejectedValueOnce(httpError(409, { status: 'error', message: 'unchanged', code: 'version_unchanged' }))
    commit.mockImplementationOnce(async () => {
      setVersionState(makeVersionState({ head: external, uncommitted: true }))
      throw httpError(409, { status: 'error', message: 'conflict', code: 'version_conflict' })
    })
    commit.mockResolvedValueOnce(makeVersion({ version_id: 'version-4', seq: 4, kind: 'manual' }))
    renderPanel()

    await clickEnabled('Commit')
    const dialog = await screen.findByRole('dialog', { name: 'Commit the working files' })
    fireEvent.change(within(dialog).getByRole('textbox', { name: 'Commit message' }), { target: { value: 'ospf cleanup' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Commit' }))
    expect(await within(dialog).findByText('There are no changes since the head version.')).toBeInTheDocument()
    expect(commit).toHaveBeenLastCalledWith(NAME, { message: 'ospf cleanup', expected_head: 'version-2' })

    fireEvent.click(within(dialog).getByRole('button', { name: 'Commit' }))
    expect(
      await within(dialog).findByText('The history or the working files changed meanwhile. Review and try again.')
    ).toBeInTheDocument()

    fireEvent.click(within(dialog).getByRole('button', { name: 'Commit' }))
    await waitFor(() => expect(commit).toHaveBeenLastCalledWith(NAME, { message: 'ospf cleanup', expected_head: 'version-3' }))
    expect(await screen.findByText('Created v4.')).toBeInTheDocument()
  })

  it('fetches a fresh working summary when the restore dialog opens even with a cached one', async () => {
    setVersionState(makeVersionState({ head: manual }))
    const getDiff = vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Show details and differences of v1' }))
    await screen.findByText('configs/r1.cfg')
    expect(getDiff).toHaveBeenCalledTimes(1)

    await clickEnabled('Restore v1')
    await screen.findByRole('dialog', { name: 'Restore v1' })

    await waitFor(() => expect(getDiff).toHaveBeenCalledTimes(2))
    expect(getDiff).toHaveBeenLastCalledWith(NAME, 'version-1', 'working')
  })

  it('refetches a displayed working diff after an external edit and after a restore, and the list on a new head', async () => {
    setVersionState(makeVersionState({ head: manual, uncommitted: true }))
    const getDiff = vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    vi.spyOn(snapshotAPI, 'restoreVersion').mockImplementation(async () => {
      setVersionState(makeVersionState({ head: manual, content_hash: hashOf('h3'), uncommitted: true }))
      return { requires_reinitialize: true, restored_from: { version_id: 'version-1', seq: 1 } }
    })
    const { queryClient } = renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Show details and differences of v2' }))
    await screen.findByText('configs/r1.cfg')
    const v2Requests = () => getDiff.mock.calls.filter((call) => call[1] === 'version-2').length
    expect(v2Requests()).toBe(1)

    await poll(queryClient, makeVersionState({ head: manual, content_hash: hashOf('h2'), uncommitted: true, pending_external: true }))
    await waitFor(() => expect(v2Requests()).toBe(2))

    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })
    await within(dialog).findByText('configs/new.cfg')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(v2Requests()).toBe(3))

    const listRequests = listMock.mock.calls.length
    await poll(queryClient, makeVersionState({ head: external, content_hash: hashOf('h3'), uncommitted: true }))
    await waitFor(() => expect(listMock.mock.calls.length).toBe(listRequests + 1))
  })

  it.each([
    [makeVersionState({ head: manual, uncommitted: false }), 'Restored v1. The working files now equal the head version.'],
    [
      makeVersionState({ head: manual, content_hash: hashOf('h4'), uncommitted: true }),
      'Restored v1 into the working files. Commit to record it as a version.',
    ],
    [versioningUnavailable('database'), 'Restored v1 into the working files.'],
  ])('reports the restore outcome from the refetched version-state (%#)', async (refetchedState, message) => {
    setVersionState(makeVersionState({ head: manual, uncommitted: true }))
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    vi.spyOn(snapshotAPI, 'restoreVersion').mockImplementation(async () => {
      setVersionState(refetchedState)
      return { requires_reinitialize: true, restored_from: { version_id: 'version-1', seq: 1 } }
    })
    renderPanel()

    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })
    await within(dialog).findByText('configs/new.cfg')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))

    expect(await screen.findByText(message)).toBeInTheDocument()
    if (!(refetchedState instanceof Error) && !refetchedState.uncommitted) {
      expect(screen.queryByText(/Commit to record/)).not.toBeInTheDocument()
    }
  })

  it('falls back to the neutral restore notice when only a state fetched before the restore response is available', async () => {
    setVersionState(makeVersionState({ head: manual, uncommitted: true }))
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(workingSummary)
    let postResponseRefetchStarted = false
    let client!: ReturnType<typeof createTestQueryClient>
    vi.spyOn(snapshotAPI, 'restoreVersion').mockImplementation(async () => {
      await refetchVersionState(client, NAME)
      await new Promise((resolve) => setTimeout(resolve, 5))
      versionStateMock.mockImplementation(() => {
        postResponseRefetchStarted = true
        return new Promise(() => {})
      })
      return { requires_reinitialize: true, restored_from: { version_id: 'version-1', seq: 1 } }
    })
    const { queryClient } = renderPanel()
    client = queryClient

    await clickEnabled('Restore v1')
    const dialog = await screen.findByRole('dialog', { name: 'Restore v1' })
    await within(dialog).findByText('configs/new.cfg')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(postResponseRefetchStarted).toBe(true))
    await act(async () => {
      await queryClient.cancelQueries({ queryKey: snapshotVersionKeys.state(NAME) })
    })

    expect(await screen.findByText('Restored v1 into the working files.')).toBeInTheDocument()
    expect(queryClient.getQueryState<SnapshotVersionState>(snapshotVersionKeys.state(NAME))?.data?.uncommitted).toBe(true)
    expect(screen.queryByText(/Commit to record|equal the head version/)).not.toBeInTheDocument()
  })

  it('shows a panel-level retry text, not a dialog text, when a missing_objects delete-all answers 409 and version-state is unreadable', async () => {
    setVersionState(versioningUnavailable('missing_objects'))
    vi.spyOn(snapshotAPI, 'deleteVersions').mockImplementation(async () => {
      setVersionState(versioningUnavailable('database'))
      throw httpError(409, { status: 'error', message: 'conflict', code: 'version_conflict' })
    })
    renderPanel()

    await clickEnabled('Delete history (all)')
    const dialog = await screen.findByRole('dialog', { name: 'Delete history (all)' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))

    expect(
      await screen.findByText('The history changed or a file change is still in progress. Try again.')
    ).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.queryByText(/Review the dialog/)).not.toBeInTheDocument()
  })

  it.each([
    ['en', manual, 'Head v2 · Working files h1000000 · Uncommitted changes'],
    ['en', null, 'No versions yet · Working files h1000000 · Uncommitted changes'],
    ['ja', manual, 'ヘッド v2・作業ファイル h1000000・未コミットの変更あり'],
  ] as const)('shows the head and the working files hash as separate labels with uncommitted changes (%s)', async (locale, head, line) => {
    translation.locale = locale
    setVersionState(makeVersionState({ head, uncommitted: true }))
    renderPanel()

    expect(await screen.findByText(line)).toBeInTheDocument()
    expect(screen.queryByText(/v2 ?[(（]/)).not.toBeInTheDocument()
  })
})
