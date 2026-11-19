import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'

import { translateEn } from '../../__tests__/translateEn'
import { translateJa } from '../../__tests__/translateJa'
import {
  createTestQueryClient,
  hashKeyed,
  hashOf,
  httpError,
  makeVersion,
  makeVersionState,
  versioningUnavailable,
} from '../../__tests__/versioning'
import { refetchVersionState } from '../../hooks/useSnapshotVersions'
import { authAPI, networkAPI, snapshotAPI, validationAPI } from '../../services/api'
import { queryClient as appQueryClient } from '../../queryClient'
import { useAuthStore, useSnapshotStore } from '../../store'
import type { AllNetworkData, HashKeyedResponse, SnapshotVersionInfo, SnapshotVersionState } from '../../types'
import { OverviewPanel } from './OverviewPanel'

const translation = vi.hoisted(() => ({ locale: 'en' as 'en' | 'ja' }))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, params?: Record<string, unknown>) =>
      translation.locale === 'ja' ? translateJa(key, params) : translateEn(key, params),
  }),
}))

vi.mock('../validation/ParseResultDetails', () => ({
  ParseResultSummaryCard: () => null,
}))

const NAME = 'snap-a'
const H1 = hashOf('h1')
const H2 = hashOf('h2')

function allData(snapshotVersion: SnapshotVersionInfo | undefined): AllNetworkData {
  const empty: Record<string, unknown[]> = {}
  for (const key of [
    'node_properties', 'interface_properties', 'routes', 'ospf_process_configuration', 'ospf_area_configuration',
    'ospf_interface_configuration', 'ospf_session_compatibility', 'ospf_edges', 'bgp_edges', 'bgp_peer_configuration',
    'bgp_process_configuration', 'bgp_session_status', 'bgp_session_compatibility', 'bgp_rib', 'edges', 'layer1_edges',
    'layer3_edges', 'vxlan_edges', 'eigrp_edges', 'isis_edges', 'ipsec_edges', 'switched_vlan_properties', 'ip_owners',
    'defined_structures', 'referenced_structures', 'named_structures', 'file_parse_status', 'init_issues',
    'parse_warnings', 'vi_conversion_status', 'reachability', 'search_route_policies', 'aaa_authentication_login',
    'filter_line_reachability',
  ]) {
    empty[key] = []
  }
  return { ...empty, ...(snapshotVersion ? { snapshot_version: snapshotVersion } : {}) } as unknown as AllNetworkData
}

const loadedAt = (hash: string | null, live = false, liveHash: string | null = null): SnapshotVersionInfo => ({
  content_hash: hash,
  live,
  live_hash: liveHash,
})

let versionStateMock: MockInstance<typeof snapshotAPI.getVersionState>
let allDataMock: MockInstance<typeof networkAPI.getAllData>

function setVersionState(state: SnapshotVersionState | Error) {
  versionStateMock.mockImplementation(() => (state instanceof Error ? Promise.reject(state) : Promise.resolve(state)))
}

function serve(data: AllNetworkData, hash: string): HashKeyedResponse<AllNetworkData> {
  return hashKeyed(data, { snapshotId: 'snapshot-id-1', contentHash: hash, cacheStatus: 'hit' })
}

function renderOverview(queryClient = createTestQueryClient()) {
  const view = render(
    <QueryClientProvider client={queryClient}>
      <OverviewPanel />
    </QueryClientProvider>
  )
  return { queryClient, ...view }
}

async function poll(queryClient: ReturnType<typeof createTestQueryClient>, state: SnapshotVersionState | Error) {
  setVersionState(state)
  await act(async () => {
    await refetchVersionState(queryClient, NAME)
  })
  await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))
}

const staleWarning = 'The rendered topology is older than the current files.'
const stagingNotice = 'Staging unavailable: results are not cached'

describe('OverviewPanel version state', () => {
  beforeEach(() => {
    useSnapshotStore.setState({ currentSnapshotName: NAME, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    versionStateMock = vi.spyOn(snapshotAPI, 'getVersionState')
    allDataMock = vi.spyOn(networkAPI, 'getAllData')
    vi.spyOn(validationAPI, 'getUnusedStructures').mockResolvedValue([])
    vi.spyOn(validationAPI, 'getUndefinedReferences').mockResolvedValue([])
    vi.spyOn(validationAPI, 'getForwardingLoops').mockResolvedValue([])
  })

  afterEach(() => {
    vi.restoreAllMocks()
    translation.locale = 'en'
  })

  it('renders the version line with v<seq>, short hash, message, kind badge, lineage and working states', async () => {
    setVersionState(
      makeVersionState({
        head: makeVersion({
          version_id: 'version-3',
          seq: 3,
          kind: 'restore',
          message: 'before OSPF cleanup',
          author: 'alice',
          parent: { version_id: null, seq: 2 },
          restored_from: { version_id: 'version-1', seq: 1 },
        }),
        uncommitted: true,
        pending_external: true,
        external_settling: true,
        restored_from: { version_id: 'version-1', seq: 1 },
      })
    )
    allDataMock.mockResolvedValue(serve(allData(loadedAt(H1)), H1))
    renderOverview()

    expect(await screen.findByText('v3')).toBeInTheDocument()
    expect(screen.getByText(`(${H1.slice(0, 8)})`)).toBeInTheDocument()
    expect(screen.getByText('before OSPF cleanup')).toBeInTheDocument()
    expect(screen.getByText('Restore')).toBeInTheDocument()
    expect(screen.getByText('Based on v2 (deleted) · Restored from v1')).toBeInTheDocument()
    expect(screen.getByText('Uncommitted changes')).toBeInTheDocument()
    expect(screen.getByText('External change pending: commit to record (Manage snapshots → History)')).toBeInTheDocument()
    expect(screen.getByText('External change settling')).toBeInTheDocument()
    expect(screen.getByText('Working files restored from v1')).toBeInTheDocument()
  })

  it('shows the localized baseline label, the System author, no "(deleted)" for a null parent and "no versions yet" for a null head', async () => {
    setVersionState(makeVersionState({ head: makeVersion({ message: 'stored english text' }) }))
    allDataMock.mockResolvedValue(serve(allData(loadedAt(H1)), H1))
    const { queryClient } = renderOverview()

    expect(await screen.findByText('Initial state')).toBeInTheDocument()
    expect(screen.getByText('Baseline')).toBeInTheDocument()
    expect(screen.getByText(/System/)).toBeInTheDocument()
    expect(screen.queryByText('stored english text')).not.toBeInTheDocument()
    expect(screen.queryByText(/\(deleted\)/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Based on/)).not.toBeInTheDocument()

    await poll(queryClient, makeVersionState({ head: null, uncommitted: true }))
    expect(await screen.findByText('No versions yet')).toBeInTheDocument()
  })

  it('shows "updating" while all-data is fetching after a hash change', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValueOnce(serve(allData(loadedAt(H1)), H1))
    const { queryClient } = renderOverview()
    await screen.findByText('OSPF Summary')
    await waitFor(() => expect(screen.queryByText('Updating…')).not.toBeInTheDocument())

    allDataMock.mockReturnValueOnce(new Promise(() => {}))
    await poll(queryClient, makeVersionState({ content_hash: H2, uncommitted: true }))

    expect(await screen.findByText('Updating…')).toBeInTheDocument()
    expect(screen.queryByText(staleWarning)).not.toBeInTheDocument()
  })

  it('shows the staging notice from version-state alone and clears it on the next poll without an all-data refetch', async () => {
    setVersionState(makeVersionState({ loaded_live: true }))
    allDataMock.mockResolvedValue(serve(allData(loadedAt(null, true, H1)), H1))
    const { queryClient } = renderOverview()

    expect(await screen.findByText(stagingNotice)).toBeInTheDocument()
    expect(screen.queryByText(staleWarning)).not.toBeInTheDocument()

    await poll(queryClient, makeVersionState({ loaded_live: false }))
    await waitFor(() => expect(screen.queryByText(stagingNotice)).not.toBeInTheDocument())
    expect(allDataMock).toHaveBeenCalledTimes(1)
  })

  it('warns about a stale topology when the settled hash differs, also for a live parse, with a forced reload action', async () => {
    setVersionState(makeVersionState({ content_hash: H2, loaded_live: true }))
    allDataMock.mockResolvedValue(serve(allData(loadedAt(null, true, H1)), H2))
    const activate = vi.spyOn(snapshotAPI, 'activate').mockReturnValue(new Promise(() => {}))
    renderOverview()

    expect(await screen.findByText(staleWarning)).toBeInTheDocument()
    expect(screen.getByText(stagingNotice)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Reload snapshot' }))
    await waitFor(() => expect(activate).toHaveBeenCalledWith(NAME))
  })

  it.each([
    ['a null loaded hash', allData(loadedAt(null))],
    ['an older backend without snapshot_version', allData(undefined)],
  ])('warns for %s while version-state is isSuccess', async (_label, data) => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(serve(data, H1))
    renderOverview()

    expect(await screen.findByText(staleWarning)).toBeInTheDocument()
  })

  it('does not warn when the settled hash equals the working hash', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(serve(allData(loadedAt(H1)), H1))
    renderOverview()

    await screen.findByText('v1')
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))
    expect(screen.queryByText(staleWarning)).not.toBeInTheDocument()
  })

  it('shows only the unavailable notice and a "last known" line when version-state answers 503 after 200', async () => {
    setVersionState(makeVersionState({ content_hash: H2, loaded_live: true }))
    allDataMock.mockResolvedValue(serve(allData(loadedAt(H1)), H2))
    const { queryClient } = renderOverview()
    await screen.findByText(staleWarning)

    await poll(queryClient, versioningUnavailable('database'))

    expect(await screen.findByText(/^Version state unavailable/)).toBeInTheDocument()
    expect(screen.getByText('Last known')).toBeInTheDocument()
    expect(screen.getByText('v1')).toBeInTheDocument()
    expect(screen.queryByText(staleWarning)).not.toBeInTheDocument()
    expect(screen.queryByText(stagingNotice)).not.toBeInTheDocument()
    expect(allDataMock).toHaveBeenCalledTimes(1)
  })

  it('shows the unavailable notice without a version line or topology after a 403', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(serve(allData(loadedAt(H1)), H1))
    const { queryClient } = renderOverview()
    await screen.findByText('v1')

    await poll(queryClient, httpError(403, { status: 'error', message: 'Access denied' }))

    expect(await screen.findByText(/^Version state unavailable/)).toBeInTheDocument()
    expect(screen.queryByText('v1')).not.toBeInTheDocument()
    expect(screen.queryByText('Last known')).not.toBeInTheDocument()
    expect(screen.getByText('No data available')).toBeInTheDocument()
  })
})

describe('OverviewPanel kind labels, loading and unavailable states, mismatch notices and session reset', () => {
  beforeEach(() => {
    localStorage.clear()
    useSnapshotStore.setState({ currentSnapshotName: NAME, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    versionStateMock = vi.spyOn(snapshotAPI, 'getVersionState')
    allDataMock = vi.spyOn(networkAPI, 'getAllData')
    vi.spyOn(validationAPI, 'getUnusedStructures').mockResolvedValue([])
    vi.spyOn(validationAPI, 'getUndefinedReferences').mockResolvedValue([])
    vi.spyOn(validationAPI, 'getForwardingLoops').mockResolvedValue([])
  })

  afterEach(() => {
    vi.restoreAllMocks()
    translation.locale = 'en'
    appQueryClient.clear()
  })

  it.each([
    ['en', 'External change detected', 'External', /System/],
    ['ja', '外部での変更を検出', '外部', /システム/],
  ] as const)('renders the external kind label under %s, never the stored text', async (locale, message, kind, author) => {
    translation.locale = locale
    setVersionState(makeVersionState({ head: makeVersion({ kind: 'external', message: 'stored external text', seq: 2 }) }))
    allDataMock.mockResolvedValue(serve(allData(loadedAt(H1)), H1))
    renderOverview()

    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(screen.getByText(kind)).toBeInTheDocument()
    expect(screen.getByText(author)).toBeInTheDocument()
    expect(screen.queryByText('stored external text')).not.toBeInTheDocument()
  })

  it("shows only the unavailable notice for a 503 on first load with a non-null all-data hash (the 'unknown' key)", async () => {
    setVersionState(versioningUnavailable('storage'))
    allDataMock.mockResolvedValue(hashKeyed(allData(loadedAt(H1)), { snapshotId: 'snapshot-id-1', contentHash: '', cacheStatus: 'bypass' }))
    renderOverview()

    expect(await screen.findByText('Version state unavailable (history storage problem)')).toBeInTheDocument()
    await screen.findByText('OSPF Summary')
    expect(screen.queryByText('Last known')).not.toBeInTheDocument()
    expect(screen.queryByText(staleWarning)).not.toBeInTheDocument()
    expect(screen.queryByText(stagingNotice)).not.toBeInTheDocument()
    expect(allDataMock).toHaveBeenCalledTimes(1)
    expect(versionStateMock).toHaveBeenCalledTimes(1)
  })

  it('shows the loading state while version-state is pending and sends no all-data request', async () => {
    versionStateMock.mockReturnValue(new Promise(() => {}))
    renderOverview()
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

    expect(screen.getByText('Loading...')).toBeInTheDocument()
    expect(screen.queryByText('No data available')).not.toBeInTheDocument()
    expect(allDataMock).not.toHaveBeenCalled()
  })

  it('shows the snapshot mismatch notice with a forced reload action', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(
      hashKeyed(allData(loadedAt(H1)), { snapshotId: 'another-snapshot', contentHash: H1, cacheStatus: 'hit' })
    )
    const activate = vi.spyOn(snapshotAPI, 'activate').mockReturnValue(new Promise(() => {}))
    renderOverview()

    expect(
      await screen.findByText('The server is serving another snapshot. Reload this snapshot to show its data.')
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Reload snapshot' }))

    await waitFor(() => expect(activate).toHaveBeenCalledWith(NAME))
  })

  it('shows the content mismatch notice with a forced reload action under ja when all-data keeps answering another hash', async () => {
    translation.locale = 'ja'
    setVersionState(makeVersionState({ content_hash: H1 }))
    allDataMock.mockResolvedValue(serve(allData(loadedAt(H2)), H2))
    const activate = vi.spyOn(snapshotAPI, 'activate').mockReturnValue(new Promise(() => {}))
    renderOverview()

    expect(
      await screen.findByText(
        'データの読み込み中にスナップショットの内容が変わりました。このスナップショットを再読み込みすると現在のデータが表示されます。'
      )
    ).toBeInTheDocument()
    expect(screen.getByText('利用可能なデータがありません')).toBeInTheDocument()
    expect(allDataMock).toHaveBeenCalledTimes(2)
    expect(screen.queryByText(/content changed|No data available/)).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'スナップショットを再読み込み' }))

    await waitFor(() => expect(activate).toHaveBeenCalledWith(NAME))
  })

  it('renders nothing of the previous user after logout and login in the same tab', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(serve(allData(loadedAt(H1)), H1))
    renderOverview(appQueryClient)
    expect(await screen.findByText('v1')).toBeInTheDocument()

    await act(() => useAuthStore.getState().logout())

    expect(await screen.findByText('Activate a snapshot to view network overview data.')).toBeInTheDocument()
    expect(screen.queryByText('v1')).not.toBeInTheDocument()
    expect(screen.queryByText(NAME)).not.toBeInTheDocument()
    expect(appQueryClient.getQueryCache().getAll().filter((query) => query.state.data !== undefined)).toHaveLength(0)

    vi.spyOn(authAPI, 'login').mockResolvedValue({
      token_type: 'cookie',
      expires_in: 3600,
      user: { username: 'bob', roles: [], email: 'bob@example.test' },
      csrf_token: 'csrf',
    })
    await act(() => useAuthStore.getState().login('bob', 'secret'))
    expect(screen.getByText('Activate a snapshot to view network overview data.')).toBeInTheDocument()

    const invalidate = vi.spyOn(appQueryClient, 'invalidateQueries')
    setVersionState(makeVersionState({ content_hash: H2, loaded_content_hash: H2 }))
    allDataMock.mockResolvedValue(serve(allData(loadedAt(H2)), H2))
    act(() => useSnapshotStore.setState({ currentSnapshotName: NAME }))
    expect(await screen.findByText('OSPF Summary')).toBeInTheDocument()
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

    expect(
      invalidate.mock.calls.filter((call) => {
        const key = (call[0] as { queryKey?: unknown[] } | undefined)?.queryKey
        return Array.isArray(key) && key.length === 2 && key[1] === NAME
      })
    ).toHaveLength(0)
  })
})
