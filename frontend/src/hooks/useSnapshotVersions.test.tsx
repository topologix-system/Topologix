import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'

import {
  createTestQueryClient,
  familyInvalidations,
  hashKeyed,
  hashOf,
  makeAllData,
  makeVersion,
  makeVersionState,
  queryWrapper,
  versioningUnavailable,
} from '../__tests__/versioning'
import { layer1API, networkAPI, snapshotAPI } from '../services/api'
import { useSnapshotStore } from '../store'
import type { NetworkInitializeResponse, SnapshotVersionState } from '../types'
import { useDeleteLayer1TopologyEditor, useSaveLayer1TopologyEditor } from './useLayer1Editor'
import { networkKeys, useAllNetworkData } from './useNetwork'
import {
  batfishQueryFamilies,
  useActivateSnapshot,
  useDeleteSnapshotArtifact,
  useDeleteSnapshotFile,
  useReplaceSnapshotArtifactContent,
  useUpdateConfigFileContent,
  useUpdateSnapshotArtifact,
  useUpdateSnapshotFileFormat,
  useUploadFile,
  useUploadSnapshotArtifact,
} from './useSnapshots'
import {
  INVALIDATION_SIGNAL_KEY,
  VERSION_STATE_POLL_INTERVAL_MS,
  getSnapshotTriggerState,
  handleInvalidationSignal,
  invalidateSnapshotFamilies,
  refetchVersionState,
  resetSnapshotTriggerState,
  snapshotVersionKeys,
  useClearResultCache,
  useCommitVersion,
  useDeleteVersions,
  useRestoreVersion,
  useSnapshotVersionState,
} from './useSnapshotVersions'

const NAME = 'snap-a'
const H1 = hashOf('h1')
const H2 = hashOf('h2')
const H3 = hashOf('h3')
const ALL_FAMILIES = batfishQueryFamilies.length
const OTHER_FAMILIES = batfishQueryFamilies.length - 1

let versionStateMock: MockInstance<typeof snapshotAPI.getVersionState>

function setVersionState(state: SnapshotVersionState | Error) {
  versionStateMock.mockImplementation(() =>
    state instanceof Error ? Promise.reject(state) : Promise.resolve(state)
  )
}

function setup() {
  const queryClient = createTestQueryClient()
  const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
  return { queryClient, invalidate, wrapper: queryWrapper(queryClient) }
}

async function poll(queryClient: ReturnType<typeof createTestQueryClient>, state: SnapshotVersionState | Error) {
  setVersionState(state)
  await act(async () => {
    await refetchVersionState(queryClient, NAME)
  })
  await settle()
}

const signalValue = () => localStorage.getItem(INVALIDATION_SIGNAL_KEY)

const settle = () => act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

function deferredActivation() {
  let resolve!: (value: NetworkInitializeResponse) => void
  const promise = new Promise<NetworkInitializeResponse>((res) => {
    resolve = res
  })
  return { promise, resolve }
}

const activation = (parsed?: boolean): NetworkInitializeResponse => ({
  status: 'success',
  network: 'net',
  snapshot: NAME,
  file_parse_status: [],
  init_issues: [],
  parse_warnings: [],
  initialization_result: {},
  ...(parsed === undefined ? {} : { parsed }),
})

beforeEach(() => {
  localStorage.clear()
  useSnapshotStore.setState({
    currentSnapshotName: NAME,
    isSnapshotActivationInProgress: false,
    activatingSnapshotName: null,
  })
  versionStateMock = vi.spyOn(snapshotAPI, 'getVersionState')
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useSnapshotVersionState', () => {
  it('polls every 15 seconds while mounted, pauses in a hidden tab and stays disabled without a snapshot', async () => {
    setVersionState(makeVersionState())
    const { queryClient, wrapper } = setup()
    renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    renderHook(() => useSnapshotVersionState(null), { wrapper })
    await waitFor(() => expect(versionStateMock).toHaveBeenCalledTimes(1))

    const query = queryClient.getQueryCache().find({ queryKey: snapshotVersionKeys.state(NAME), exact: true })
    expect(query?.observers[0].options.refetchInterval).toBe(VERSION_STATE_POLL_INTERVAL_MS)
    expect(VERSION_STATE_POLL_INTERVAL_MS).toBe(15_000)
    expect(query?.observers[0].options.refetchIntervalInBackground).not.toBe(true)
    expect(versionStateMock).not.toHaveBeenCalledWith(null)
  })

  it('invalidates the other families once for H1 -> error -> H2 with two instances mounted, and not for H1 -> error -> H1', async () => {
    setVersionState(makeVersionState())
    const first = setup()
    renderHook(() => [useSnapshotVersionState(NAME), useSnapshotVersionState(NAME)], { wrapper: first.wrapper })
    await waitFor(() => expect(versionStateMock).toHaveBeenCalled())
    await settle()

    await poll(first.queryClient, versioningUnavailable('database'))
    await poll(first.queryClient, makeVersionState({ content_hash: H2 }))

    expect(familyInvalidations(first.invalidate, NAME)).toHaveLength(OTHER_FAMILIES)
    expect(familyInvalidations(first.invalidate, NAME, 'network')).toHaveLength(0)

    setVersionState(makeVersionState())
    const second = setup()
    renderHook(() => [useSnapshotVersionState(NAME), useSnapshotVersionState(NAME)], { wrapper: second.wrapper })
    await waitFor(() => expect(second.queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()
    await poll(second.queryClient, versioningUnavailable('database'))
    await poll(second.queryClient, makeVersionState())

    expect(familyInvalidations(second.invalidate, NAME)).toHaveLength(0)
  })

  it('fires the loaded-pair trigger for H1 -> H2 and a changed Batfish version but not for H -> null -> H or under the kill switch', async () => {
    const loaded = (hash: string | null, version: string | null = '2025.1') =>
      makeVersionState({ loaded_content_hash: hash, loaded_batfish_version: version })
    setVersionState(loaded(H1))
    const { queryClient, invalidate, wrapper } = setup()
    renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()

    await poll(queryClient, loaded(null))
    await poll(queryClient, loaded(H1))
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)

    await poll(queryClient, loaded(H2))
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)

    invalidate.mockClear()
    await poll(queryClient, loaded(H2, '2025.2'))
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)

    invalidate.mockClear()
    await poll(queryClient, makeVersionState({ loaded_content_hash: H3, result_cache_enabled: false }))
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
  })

  it('reloads the version list and working diffs on a new head without touching Batfish families', async () => {
    setVersionState(makeVersionState())
    const { queryClient, invalidate, wrapper } = setup()
    renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()
    queryClient.setQueryData(snapshotVersionKeys.list(NAME), { pages: [], pageParams: [] })
    queryClient.setQueryData(snapshotVersionKeys.diff(NAME, 'version-1', 'working'), { files: [] })
    queryClient.setQueryData(snapshotVersionKeys.diff(NAME, 'version-1', 'version-0'), { files: [] })

    await poll(
      queryClient,
      makeVersionState({ head: makeVersion({ version_id: 'version-2', seq: 2, kind: 'external' }) })
    )

    expect(queryClient.getQueryState(snapshotVersionKeys.list(NAME))?.isInvalidated).toBe(true)
    expect(queryClient.getQueryState(snapshotVersionKeys.diff(NAME, 'version-1', 'working'))?.isInvalidated).toBe(true)
    expect(queryClient.getQueryState(snapshotVersionKeys.diff(NAME, 'version-1', 'version-0'))?.isInvalidated).toBe(false)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
  })

  it('refreshes a working diff when only the working hash changes', async () => {
    setVersionState(makeVersionState({ uncommitted: true }))
    const { queryClient, wrapper } = setup()
    renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()
    queryClient.setQueryData(snapshotVersionKeys.list(NAME), { pages: [], pageParams: [] })
    queryClient.setQueryData(snapshotVersionKeys.diff(NAME, 'version-1', 'working'), { files: [] })

    await poll(queryClient, makeVersionState({ content_hash: H2, uncommitted: true, pending_external: true }))

    expect(queryClient.getQueryState(snapshotVersionKeys.diff(NAME, 'version-1', 'working'))?.isInvalidated).toBe(true)
    expect(queryClient.getQueryState(snapshotVersionKeys.list(NAME))?.isInvalidated).toBe(false)
  })

  it('fires nothing on the first success after resetSnapshotTriggerState', async () => {
    setVersionState(makeVersionState({ loaded_content_hash: H1 }))
    const { queryClient, invalidate, wrapper } = setup()
    const { unmount } = renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()
    unmount()

    queryClient.clear()
    resetSnapshotTriggerState(queryClient)
    setVersionState(makeVersionState({ content_hash: H2, loaded_content_hash: H2 }))
    renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
  })
})

describe('invalidateSnapshotFamilies', () => {
  it('scopes every family to [family, name], applies networkRefetchType to the network family only and writes the signal', async () => {
    const { queryClient, invalidate } = setup()

    await invalidateSnapshotFamilies(queryClient, NAME, { networkRefetchType: 'none' })

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    for (const [family] of batfishQueryFamilies) {
      expect(invalidate).toHaveBeenCalledWith({
        queryKey: [family, NAME],
        refetchType: family === 'network' ? 'none' : 'active',
      })
    }
    expect(JSON.parse(signalValue() ?? '{}')).toMatchObject({ name: NAME, reason: 'edit', ts: expect.any(Number) })
  })

  it('writes no signal with signal: false', async () => {
    const { queryClient } = setup()
    await invalidateSnapshotFamilies(queryClient, NAME, { signal: false })
    expect(signalValue()).toBeNull()
  })
})

describe('topologix:invalidate signal handling', () => {
  const edit = JSON.stringify({ name: NAME, ts: 1, reason: 'edit' })
  const clear = JSON.stringify({ name: NAME, ts: 1, reason: 'clear' })

  async function seededClient(state: SnapshotVersionState | Error, { observed }: { observed: boolean }) {
    const context = setup()
    setVersionState(state)
    const rendered = renderHook(() => useSnapshotVersionState(NAME), { wrapper: context.wrapper })
    await waitFor(() =>
      expect(context.queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).not.toBe('pending')
    )
    await settle()
    if (!observed) {
      rendered.unmount()
      await settle()
    }
    context.invalidate.mockClear()
    versionStateMock.mockClear()
    return context
  }

  it('invalidates once with signal: false on an isError version-state, observers or not', async () => {
    const { queryClient, invalidate } = await seededClient(versioningUnavailable('database'), { observed: false })

    await act(() => handleInvalidationSignal(queryClient, edit))

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(signalValue()).toBeNull()
  })

  it('only marks version-state stale while it is pending or absent', async () => {
    const { queryClient, invalidate } = setup()

    await act(() => handleInvalidationSignal(queryClient, edit))

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: snapshotVersionKeys.state(NAME), exact: true, refetchType: 'none' })
    expect(versionStateMock).not.toHaveBeenCalled()
    expect(getSnapshotTriggerState(queryClient, NAME).suppressToken).toBeNull()
  })

  it('invalidates once on reason clear whatever the status', async () => {
    const { queryClient, invalidate } = setup()

    await act(() => handleInvalidationSignal(queryClient, clear))

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(signalValue()).toBeNull()
  })

  it('refetches version-state once and invalidates nothing when an observed success returns unchanged data', async () => {
    const { queryClient, invalidate } = await seededClient(makeVersionState(), { observed: true })

    await act(() => handleInvalidationSignal(queryClient, edit))
    await settle()

    expect(versionStateMock).toHaveBeenCalledTimes(1)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
  })

  it('invalidates once with signal: false when the observed refetch answers 503', async () => {
    const { queryClient, invalidate } = await seededClient(makeVersionState(), { observed: true })
    setVersionState(versioningUnavailable('database'))

    await act(() => handleInvalidationSignal(queryClient, edit))
    await settle()

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(signalValue()).toBeNull()
  })

  it('invalidates exactly once with signal: false when the observed refetch is the first result reporting false', async () => {
    const { queryClient, invalidate } = await seededClient(makeVersionState(), { observed: true })
    setVersionState(makeVersionState({ result_cache_enabled: false }))

    await act(() => handleInvalidationSignal(queryClient, edit))
    await settle()

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(signalValue()).toBeNull()
  })

  it('only marks version-state stale for an unobserved success', async () => {
    const { queryClient, invalidate } = await seededClient(makeVersionState(), { observed: false })

    await act(() => handleInvalidationSignal(queryClient, edit))

    expect(versionStateMock).not.toHaveBeenCalled()
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
    expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.isInvalidated).toBe(true)
  })

  it.each([
    ['with a mounted observer', true, makeVersionState({ result_cache_enabled: false })],
    ['without an observer', false, makeVersionState({ result_cache_enabled: false })],
    ['when the refetch answers 503', true, versioningUnavailable('database')],
  ])('under the kill switch refetches once and invalidates once with signal: false %s', async (_label, observed, refetched) => {
    const { queryClient, invalidate } = await seededClient(makeVersionState({ result_cache_enabled: false }), { observed })
    setVersionState(refetched)

    await act(() => handleInvalidationSignal(queryClient, edit))
    await settle()

    expect(versionStateMock).toHaveBeenCalledTimes(1)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(signalValue()).toBeNull()
  })

  it('consumes the one-shot invalidate_all mark once when the kill-switch refetch reports true', async () => {
    const { queryClient, invalidate } = await seededClient(makeVersionState({ result_cache_enabled: false }), { observed: true })
    setVersionState(makeVersionState())

    await act(() => handleInvalidationSignal(queryClient, edit))
    await settle()
    await settle()

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(getSnapshotTriggerState(queryClient, NAME).invalidateAll).toBe(false)
    expect(signalValue()).toBeNull()
  })

  it('suppresses the echo of a signal-induced trigger, but a later poll trigger writes the signal again', async () => {
    const { queryClient, invalidate } = await seededClient(makeVersionState(), { observed: true })
    setVersionState(makeVersionState({ content_hash: H2 }))

    await act(() => handleInvalidationSignal(queryClient, edit))
    await settle()

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(OTHER_FAMILIES)
    expect(signalValue()).toBeNull()

    await poll(queryClient, makeVersionState({ content_hash: H3 }))
    expect(JSON.parse(signalValue() ?? '{}')).toMatchObject({ name: NAME, reason: 'edit' })
  })

  it('lets a later poll write the signal after a no-op signal-induced refetch', async () => {
    const { queryClient } = await seededClient(makeVersionState(), { observed: true })

    await act(() => handleInvalidationSignal(queryClient, edit))
    await settle()
    expect(getSnapshotTriggerState(queryClient, NAME).suppressToken).toBeNull()

    await poll(queryClient, makeVersionState({ content_hash: H2 }))
    expect(signalValue()).not.toBeNull()
  })

  it('does not suppress with a token older than 30 seconds or left by an unmounted observer', async () => {
    const { queryClient } = await seededClient(makeVersionState(), { observed: true })
    getSnapshotTriggerState(queryClient, NAME).suppressToken = Date.now() - 31_000

    await poll(queryClient, makeVersionState({ content_hash: H2 }))
    expect(signalValue()).not.toBeNull()

    const other = setup()
    setVersionState(makeVersionState())
    const rendered = renderHook(() => useSnapshotVersionState(NAME), { wrapper: other.wrapper })
    await waitFor(() => expect(other.queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    getSnapshotTriggerState(other.queryClient, NAME).suppressToken = Date.now()
    rendered.unmount()
    await settle()
    expect(getSnapshotTriggerState(other.queryClient, NAME).suppressToken).toBeNull()
  })
})

describe('useActivateSnapshot', () => {
  let activateMock: MockInstance<typeof snapshotAPI.activate>

  beforeEach(() => {
    activateMock = vi.spyOn(snapshotAPI, 'activate')
  })

  async function activationOnlyClient() {
    const context = setup()
    setVersionState(makeVersionState())
    const versionStateHook = renderHook(() => useSnapshotVersionState(NAME), { wrapper: context.wrapper })
    await waitFor(() => expect(context.queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()
    versionStateHook.unmount()
    await settle()
    const rendered = renderHook(() => useActivateSnapshot(), { wrapper: context.wrapper })
    context.invalidate.mockClear()
    return { ...context, ...rendered }
  }

  async function mountedClient(state: SnapshotVersionState | Error) {
    const context = setup()
    setVersionState(state)
    const rendered = renderHook(
      () => ({ versionState: useSnapshotVersionState(NAME), activate: useActivateSnapshot() }),
      { wrapper: context.wrapper }
    )
    await waitFor(() => expect(context.queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).not.toBe('pending'))
    await settle()
    context.invalidate.mockClear()
    return { ...context, ...rendered }
  }

  it('if_stale keeps the current name, cancels nothing upfront and invalidates every family once when parsed is true', async () => {
    const { queryClient, invalidate, result } = await mountedClient(makeVersionState({ loaded_content_hash: H1 }))
    const cancel = vi.spyOn(queryClient, 'cancelQueries')
    activateMock.mockResolvedValue(activation(true))
    setVersionState(makeVersionState({ loaded_content_hash: H2 }))
    const names: (string | null)[] = []
    const unsubscribe = useSnapshotStore.subscribe((state) => names.push(state.currentSnapshotName))

    await act(() => result.current.activate.mutateAsync({ name: NAME, ifStale: true }))
    await settle()
    unsubscribe()

    expect(activateMock).toHaveBeenCalledWith(NAME, { if_stale: true })
    expect(cancel).not.toHaveBeenCalled()
    expect(names).not.toContain(null)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(getSnapshotTriggerState(queryClient, NAME).loadedPair?.hash).toBe(H2)
    expect(signalValue()).not.toBeNull()
  })

  it('if_stale pre-write clears fallback_mismatch so the settled refetch invalidates exactly once', async () => {
    const { queryClient, invalidate, result } = await mountedClient(makeVersionState())
    getSnapshotTriggerState(queryClient, NAME).fallbackMismatch = true
    activateMock.mockResolvedValue(activation(true))

    await act(() => result.current.activate.mutateAsync({ name: NAME, ifStale: true }))
    await settle()

    expect(getSnapshotTriggerState(queryClient, NAME).fallbackMismatch).toBe(false)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
  })

  it('writes no signal, no trigger state and no snapshot name when the session was reset during the activation', async () => {
    const { queryClient, invalidate, result } = await activationOnlyClient()
    const pending = deferredActivation()
    activateMock.mockReturnValue(pending.promise)
    let running!: Promise<unknown>
    act(() => {
      running = result.current.mutateAsync({ name: NAME, ifStale: true })
    })
    await settle()
    versionStateMock.mockClear()

    act(() => {
      queryClient.clear()
      resetSnapshotTriggerState(queryClient)
      useSnapshotStore.setState({ currentSnapshotName: null, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
      localStorage.removeItem(INVALIDATION_SIGNAL_KEY)
    })
    await act(async () => {
      pending.resolve(activation(true))
      await running
    })
    await settle()

    expect(signalValue()).toBeNull()
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
    expect(versionStateMock).not.toHaveBeenCalled()
    expect(useSnapshotStore.getState().currentSnapshotName).toBeNull()
    expect(getSnapshotTriggerState(queryClient, NAME).workingHash).toBeUndefined()
  })

  it('the forced path does not select the snapshot again when the session was reset during the activation', async () => {
    const { queryClient, result } = await activationOnlyClient()
    const pending = deferredActivation()
    activateMock.mockReturnValue(pending.promise)
    let running!: Promise<unknown>
    act(() => {
      running = result.current.mutateAsync(NAME)
    })
    await settle()

    act(() => {
      queryClient.clear()
      resetSnapshotTriggerState(queryClient)
      useSnapshotStore.setState({ currentSnapshotName: null, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    })
    await act(async () => {
      pending.resolve(activation(true))
      await running
    })

    expect(useSnapshotStore.getState().currentSnapshotName).toBeNull()
    expect(queryClient.getQueryData(['validation', NAME, 'file-parse-status'])).toBeUndefined()
  })

  it('if_stale with an absent parsed flag counts as parsed', async () => {
    const { invalidate, result } = await mountedClient(makeVersionState())
    activateMock.mockResolvedValue(activation())

    await act(() => result.current.activate.mutateAsync({ name: NAME, ifStale: true }))

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
  })

  it('if_stale with parsed false under a settled success writes nothing, so the next mount still fires the working-hash trigger', async () => {
    const { queryClient, invalidate, wrapper } = setup()
    setVersionState(makeVersionState())
    const versionStateHook = renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()
    versionStateHook.unmount()
    await settle()
    const { result } = renderHook(() => useActivateSnapshot(), { wrapper })
    activateMock.mockResolvedValue(activation(false))
    setVersionState(makeVersionState({ content_hash: H2 }))
    invalidate.mockClear()

    await act(() => result.current.mutateAsync({ name: NAME, ifStale: true }))

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
    expect(getSnapshotTriggerState(queryClient, NAME).workingHash).toBe(H1)

    renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    await settle()
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(OTHER_FAMILIES)
  })

  it.each([
    ['the kill switch is on', makeVersionState({ result_cache_enabled: false })],
    ['version-state is not isSuccess', versioningUnavailable('database')],
  ])('if_stale with parsed false still invalidates once when %s', async (_label, state) => {
    const { invalidate, result } = await mountedClient(state)
    activateMock.mockResolvedValue(activation(false))

    await act(() => result.current.activate.mutateAsync({ name: NAME, ifStale: true }))

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
  })

  it('if_stale activation errors neither refetch, pre-write nor invalidate and reject', async () => {
    const { queryClient, invalidate, result } = await mountedClient(makeVersionState())
    versionStateMock.mockClear()
    activateMock.mockRejectedValue(new Error('activation failed'))
    const before = { ...getSnapshotTriggerState(queryClient, NAME) }

    await act(async () => {
      await expect(result.current.activate.mutateAsync({ name: NAME, ifStale: true })).rejects.toThrow('activation failed')
    })

    expect(versionStateMock).not.toHaveBeenCalled()
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
    expect(getSnapshotTriggerState(queryClient, NAME)).toMatchObject(before)
    expect(useSnapshotStore.getState().currentSnapshotName).toBe(NAME)
  })

  it('sends exactly one all-data request for isError at H1 -> parsed: true -> refetch succeeding at H2', async () => {
    const allData = vi.spyOn(networkAPI, 'getAllData')
    allData.mockResolvedValueOnce(hashKeyed(makeAllData('n1', H1), { snapshotId: 'snapshot-id-1', contentHash: H1, cacheStatus: 'hit' }))
    setVersionState(makeVersionState())
    const { queryClient, invalidate, wrapper } = setup()
    const { result } = renderHook(() => ({ data: useAllNetworkData(), activate: useActivateSnapshot() }), { wrapper })
    await waitFor(() => expect(result.current.data.data).toBeDefined())
    await poll(queryClient, versioningUnavailable('database'))
    allData.mockClear()
    invalidate.mockClear()

    allData.mockResolvedValue(hashKeyed(makeAllData('n2', H2), { snapshotId: 'snapshot-id-1', contentHash: H2, cacheStatus: 'stored' }))
    activateMock.mockResolvedValue(activation(true))
    setVersionState(makeVersionState({ content_hash: H2, loaded_content_hash: H2 }))
    await act(() => result.current.activate.mutateAsync({ name: NAME, ifStale: true }))

    await waitFor(() => expect(result.current.data.data?.node_properties[0].node).toBe('n2'))
    await settle()
    expect(allData).toHaveBeenCalledTimes(1)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['network', NAME], refetchType: 'none' })
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
  })

  it('the forced path refetches version-state before invalidating network keys', async () => {
    const { queryClient, result } = await mountedClient(makeVersionState())
    const order: string[] = []
    versionStateMock.mockImplementation(async () => {
      order.push('version-state')
      return makeVersionState()
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries').mockImplementation(async (filters) => {
      if ((filters as { queryKey?: unknown[] })?.queryKey?.[0] === 'network') order.push('invalidate-network')
    })
    activateMock.mockResolvedValue(activation(true))

    await act(() => result.current.activate.mutateAsync(NAME))

    expect(activateMock).toHaveBeenCalledWith(NAME)
    expect(order.indexOf('version-state')).toBeGreaterThanOrEqual(0)
    expect(order.indexOf('version-state')).toBeLessThan(order.indexOf('invalidate-network'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['network'], refetchType: 'none' })
  })
})

describe('mutation hooks', () => {
  it('await the version-state refetch and invalidate no Batfish family after an upload', async () => {
    setVersionState(makeVersionState())
    const { queryClient, invalidate, wrapper } = setup()
    const { result } = renderHook(() => ({ versionState: useSnapshotVersionState(NAME), upload: useUploadFile() }), { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()
    vi.spyOn(snapshotAPI, 'uploadFile').mockResolvedValue({
      name: 'r1.cfg',
      size_bytes: 1,
      modified_at: '2026-01-01T00:00:00Z',
      requires_reinitialize: true,
    })
    let refetched = false
    versionStateMock.mockImplementation(async () => {
      refetched = true
      return makeVersionState({ uncommitted: true })
    })
    invalidate.mockClear()

    await act(async () => {
      await result.current.upload.mutateAsync({ name: NAME, file: new File(['x'], 'r1.cfg') })
      expect(refetched).toBe(true)
    })

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
    expect(invalidate).not.toHaveBeenCalledWith(expect.objectContaining({ queryKey: ['network'] }))
  })

  it('commit and history deletion do not invalidate network keys', async () => {
    setVersionState(makeVersionState({ uncommitted: true }))
    const { invalidate, wrapper } = setup()
    vi.spyOn(snapshotAPI, 'commitVersion').mockResolvedValue(makeVersion({ version_id: 'version-2', seq: 2, kind: 'manual' }))
    const deleteVersions = vi.spyOn(snapshotAPI, 'deleteVersions').mockResolvedValue({ deleted: 1, head: null })
    const { result } = renderHook(() => ({ commit: useCommitVersion(), remove: useDeleteVersions() }), { wrapper })

    await act(() => result.current.commit.mutateAsync({ name: NAME, message: 'change', expectedHead: 'version-1' }))
    await act(() =>
      result.current.remove.mutateAsync({ name: NAME, request: { mode: 'oldest', count: 1, expected_head: 'version-2', expected_total: 2 } })
    )

    expect(deleteVersions).toHaveBeenCalledWith(NAME, { mode: 'oldest', count: 1, expected_head: 'version-2', expected_total: 2 })
    expect(invalidate.mock.calls.some((call) => (call[0] as { queryKey?: unknown[] })?.queryKey?.[0] === 'network')).toBe(false)
  })

  it('restore sends the displayed working hash as expected_working_hash', async () => {
    setVersionState(makeVersionState())
    const { wrapper } = setup()
    const restore = vi
      .spyOn(snapshotAPI, 'restoreVersion')
      .mockResolvedValue({ requires_reinitialize: true, restored_from: { version_id: 'version-1', seq: 1 } })
    const { result } = renderHook(() => useRestoreVersion(), { wrapper })

    await act(() => result.current.mutateAsync({ name: NAME, versionId: 'version-1', expectedWorkingHash: H2 }))

    expect(restore).toHaveBeenCalledWith(NAME, 'version-1', { expected_working_hash: H2 })
  })

  it('useClearResultCache invalidates through the helper with reason clear only on success', async () => {
    const { invalidate, wrapper } = setup()
    const clear = vi.spyOn(snapshotAPI, 'clearResultCache').mockRejectedValueOnce(versioningUnavailable('storage'))
    versionStateMock.mockRejectedValue(versioningUnavailable('storage'))
    const { result } = renderHook(() => useClearResultCache(), { wrapper })

    await act(async () => {
      await expect(result.current.mutateAsync(NAME)).rejects.toBeDefined()
    })
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)

    clear.mockResolvedValueOnce({ cleared: true })
    await act(() => result.current.mutateAsync(NAME))
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(JSON.parse(signalValue() ?? '{}')).toMatchObject({ name: NAME, reason: 'clear' })
  })
})

describe('Layer 1 hooks', () => {
  beforeEach(() => {
    vi.spyOn(layer1API, 'saveTopology').mockResolvedValue({ status: 'saved' } as never)
  })

  async function layer1Client(state: SnapshotVersionState | Error) {
    const context = setup()
    setVersionState(state)
    const rendered = renderHook(
      () => ({ versionState: useSnapshotVersionState(NAME), save: useSaveLayer1TopologyEditor() }),
      { wrapper: context.wrapper }
    )
    await waitFor(() => expect(context.queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).not.toBe('pending'))
    await settle()
    context.invalidate.mockClear()
    return { ...context, ...rendered }
  }

  it('invalidate every family of the current snapshot once when version-state errs after the awaited refetch', async () => {
    const { queryClient, invalidate, result } = await layer1Client(makeVersionState())
    const refetch = vi.spyOn(queryClient, 'refetchQueries')
    setVersionState(versioningUnavailable('database'))

    await act(() => result.current.save.mutateAsync({ snapshotName: NAME, topology: { edges: [] } as never }))
    await settle()

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(refetch).not.toHaveBeenCalledWith({ queryKey: ['topology'] })
    expect(invalidate).not.toHaveBeenCalledWith({ queryKey: ['network'] })
  })

  it('invalidate once under the kill switch', async () => {
    const { invalidate, result } = await layer1Client(makeVersionState({ result_cache_enabled: false }))

    await act(() => result.current.save.mutateAsync({ snapshotName: NAME, topology: { edges: [] } as never }))

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
  })

  it("send exactly one all-data request and never refetch the 'unknown' key when the awaited refetch is the first success", async () => {
    const allData = vi.spyOn(networkAPI, 'getAllData').mockResolvedValue(hashKeyed(makeAllData('n0')))
    setVersionState(versioningUnavailable('database'))
    const { invalidate, wrapper } = setup()
    const { result } = renderHook(
      () => ({ data: useAllNetworkData(), save: useSaveLayer1TopologyEditor() }),
      { wrapper }
    )
    await waitFor(() => expect(result.current.data.data).toBeDefined())
    await settle()
    allData.mockClear()
    invalidate.mockClear()
    allData.mockResolvedValue(hashKeyed(makeAllData('n1', H1), { snapshotId: 'snapshot-id-1', contentHash: H1, cacheStatus: 'stored' }))
    setVersionState(makeVersionState({ loaded_content_hash: H1 }))

    await act(() => result.current.save.mutateAsync({ snapshotName: NAME, topology: { edges: [] } as never }))
    await waitFor(() => expect(result.current.data.data?.node_properties[0].node).toBe('n1'))
    await settle()

    expect(allData).toHaveBeenCalledTimes(1)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['network', NAME], refetchType: 'none' })
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
  })

  it('leave the triggers to version-state in normal mode and never touch another snapshot', async () => {
    const { invalidate, result } = await layer1Client(makeVersionState())

    await act(() => result.current.save.mutateAsync({ snapshotName: 'snap-other', topology: { edges: [] } as never }))
    await act(() => result.current.save.mutateAsync({ snapshotName: NAME, topology: { edges: [] } as never }))
    await settle()

    expect(familyInvalidations(invalidate, 'snap-other')).toHaveLength(0)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
  })
})

describe('request counts with hash-keyed observers mounted', () => {
  let allData: MockInstance<typeof networkAPI.getAllData>
  const servedAt = (label: string, hash: string) =>
    hashKeyed(makeAllData(label, hash), { snapshotId: 'snapshot-id-1', contentHash: hash, cacheStatus: 'stored' })

  beforeEach(() => {
    allData = vi.spyOn(networkAPI, 'getAllData')
    vi.spyOn(layer1API, 'saveTopology').mockResolvedValue({ status: 'saved' } as never)
  })

  async function topologyClient(state: SnapshotVersionState | Error, first = servedAt('n1', H1)) {
    const context = setup()
    setVersionState(state)
    allData.mockResolvedValueOnce(first)
    const rendered = renderHook(
      () => ({
        data: useAllNetworkData(),
        activate: useActivateSnapshot(),
        save: useSaveLayer1TopologyEditor(),
        upload: useUploadFile(),
      }),
      { wrapper: context.wrapper }
    )
    await waitFor(() => expect(rendered.result.current.data.data).toBeDefined())
    await settle()
    context.invalidate.mockClear()
    allData.mockClear()
    return { ...context, ...rendered }
  }

  it('one result changing both the working hash and the loaded pair sends exactly one all-data request', async () => {
    const { queryClient, invalidate, result } = await topologyClient(makeVersionState({ loaded_content_hash: H1 }))
    allData.mockResolvedValue(servedAt('n2', H2))

    await poll(queryClient, makeVersionState({ content_hash: H2, loaded_content_hash: H2 }))
    await waitFor(() => expect(result.current.data.data?.node_properties[0].node).toBe('n2'))
    await settle()

    expect(allData).toHaveBeenCalledTimes(1)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['network', NAME], refetchType: 'none' })
  })

  it.each([
    ['a changed hash', H2, 'none'],
    ['a hash equal to retained_key', H1, 'active'],
  ])('the one-shot invalidate_all mark with %s sends exactly one all-data request', async (_label, hash, refetchType) => {
    const { queryClient, invalidate, result } = await topologyClient(
      makeVersionState({ result_cache_enabled: false }),
      hashKeyed(makeAllData('n1'))
    )
    allData.mockResolvedValue(servedAt('n2', hash))
    setVersionState(makeVersionState({ content_hash: hash }))

    await act(() => handleInvalidationSignal(queryClient, JSON.stringify({ name: NAME, ts: 1, reason: 'edit' })))
    await waitFor(() => expect(result.current.data.data?.node_properties[0].node).toBe('n2'))
    await settle()

    expect(allData).toHaveBeenCalledTimes(1)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['network', NAME], refetchType })
    expect(signalValue()).toBeNull()
  })

  it('a Reload whose awaited refetch is the first version-state failure still refetches the topology', async () => {
    const { result } = await topologyClient(makeVersionState())
    vi.spyOn(snapshotAPI, 'activate').mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(activation(true)), 30))
    )
    allData.mockResolvedValue(servedAt('n1b', H1))
    setVersionState(versioningUnavailable('database'))

    let running!: Promise<unknown>
    act(() => {
      running = result.current.activate.mutateAsync(NAME)
    })
    await waitFor(() => expect(result.current.data.data?.node_properties[0].node).toBe('n1b'))
    await act(() => running)

    expect(allData).toHaveBeenCalledTimes(1)
    expect(useSnapshotStore.getState().currentSnapshotName).toBe(NAME)
  })

  it('a Layer 1 save under the kill switch sends exactly one all-data request', async () => {
    const { invalidate, result } = await topologyClient(makeVersionState({ result_cache_enabled: false }), hashKeyed(makeAllData('n1')))
    allData.mockResolvedValue(hashKeyed(makeAllData('n2')))

    await act(() => result.current.save.mutateAsync({ snapshotName: NAME, topology: { edges: [] } as never }))
    await waitFor(() => expect(result.current.data.data?.node_properties[0].node).toBe('n2'))
    await settle()

    expect(allData).toHaveBeenCalledTimes(1)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
  })

  it('leaves the current snapshot untouched by a fallback-mode edit of another snapshot', async () => {
    const { queryClient, invalidate, result } = await topologyClient(makeVersionState())
    await poll(queryClient, versioningUnavailable('database'))
    invalidate.mockClear()

    await act(() => result.current.save.mutateAsync({ snapshotName: 'snap-other', topology: { edges: [] } as never }))
    await settle()

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
    expect(familyInvalidations(invalidate, 'snap-other')).toHaveLength(0)
    expect(allData).not.toHaveBeenCalled()
  })

  it('a remount within 5 minutes after a signal makes one version-state fetch and re-keys', async () => {
    const { queryClient, wrapper, unmount } = await topologyClient(makeVersionState())
    unmount()
    await settle()
    versionStateMock.mockClear()

    await act(() => handleInvalidationSignal(queryClient, JSON.stringify({ name: NAME, ts: 1, reason: 'edit' })))
    expect(versionStateMock).not.toHaveBeenCalled()

    setVersionState(makeVersionState({ content_hash: H2 }))
    allData.mockResolvedValue(servedAt('n2', H2))
    const remounted = renderHook(() => useAllNetworkData(), { wrapper })
    await waitFor(() => expect(remounted.result.current.data?.node_properties[0].node).toBe('n2'))
    await settle()

    expect(versionStateMock).toHaveBeenCalledTimes(1)
    expect(allData).toHaveBeenCalledTimes(1)
    expect(queryClient.getQueryData(networkKeys.allData(NAME, H2))).toBeDefined()
  })

  it('a kill-switch edit with a popout open sends no all-data request before the activation and one per window after it', async () => {
    const main = await topologyClient(makeVersionState({ result_cache_enabled: false }), hashKeyed(makeAllData('main-1')))
    const popoutClient = createTestQueryClient()
    const popoutInvalidate = vi.spyOn(popoutClient, 'invalidateQueries')
    allData.mockResolvedValueOnce(hashKeyed(makeAllData('popout-1')))
    const popout = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(popoutClient) })
    await waitFor(() => expect(popout.result.current.data).toBeDefined())
    await settle()
    allData.mockClear()
    vi.spyOn(snapshotAPI, 'uploadFile').mockResolvedValue({
      name: 'r1.cfg',
      size_bytes: 1,
      modified_at: '2026-01-01T00:00:00Z',
      requires_reinitialize: true,
    })
    vi.spyOn(snapshotAPI, 'activate').mockResolvedValue(activation(true))
    setVersionState(makeVersionState({ content_hash: H2, result_cache_enabled: false }))

    await act(() => main.result.current.upload.mutateAsync({ name: NAME, file: new File(['x'], 'r1.cfg') }))
    await settle()
    expect(allData).not.toHaveBeenCalled()
    expect(signalValue()).toBeNull()

    allData.mockResolvedValueOnce(hashKeyed(makeAllData('main-2')))
    await act(() => main.result.current.activate.mutateAsync({ name: NAME, ifStale: true }))
    await waitFor(() => expect(main.result.current.data.data?.node_properties[0].node).toBe('main-2'))
    await settle()
    expect(allData).toHaveBeenCalledTimes(1)
    const signal = signalValue()
    expect(JSON.parse(signal ?? '{}')).toMatchObject({ name: NAME, reason: 'edit' })

    allData.mockResolvedValueOnce(hashKeyed(makeAllData('popout-2')))
    localStorage.removeItem(INVALIDATION_SIGNAL_KEY)
    await act(() => handleInvalidationSignal(popoutClient, signal))
    await waitFor(() => expect(popout.result.current.data?.node_properties[0].node).toBe('popout-2'))
    await settle()

    expect(allData).toHaveBeenCalledTimes(2)
    expect(familyInvalidations(popoutInvalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(signalValue()).toBeNull()
  })
})

describe('trigger and signal handling with two instances, a pending query and fallback_mismatch', () => {
  it('fires the loaded-pair trigger exactly once with two instances mounted', async () => {
    setVersionState(makeVersionState({ loaded_content_hash: H1 }))
    const { queryClient, invalidate, wrapper } = setup()
    renderHook(() => [useSnapshotVersionState(NAME), useSnapshotVersionState(NAME)], { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()

    await poll(queryClient, makeVersionState({ loaded_content_hash: H2 }))

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
  })

  it('only marks version-state stale while an observed query is still pending', async () => {
    versionStateMock.mockReturnValue(new Promise(() => {}))
    const { queryClient, invalidate, wrapper } = setup()
    renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    await settle()

    await act(() => handleInvalidationSignal(queryClient, JSON.stringify({ name: NAME, ts: 1, reason: 'edit' })))

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: snapshotVersionKeys.state(NAME), exact: true, refetchType: 'none' })
    expect(getSnapshotTriggerState(queryClient, NAME).suppressToken).toBeNull()
  })

  it('with fallback_mismatch set, a signal whose refetch is the first settled false result invalidates once and writes no signal', async () => {
    setVersionState(makeVersionState())
    const { queryClient, invalidate, wrapper } = setup()
    renderHook(() => useSnapshotVersionState(NAME), { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()
    invalidate.mockClear()
    getSnapshotTriggerState(queryClient, NAME).fallbackMismatch = true
    setVersionState(makeVersionState({ result_cache_enabled: false }))

    await act(() => handleInvalidationSignal(queryClient, JSON.stringify({ name: NAME, ts: 1, reason: 'edit' })))
    await settle()

    expect(familyInvalidations(invalidate, NAME)).toHaveLength(ALL_FAMILIES)
    expect(getSnapshotTriggerState(queryClient, NAME).fallbackMismatch).toBe(false)
    expect(signalValue()).toBeNull()
  })
})

describe('no other mutation hook invalidates anything', () => {
  const file = { name: 'r1.cfg', size_bytes: 1, modified_at: '2026-01-01T00:00:00Z', requires_reinitialize: true }
  const artifact = {
    artifact_id: 'a1',
    artifact_type: 'network_config',
    label: 'Config',
    category: 'configs',
    logical_name: 'r1',
    relative_path: 'configs/r1.cfg',
    size_bytes: 1,
    modified_at: '2026-01-01T00:00:00Z',
    metadata: {},
    mutation_policy: {} as never,
    warnings: [],
    requires_reinitialize: true,
  }
  const cases: [string, () => { mutateAsync: (variables: never) => Promise<unknown> }, () => void, unknown][] = [
    ['useUpdateSnapshotFileFormat', useUpdateSnapshotFileFormat, () => vi.spyOn(snapshotAPI, 'updateFileFormat').mockResolvedValue(file), { name: NAME, filename: 'r1.cfg', configurationFormatOverride: 'ios' }],
    ['useUpdateConfigFileContent', useUpdateConfigFileContent, () => vi.spyOn(snapshotAPI, 'updateConfigFileContent').mockResolvedValue(file), { name: NAME, filename: 'r1.cfg', content: 'x', expectedSha256: 'a' }],
    ['useDeleteSnapshotFile', useDeleteSnapshotFile, () => vi.spyOn(snapshotAPI, 'deleteFile').mockResolvedValue({ name: 'r1.cfg', requires_reinitialize: true }), { name: NAME, filename: 'r1.cfg' }],
    ['useUploadSnapshotArtifact', useUploadSnapshotArtifact, () => vi.spyOn(snapshotAPI, 'uploadArtifact').mockResolvedValue(artifact), { name: NAME, artifactType: 'network_config', file: new File(['x'], 'r1.cfg'), metadata: {}, previewToken: 't' }],
    ['useUpdateSnapshotArtifact', useUpdateSnapshotArtifact, () => vi.spyOn(snapshotAPI, 'updateArtifact').mockResolvedValue(artifact), { name: NAME, artifactId: 'a1', previewToken: 't' }],
    ['useReplaceSnapshotArtifactContent', useReplaceSnapshotArtifactContent, () => vi.spyOn(snapshotAPI, 'replaceArtifactContent').mockResolvedValue(artifact), { name: NAME, artifactId: 'a1', file: new File(['x'], 'r1.cfg'), previewToken: 't' }],
    ['useDeleteSnapshotArtifact', useDeleteSnapshotArtifact, () => vi.spyOn(snapshotAPI, 'deleteArtifact').mockResolvedValue({ artifact_id: 'a1', artifact_type: 'network_config', relative_path: 'configs/r1.cfg', requires_reinitialize: true }), { name: NAME, artifactId: 'a1', previewToken: 't' }],
    ['useRestoreVersion', useRestoreVersion, () => vi.spyOn(snapshotAPI, 'restoreVersion').mockResolvedValue({ requires_reinitialize: true, restored_from: { version_id: 'version-1', seq: 1 } }), { name: NAME, versionId: 'version-1', expectedWorkingHash: H1 }],
    ['useCommitVersion', useCommitVersion, () => vi.spyOn(snapshotAPI, 'commitVersion').mockResolvedValue(makeVersion()), { name: NAME, message: 'm', expectedHead: 'version-1' }],
    ['useDeleteVersions', useDeleteVersions, () => vi.spyOn(snapshotAPI, 'deleteVersion').mockResolvedValue({ deleted: 1, head: null }), { name: NAME, versionId: 'version-1', expectedHead: 'version-1' }],
    ['useDeleteLayer1TopologyEditor', useDeleteLayer1TopologyEditor, () => vi.spyOn(layer1API, 'deleteTopology').mockResolvedValue(undefined), NAME],
  ]

  it.each(cases)('%s awaits the version-state refetch and invalidates no Batfish family', async (_name, useHook, mockApi, variables) => {
    mockApi()
    setVersionState(makeVersionState())
    const { queryClient, invalidate, wrapper } = setup()
    const refetch = vi.spyOn(queryClient, 'refetchQueries')
    const { result } = renderHook(() => ({ versionState: useSnapshotVersionState(NAME), mutation: useHook() }), { wrapper })
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('success'))
    await settle()
    invalidate.mockClear()
    refetch.mockClear()
    versionStateMock.mockClear()

    await act(() => result.current.mutation.mutateAsync(variables as never))
    await settle()

    expect(versionStateMock).toHaveBeenCalledTimes(1)
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)
    for (const call of [...invalidate.mock.calls, ...refetch.mock.calls]) {
      const key = (call[0] as { queryKey?: unknown[] } | undefined)?.queryKey
      expect(batfishQueryFamilies.some(([family]) => key?.[0] === family)).toBe(false)
    }
  })
})
