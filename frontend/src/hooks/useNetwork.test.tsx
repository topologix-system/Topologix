import { act, renderHook, waitFor } from '@testing-library/react'
import { onlineManager } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'

import {
  createTestQueryClient,
  familyInvalidations,
  hashKeyed,
  hashOf,
  httpError,
  makeAllData,
  makeVersionState,
  networkError,
  queryWrapper,
  versioningUnavailable,
} from '../__tests__/versioning'
import { networkAPI, snapshotAPI } from '../services/api'
import { useSnapshotStore } from '../store'
import type { AllNetworkData, HashKeyedResponse, SnapshotVersionState } from '../types'
import { batfishQueryFamilies } from './useSnapshots'
import { SnapshotMismatchError, networkKeys, useAllNetworkData } from './useNetwork'
import {
  getSnapshotTriggerState,
  refetchVersionState,
  resetSnapshotTriggerState,
  retryVersionState,
  snapshotVersionKeys,
} from './useSnapshotVersions'

const NAME = 'snap-a'
const H1 = hashOf('h1')
const H2 = hashOf('b2')
const SNAPSHOT_ID = 'snapshot-id-1'

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

const served = (label: string, hash: string, cacheStatus = 'hit'): HashKeyedResponse<AllNetworkData> =>
  hashKeyed(makeAllData(label, hash), { snapshotId: SNAPSHOT_ID, contentHash: hash, cacheStatus })

let versionStateMock: MockInstance<typeof snapshotAPI.getVersionState>
let allDataMock: MockInstance<typeof networkAPI.getAllData>

function setVersionState(state: SnapshotVersionState | Error) {
  versionStateMock.mockImplementation(() =>
    state instanceof Error ? Promise.reject(state) : Promise.resolve(state)
  )
}

async function pollVersionState(queryClient: ReturnType<typeof createTestQueryClient>) {
  await act(async () => {
    await refetchVersionState(queryClient, NAME)
  })
  await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))
}

describe('hash-keyed network queries', () => {
  beforeEach(() => {
    localStorage.clear()
    useSnapshotStore.setState({
      currentSnapshotName: NAME,
      isSnapshotActivationInProgress: false,
      activatingSnapshotName: null,
    })
    versionStateMock = vi.spyOn(snapshotAPI, 'getVersionState')
    allDataMock = vi.spyOn(networkAPI, 'getAllData')
  })

  afterEach(() => {
    vi.restoreAllMocks()
    onlineManager.setOnline(true)
  })

  it('include the content hash in networkKeys', () => {
    expect(networkKeys.allData(NAME, H1)).toEqual(['network', NAME, H1, 'all-data'])
    expect(networkKeys.nodes(NAME, H1)).toEqual(['network', NAME, H1, 'nodes'])
    expect(networkKeys.interfaces(NAME, null)).toEqual(['network', NAME, null, 'interfaces'])
    expect(networkKeys.routes(NAME, 'unknown')).toEqual(['network', NAME, 'unknown', 'routes'])
    expect(networkKeys.vlans(NAME, H2)).toEqual(['network', NAME, H2, 'vlans'])
    expect(networkKeys.ipOwners(NAME, H2)).toEqual(['network', NAME, H2, 'ip-owners'])
  })

  it('stay disabled and report loading while version-state is pending, then send exactly one all-data request', async () => {
    const pendingState = deferred<SnapshotVersionState>()
    versionStateMock.mockReturnValue(pendingState.promise)
    allDataMock.mockResolvedValue(served('n1', H1))
    const queryClient = createTestQueryClient()

    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })

    expect(result.current.isLoading).toBe(true)
    expect(allDataMock).not.toHaveBeenCalled()

    await act(async () => pendingState.resolve(makeVersionState()))
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n1'))
    expect(allDataMock).toHaveBeenCalledTimes(1)
    expect(queryClient.getQueryData(networkKeys.allData(NAME, H1))).toMatchObject({ legacy: false })
  })

  it('report no loading and send nothing without an active snapshot', () => {
    useSnapshotStore.setState({ currentSnapshotName: null })
    const queryClient = createTestQueryClient()

    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })

    expect(result.current.isLoading).toBe(false)
    expect(versionStateMock).not.toHaveBeenCalled()
    expect(allDataMock).not.toHaveBeenCalled()
  })

  it('do not refetch while the hash is unchanged and keep the previous data as placeholder on a hash change', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValueOnce(served('n1', H1))
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n1'))

    await pollVersionState(queryClient)
    await pollVersionState(queryClient)
    expect(allDataMock).toHaveBeenCalledTimes(1)

    const second = deferred<HashKeyedResponse<AllNetworkData>>()
    allDataMock.mockReturnValueOnce(second.promise)
    setVersionState(makeVersionState({ content_hash: H2 }))
    await pollVersionState(queryClient)

    await waitFor(() => expect(allDataMock).toHaveBeenCalledTimes(2))
    expect(result.current.isPlaceholderData).toBe(true)
    expect(result.current.data?.node_properties[0].node).toBe('n1')

    await act(async () => second.resolve(served('n2', H2)))
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n2'))
    expect(result.current.isPlaceholderData).toBe(false)
  })

  it('do not keep previous data across a snapshot switch', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(served('n1', H1))
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data).toBeDefined())

    versionStateMock.mockReturnValue(new Promise(() => {}))
    act(() => useSnapshotStore.setState({ currentSnapshotName: 'snap-b' }))

    expect(result.current.data).toBeUndefined()
    expect(result.current.isPlaceholderData).toBe(false)
    expect(result.current.isLoading).toBe(true)
  })

  it('keep the retained H1 key while the backend is unreachable: no request later, on reconnect or on remount', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(served('n1', H1))
    const queryClient = createTestQueryClient()
    const wrapper = queryWrapper(queryClient)
    const first = renderHook(() => useAllNetworkData(), { wrapper })
    await waitFor(() => expect(first.result.current.data).toBeDefined())

    setVersionState(networkError())
    await pollVersionState(queryClient)
    await waitFor(() => expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('error'))
    expect(first.result.current.data?.node_properties[0].node).toBe('n1')

    await act(async () => {
      onlineManager.setOnline(false)
      onlineManager.setOnline(true)
    })
    first.unmount()

    const now = Date.now()
    vi.spyOn(Date, 'now').mockReturnValue(now + 6 * 60 * 1000)
    const second = renderHook(() => useAllNetworkData(), { wrapper })
    await act(async () => {})

    expect(second.result.current.data?.node_properties[0].node).toBe('n1')
    expect(allDataMock).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['a 403', httpError(403, { status: 'error', message: 'Access denied' })],
    ['a snapshot_not_found 404', httpError(404, { status: 'error', message: 'gone', code: 'snapshot_not_found' })],
  ])('drop the key on %s after a success and stay without data until the next success', async (_label, failure) => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValueOnce(served('n1', H1))
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data).toBeDefined())

    setVersionState(failure)
    await pollVersionState(queryClient)
    await waitFor(() => expect(result.current.data).toBeUndefined())
    expect(result.current.isPlaceholderData).toBe(false)

    setVersionState(networkError())
    await pollVersionState(queryClient)
    expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.error).toMatchObject({ code: 'ERR_NETWORK' })
    expect(result.current.data).toBeUndefined()
    expect(result.current.isPlaceholderData).toBe(false)

    const recovered = deferred<HashKeyedResponse<AllNetworkData>>()
    allDataMock.mockReturnValueOnce(recovered.promise)
    setVersionState(makeVersionState({ content_hash: H2 }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(allDataMock).toHaveBeenCalledTimes(2))
    expect(result.current.data).toBeUndefined()
    expect(result.current.isPlaceholderData).toBe(false)

    await act(async () => recovered.resolve(served('n2', H2)))
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n2'))
  })

  it('keep the retained key on a code-less 404 like a network error', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(served('n1', H1))
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data).toBeDefined())

    setVersionState(httpError(404, { message: 'Not Found' }))
    await pollVersionState(queryClient)
    await act(async () => {})

    expect(result.current.data?.node_properties[0].node).toBe('n1')
    expect(allDataMock).toHaveBeenCalledTimes(1)
  })

  it("fall back to 'unknown' with the legacy staleTime only for a 5xx error without data, without retrying the 503", async () => {
    setVersionState(versioningUnavailable('storage'))
    allDataMock.mockResolvedValue(hashKeyed(makeAllData('n1'), { snapshotId: SNAPSHOT_ID, contentHash: '', cacheStatus: 'bypass' }))
    const queryClient = createTestQueryClient()

    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })

    await waitFor(() => expect(result.current.data).toBeDefined())
    expect(versionStateMock).toHaveBeenCalledTimes(1)
    expect(queryClient.getQueryData(networkKeys.allData(NAME, 'unknown'))).toMatchObject({ legacy: true })
  })

  it('accept a bypass hash, missing identity headers, unstored responses and the unknown key with the legacy staleTime', async () => {
    const cases: HashKeyedResponse<AllNetworkData>[] = [
      hashKeyed(makeAllData('bypass'), { snapshotId: SNAPSHOT_ID, contentHash: '', cacheStatus: 'bypass' }),
      hashKeyed(makeAllData('kill-switch')),
      hashKeyed(makeAllData('unstored'), { snapshotId: SNAPSHOT_ID, contentHash: H2, cacheStatus: 'unstored' }),
    ]
    for (const response of cases) {
      setVersionState(makeVersionState())
      allDataMock.mockReset()
      allDataMock.mockResolvedValue(response)
      const queryClient = createTestQueryClient()
      const wrapper = queryWrapper(queryClient)
      const first = renderHook(() => useAllNetworkData(), { wrapper })
      await waitFor(() => expect(first.result.current.data).toBeDefined())
      expect(queryClient.getQueryData(networkKeys.allData(NAME, H1))).toMatchObject({ legacy: true })
      first.unmount()

      const now = Date.now()
      const clock = vi.spyOn(Date, 'now').mockReturnValue(now + 6 * 60 * 1000)
      const second = renderHook(() => useAllNetworkData(), { wrapper })
      await waitFor(() => expect(allDataMock).toHaveBeenCalledTimes(2))
      second.unmount()
      clock.mockRestore()
      queryClient.clear()
    }
  })

  it('reject a present but different snapshot id with snapshot_mismatch: nothing written, no re-request, one version-state refetch', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(
      hashKeyed(makeAllData('other'), { snapshotId: 'other-snapshot', contentHash: H1, cacheStatus: 'hit' })
    )
    const queryClient = createTestQueryClient()

    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })

    await waitFor(() => expect(result.current.error).toBeInstanceOf(SnapshotMismatchError))
    expect(allDataMock).toHaveBeenCalledTimes(1)
    expect(versionStateMock).toHaveBeenCalledTimes(2)
    expect(queryClient.getQueryData(networkKeys.allData(NAME, H1))).toBeUndefined()
  })

  it('re-key a hash mismatch, refetch version-state and re-request once', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockImplementation(async () => {
      setVersionState(makeVersionState({ content_hash: H2 }))
      return served('n2', H2)
    })
    const queryClient = createTestQueryClient()

    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })

    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n2'))
    expect(allDataMock).toHaveBeenCalledTimes(2)
    expect(versionStateMock).toHaveBeenCalledTimes(2)
    expect(queryClient.getQueryData(networkKeys.allData(NAME, H2))).toMatchObject({ legacy: false })
  })

  it('resolve a fresh key during external_settling with the legacy staleTime and reconcile once on settle', async () => {
    setVersionState(makeVersionState({ external_settling: true }))
    allDataMock.mockResolvedValue(served('n2', H2))
    const queryClient = createTestQueryClient()
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')

    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })

    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n2'))
    expect(allDataMock).toHaveBeenCalledTimes(2)
    expect(queryClient.getQueryData(networkKeys.allData(NAME, H1))).toMatchObject({ legacy: true })
    expect(getSnapshotTriggerState(queryClient, NAME).fallbackMismatch).toBe(true)

    setVersionState(makeVersionState({ external_settling: true }))
    await pollVersionState(queryClient)
    await act(async () => {})
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)

    setVersionState(makeVersionState())
    await pollVersionState(queryClient)
    await waitFor(() => expect(familyInvalidations(invalidate, NAME)).toHaveLength(batfishQueryFamilies.length))
  })

  it('return a mismatched response for the current key while version-state errs and invalidate once on the first settled success', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValueOnce(served('n1', H1))
    const queryClient = createTestQueryClient()
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data).toBeDefined())

    setVersionState(versioningUnavailable('database'))
    await pollVersionState(queryClient)
    allDataMock.mockResolvedValue(served('n2', H2))
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: networkKeys.allData(NAME, H1) })
    })

    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n2'))
    expect(allDataMock).toHaveBeenCalledTimes(3)
    expect(getSnapshotTriggerState(queryClient, NAME).fallbackMismatch).toBe(true)
    invalidate.mockClear()

    setVersionState(makeVersionState({ external_settling: true }))
    await pollVersionState(queryClient)
    await act(async () => {})
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(0)

    setVersionState(makeVersionState({ content_hash: H2 }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(familyInvalidations(invalidate, NAME)).toHaveLength(batfishQueryFamilies.length))
    await act(async () => {})
    expect(familyInvalidations(invalidate, NAME)).toHaveLength(batfishQueryFamilies.length)
    expect(getSnapshotTriggerState(queryClient, NAME).fallbackMismatch).toBe(false)
  })

  it('keep the key in use as retained_key when the kill switch flips on, clear it on a flip back and never reuse an old period key', async () => {
    const H3 = hashOf('c3')
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValueOnce(served('n1', H1))
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n1'))

    await pollVersionState(queryClient)
    setVersionState(makeVersionState({ content_hash: H2, result_cache_enabled: false }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(getSnapshotTriggerState(queryClient, NAME).retainedKey).toBe(H1))
    expect(allDataMock).toHaveBeenCalledTimes(1)
    expect(result.current.data?.node_properties[0].node).toBe('n1')

    allDataMock.mockResolvedValueOnce(served('n2', H2))
    setVersionState(makeVersionState({ content_hash: H2 }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n2'))
    expect(getSnapshotTriggerState(queryClient, NAME).retainedKey).toBeUndefined()

    setVersionState(makeVersionState({ content_hash: H3, result_cache_enabled: false }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(getSnapshotTriggerState(queryClient, NAME).retainedKey).toBe(H2))
    expect(allDataMock).toHaveBeenCalledTimes(2)
  })

  it('under the kill switch show a spinner and one request under H2 after H1 -> snapshot_not_found -> re-created at H2', async () => {
    setVersionState(makeVersionState({ result_cache_enabled: false }))
    allDataMock.mockResolvedValueOnce(hashKeyed(makeAllData('n1')))
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n1'))

    setVersionState(httpError(404, { status: 'error', message: 'gone', code: 'snapshot_not_found' }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(result.current.data).toBeUndefined())

    const recreated = deferred<HashKeyedResponse<AllNetworkData>>()
    allDataMock.mockReturnValueOnce(recreated.promise)
    setVersionState(makeVersionState({ content_hash: H2, result_cache_enabled: false, snapshot_id: 'snapshot-id-2' }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(allDataMock).toHaveBeenCalledTimes(2))
    expect(result.current.data).toBeUndefined()
    expect(result.current.isPlaceholderData).toBe(false)
    expect(queryClient.getQueryState(networkKeys.allData(NAME, H2))?.fetchStatus).toBe('fetching')

    await act(async () => recreated.resolve(hashKeyed(makeAllData('n2'))))
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n2'))
    expect(allDataMock).toHaveBeenCalledTimes(2)
  })

  it('clear placeholder data when a 403 arrives while it is displayed', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValueOnce(served('n1', H1))
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data).toBeDefined())

    allDataMock.mockReturnValueOnce(new Promise(() => {}))
    setVersionState(makeVersionState({ content_hash: H2 }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(result.current.isPlaceholderData).toBe(true))

    setVersionState(httpError(403, { status: 'error', message: 'Access denied' }))
    await pollVersionState(queryClient)

    await waitFor(() => expect(result.current.data).toBeUndefined())
    expect(result.current.isPlaceholderData).toBe(false)
  })

  it('use the legacy staleTime for a retained key whose entry was fetched before the kill switch flipped on', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValue(served('n1', H1))
    const queryClient = createTestQueryClient()
    const wrapper = queryWrapper(queryClient)
    const first = renderHook(() => useAllNetworkData(), { wrapper })
    await waitFor(() => expect(first.result.current.data).toBeDefined())
    expect(queryClient.getQueryData(networkKeys.allData(NAME, H1))).toMatchObject({ legacy: false })

    setVersionState(makeVersionState({ result_cache_enabled: false }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(getSnapshotTriggerState(queryClient, NAME).retainedKey).toBe(H1))
    first.unmount()

    const now = Date.now()
    vi.spyOn(Date, 'now').mockReturnValue(now + 6 * 60 * 1000)
    renderHook(() => useAllNetworkData(), { wrapper })

    await waitFor(() => expect(allDataMock).toHaveBeenCalledTimes(2))
  })

  it('write nothing into a client whose session was reset while a hash-mismatch fetch was running', async () => {
    setVersionState(makeVersionState())
    const pending = deferred<HashKeyedResponse<AllNetworkData>>()
    allDataMock.mockResolvedValue(served('n1', H1))
    allDataMock.mockReturnValueOnce(pending.promise)
    const queryClient = createTestQueryClient()
    const { unmount } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(allDataMock).toHaveBeenCalledTimes(1))
    unmount()
    versionStateMock.mockClear()

    act(() => {
      queryClient.clear()
      resetSnapshotTriggerState(queryClient)
    })
    await act(async () => pending.resolve(served('n2', H2)))
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

    expect(queryClient.getQueryData(networkKeys.allData(NAME, H2))).toBeUndefined()
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0)
    expect(versionStateMock).not.toHaveBeenCalled()
    expect(allDataMock).toHaveBeenCalledTimes(1)
  })

  it('render H2 data during a second error interval after H2', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValueOnce(served('n1', H1))
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n1'))

    setVersionState(versioningUnavailable('database'))
    await pollVersionState(queryClient)
    allDataMock.mockResolvedValueOnce(served('n2', H2))
    setVersionState(makeVersionState({ content_hash: H2 }))
    await pollVersionState(queryClient)
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n2'))

    setVersionState(versioningUnavailable('database'))
    await pollVersionState(queryClient)

    expect(queryClient.getQueryState(snapshotVersionKeys.state(NAME))?.status).toBe('error')
    expect(result.current.data?.node_properties[0].node).toBe('n2')
    expect(allDataMock).toHaveBeenCalledTimes(2)
  })

  it("fall back to 'unknown' for a code-less 404 without data", async () => {
    setVersionState(httpError(404, { message: 'Not Found' }))
    allDataMock.mockResolvedValue(hashKeyed(makeAllData('n1')))
    const queryClient = createTestQueryClient()

    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })

    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n1'))
    expect(queryClient.getQueryData(networkKeys.allData(NAME, 'unknown'))).toMatchObject({ legacy: true })
  })

  it('keep the existing data of the key when a mismatch persists while external_settling', async () => {
    setVersionState(makeVersionState())
    allDataMock.mockResolvedValueOnce(served('n1', H1))
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useAllNetworkData(), { wrapper: queryWrapper(queryClient) })
    await waitFor(() => expect(result.current.data?.node_properties[0].node).toBe('n1'))

    setVersionState(makeVersionState({ external_settling: true }))
    allDataMock.mockResolvedValue(served('n2', H2))
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: networkKeys.allData(NAME, H1) })
    })
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

    expect(allDataMock).toHaveBeenCalledTimes(3)
    expect(result.current.data?.node_properties[0].node).toBe('n1')
    expect(queryClient.getQueryData(networkKeys.allData(NAME, H1))).toMatchObject({ legacy: false })
    expect(queryClient.getQueryData(networkKeys.allData(NAME, H2))).toMatchObject({ legacy: false })
    expect(getSnapshotTriggerState(queryClient, NAME).fallbackMismatch).toBe(false)
  })

  it('never retry an HTTP response of version-state', () => {
    expect(retryVersionState(0, versioningUnavailable('database'))).toBe(false)
    expect(retryVersionState(0, httpError(500))).toBe(false)
    expect(retryVersionState(0, networkError())).toBe(true)
    expect(retryVersionState(2, networkError())).toBe(false)
  })
})
