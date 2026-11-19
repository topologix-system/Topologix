import { createElement, type ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosError, AxiosHeaders, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios'

import { batfishQueryFamilies } from '../hooks/useSnapshots'
import type { AllNetworkData, HashKeyedResponse, SnapshotVersion, SnapshotVersionState } from '../types'

export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, retryDelay: 0, staleTime: 5 * 60 * 1000, gcTime: 10 * 60 * 1000, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  })
}

export function queryWrapper(queryClient: QueryClient) {
  return ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client: queryClient }, children)
}

export function httpError(status: number, data: unknown = {}): AxiosError {
  const config = { headers: new AxiosHeaders() } as InternalAxiosRequestConfig
  const response: AxiosResponse = { status, statusText: String(status), headers: {}, config, data }
  return new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_RESPONSE', config, {}, response)
}

export function networkError(): AxiosError {
  return new AxiosError('Network Error', AxiosError.ERR_NETWORK)
}

export function versioningUnavailable(reason: string): AxiosError {
  return httpError(503, {
    status: 'error',
    message: 'Snapshot versioning is unavailable',
    code: 'versioning_unavailable',
    details: { reason },
  })
}

export function hashOf(label: string): string {
  return label.padEnd(64, '0')
}

export function makeVersion(overrides: Partial<SnapshotVersion> = {}): SnapshotVersion {
  return {
    version_id: 'version-1',
    seq: 1,
    message: 'Initial state',
    kind: 'baseline',
    created_at: '2026-11-11T10:02:00+00:00',
    author: null,
    file_count: 2,
    total_bytes: 120,
    parent: null,
    restored_from: null,
    ...overrides,
  }
}

export function makeVersionState(overrides: Partial<SnapshotVersionState> = {}): SnapshotVersionState {
  return {
    snapshot_id: 'snapshot-id-1',
    content_hash: hashOf('h1'),
    loaded_content_hash: null,
    loaded_batfish_version: null,
    loaded_live: false,
    result_cache_enabled: true,
    head: makeVersion(),
    uncommitted: false,
    pending_external: false,
    external_settling: false,
    restored_from: null,
    ...overrides,
  }
}

export function makeAllData(label: string, contentHash: string | null = null): AllNetworkData {
  return {
    node_properties: [{ node: label }],
    snapshot_version: { content_hash: contentHash, live: false, live_hash: null },
  } as unknown as AllNetworkData
}

export function hashKeyed<T>(
  data: T,
  identity: { snapshotId?: string; contentHash?: string; cacheStatus?: string } = {}
): HashKeyedResponse<T> {
  return { data, identity }
}

export function familyInvalidations(
  invalidate: { mock: { calls: unknown[][] } },
  name: string,
  family?: string
): unknown[][] {
  return invalidate.mock.calls.filter((call) => {
    const key = (call[0] as { queryKey?: unknown[] } | undefined)?.queryKey
    return (
      Array.isArray(key) &&
      key.length === 2 &&
      key[1] === name &&
      batfishQueryFamilies.some(([batfishFamily]) => batfishFamily === key[0]) &&
      (family === undefined || key[0] === family)
    )
  })
}
