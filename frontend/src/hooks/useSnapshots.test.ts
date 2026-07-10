import { createElement, type ReactNode } from 'react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { snapshotAPI } from '../services/api'
import {
  configFileContentQueryOptions,
  snapshotKeys,
  useUpdateSnapshotFileFormat,
} from './useSnapshots'

describe('config file content query behavior', () => {
  it('does not background-refetch open editor content on reconnect or staleness', () => {
    expect(configFileContentQueryOptions).toEqual({
      staleTime: Infinity,
      refetchOnReconnect: false,
      refetchOnWindowFocus: false,
    })
  })

  it('keeps content queries outside the files-list key prefix', () => {
    const filesKey = snapshotKeys.files('snapshot-a')
    const contentKey = snapshotKeys.fileContent('snapshot-a', 'router.cfg')

    expect(contentKey.slice(0, filesKey.length)).not.toEqual(filesKey)
  })

  it('marks active content stale without refetching after a format override', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const contentKey = snapshotKeys.fileContent('snapshot-a', 'router.cfg')
    const contentQuery = vi.fn().mockResolvedValue({
      content: 'hostname router\ninterface Ethernet0\n',
      sha256: 'a'.repeat(64),
      size_bytes: 36,
    })
    const updateFileFormat = vi.spyOn(snapshotAPI, 'updateFileFormat').mockResolvedValue({
      name: 'router.cfg',
      size_bytes: 36,
      modified_at: '2026-01-01T00:00:00Z',
      configuration_format_override: 'ios',
      requires_reinitialize: false,
    })
    const wrapper = ({ children }: { children: ReactNode }) =>
      createElement(QueryClientProvider, { client: queryClient }, children)

    const { result } = renderHook(
      () => ({
        content: useQuery({
          queryKey: contentKey,
          queryFn: contentQuery,
          staleTime: Infinity,
        }),
        formatMutation: useUpdateSnapshotFileFormat(),
      }),
      { wrapper }
    )

    await waitFor(() => expect(result.current.content.isSuccess).toBe(true))
    expect(contentQuery).toHaveBeenCalledTimes(1)

    act(() => {
      result.current.formatMutation.mutate({
        name: 'snapshot-a',
        filename: 'router.cfg',
        configurationFormatOverride: 'ios',
      })
    })

    await waitFor(() => expect(result.current.formatMutation.isSuccess).toBe(true))
    expect(updateFileFormat).toHaveBeenCalledWith('snapshot-a', 'router.cfg', 'ios')
    expect(queryClient.getQueryState(contentKey)?.isInvalidated).toBe(true)
    expect(contentQuery).toHaveBeenCalledTimes(1)
  })
})
