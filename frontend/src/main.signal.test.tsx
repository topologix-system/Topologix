import { act, render } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { describe, expect, it, vi } from 'vitest'

import { createTestQueryClient, familyInvalidations } from './__tests__/versioning'
import { batfishQueryFamilies } from './hooks/useSnapshots'
import { SnapshotStorageSync } from './main'
import { useSnapshotStore } from './store'

vi.mock('react-dom/client', () => ({
  default: { createRoot: () => ({ render: vi.fn() }) },
}))

function renderSync() {
  const queryClient = createTestQueryClient()
  const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
  render(
    <QueryClientProvider client={queryClient}>
      <SnapshotStorageSync />
    </QueryClientProvider>
  )
  return { queryClient, invalidate }
}

const settle = () => act(() => new Promise<void>((resolve) => setTimeout(resolve, 20)))

describe('SnapshotStorageSync', () => {
  it('applies a topologix:invalidate clear signal to every family of the named snapshot without echoing it', async () => {
    const { invalidate } = renderSync()

    act(() => {
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: 'topologix:invalidate',
          newValue: JSON.stringify({ name: 'snap-a', ts: 1, reason: 'clear' }),
        })
      )
    })
    await settle()

    expect(familyInvalidations(invalidate, 'snap-a')).toHaveLength(batfishQueryFamilies.length)
    expect(localStorage.getItem('topologix:invalidate')).toBeNull()
  })

  it('refetches the network queries on a snapshot storage event for the same snapshot', async () => {
    useSnapshotStore.setState({ currentSnapshotName: 'snap-a' })
    const { invalidate } = renderSync()

    act(() => {
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: 'topologix-snapshot-storage',
          newValue: JSON.stringify({ state: { currentSnapshotName: 'snap-a' } }),
        })
      )
    })
    await settle()

    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['network'], refetchType: 'active' })
  })
})
