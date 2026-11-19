import type { QueryClient } from '@tanstack/react-query'

export const INVALIDATION_SIGNAL_KEY = 'topologix:invalidate'

export interface LoadedPair {
  hash: string
  batfishVersion: string | null
}

/**
 * Per-(QueryClient, snapshot name) bookkeeping of the version-state triggers
 */
export interface SnapshotTriggerState {
  workingHash: string | null | undefined
  loadedPair: LoadedPair | undefined
  fallbackMismatch: boolean
  suppressToken: number | null
  noData: boolean
  headVersionId: string | null | undefined
  workingDiffHash: string | null | undefined
  retainedKey: string | null | undefined
  lastTrueModeHash: string | null | undefined
  invalidateAll: boolean
  firstKeyAfterClear: string | null | undefined
  lastEvaluated: string | undefined
  observedKey: string | undefined
}

const triggerStates = new WeakMap<QueryClient, Map<string, SnapshotTriggerState>>()
const clientGenerations = new WeakMap<QueryClient, number>()

function createTriggerState(): SnapshotTriggerState {
  return {
    workingHash: undefined,
    loadedPair: undefined,
    fallbackMismatch: false,
    suppressToken: null,
    noData: false,
    headVersionId: undefined,
    workingDiffHash: undefined,
    retainedKey: undefined,
    lastTrueModeHash: undefined,
    invalidateAll: false,
    firstKeyAfterClear: undefined,
    lastEvaluated: undefined,
    observedKey: undefined,
  }
}

export function getSnapshotTriggerState(queryClient: QueryClient, name: string): SnapshotTriggerState {
  let states = triggerStates.get(queryClient)
  if (!states) {
    states = new Map()
    triggerStates.set(queryClient, states)
  }
  let state = states.get(name)
  if (!state) {
    state = createTriggerState()
    states.set(name, state)
  }
  return state
}

/**
 * Session generation of a QueryClient; resetSnapshotTriggerState increments it
 */
export function getClientGeneration(queryClient: QueryClient): number {
  return clientGenerations.get(queryClient) ?? 0
}

export function resetSnapshotTriggerState(queryClient: QueryClient): void {
  triggerStates.delete(queryClient)
  clientGenerations.set(queryClient, getClientGeneration(queryClient) + 1)
}
