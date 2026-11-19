/**
 * Active snapshot state management with Zustand
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

/**
 * Snapshot store state and actions
 * Tracks the currently active snapshot for Batfish analysis
 */
interface SnapshotState {
  currentSnapshotName: string | null
  isSnapshotActivationInProgress: boolean
  activatingSnapshotName: string | null
  setCurrentSnapshotName: (name: string | null) => void
  setSnapshotActivationState: (isInProgress: boolean, name?: string | null) => void
}

/**
 * Zustand snapshot store with localStorage persistence
 * Maintains active snapshot name across browser sessions
 */
export const useSnapshotStore = create<SnapshotState>()(
  persist(
    (set) => ({
      currentSnapshotName: null,
      isSnapshotActivationInProgress: false,
      activatingSnapshotName: null,
      setCurrentSnapshotName: (name) => set({ currentSnapshotName: name }),
      setSnapshotActivationState: (isInProgress, name = null) =>
        set({
          isSnapshotActivationInProgress: isInProgress,
          activatingSnapshotName: isInProgress ? name : null,
        }),
    }),
    {
      name: 'topologix-snapshot-storage',
      partialize: (state) => ({ currentSnapshotName: state.currentSnapshotName }),
    }
  )
)
