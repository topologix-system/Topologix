/**
 * Active snapshot state management with Zustand
 * - Persists currently active snapshot name to localStorage
 * - Used to track which Batfish snapshot is currently loaded
 * - Synchronized with backend snapshot activation via snapshotAPI
 * - Simple string persistence with Zustand persist middleware
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

/**
 * Snapshot store state and actions
 * Tracks the currently active snapshot for Batfish analysis
 */
interface SnapshotState {
  currentSnapshotName: string | null
  setCurrentSnapshotName: (name: string | null) => void
}

/**
 * Zustand snapshot store with localStorage persistence
 * Maintains active snapshot name across browser sessions
 * Used by Header dropdown and SnapshotManagement page
 */
export const useSnapshotStore = create<SnapshotState>()(
  persist(
    (set) => ({
      currentSnapshotName: null,
      setCurrentSnapshotName: (name) => set({ currentSnapshotName: name }),
    }),
    {
      name: 'topologix-snapshot-storage',
    }
  )
)