/**
 * Node position persistence across snapshot switches
 * - Stores graph node positions per snapshot in nested Record<snapshot, Record<nodeId, position>>
 * - Implements debounced saves (300ms) to prevent excessive localStorage writes during dragging
 * - Maintains position history for all loaded snapshots during browser session
 * - Automatically restores saved positions when switching between snapshots
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

/**
 * Node position coordinates for graph layout
 * X and Y coordinates for Cytoscape node positioning
 */
export interface NodePosition {
  x: number
  y: number
}

/**
 * Node position mapping for a single snapshot
 * Maps node IDs to their X/Y coordinates
 */
export type SnapshotPositions = Record<string, NodePosition>

/**
 * Position store state and actions
 * Manages graph node positions per snapshot
 */
interface PositionState {
  positions: Record<string, SnapshotPositions>

  savePositions: (snapshotName: string, positions: SnapshotPositions) => void

  getPositions: (snapshotName: string) => SnapshotPositions | undefined

  clearPositions: (snapshotName: string) => void

  clearAllPositions: () => void
}

/**
 * Zustand position store with localStorage persistence
 * Saves node positions per snapshot for layout consistency
 * Used by TopologyViewer to restore user-arranged graphs
 */
export const usePositionStore = create<PositionState>()(
  persist(
    (set, get) => ({
      positions: {},

      savePositions: (snapshotName, positions) => {
        console.log(`[PositionStore] Saving positions for snapshot: ${snapshotName}, nodes: ${Object.keys(positions).length}`)
        set((state) => ({
          positions: {
            ...state.positions,
            [snapshotName]: positions,
          },
        }))
      },

      getPositions: (snapshotName) => {
        const positions = get().positions[snapshotName]
        if (positions) {
          console.log(`[PositionStore] Retrieved ${Object.keys(positions).length} positions for snapshot: ${snapshotName}`)
        } else {
          console.log(`[PositionStore] No saved positions found for snapshot: ${snapshotName}`)
        }
        return positions
      },

      clearPositions: (snapshotName) => {
        console.log(`[PositionStore] Clearing positions for snapshot: ${snapshotName}`)
        set((state) => {
          const newPositions = { ...state.positions }
          delete newPositions[snapshotName]
          return { positions: newPositions }
        })
      },

      clearAllPositions: () => {
        console.log('[PositionStore] Clearing all saved positions')
        set({ positions: {} })
      },
    }),
    {
      name: 'topologix-position-storage',
    }
  )
)
