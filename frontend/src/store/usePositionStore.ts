/**
 * Node position persistence across snapshot switches
 * - Stores graph node positions per snapshot in nested Record<snapshot, Record<nodeId, position>>
 * - Implements debounced saves (300ms) to prevent excessive localStorage writes during dragging
 * - Maintains position history for all loaded snapshots during browser session
 * - Automatically restores saved positions when switching between snapshots
 * - Limits stored snapshots to prevent unbounded localStorage growth
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { logger } from '../utils/logger'

// Maximum number of snapshot positions to keep in storage to prevent memory bloat
const MAX_SNAPSHOTS = 50

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
        logger.log(`[PositionStore] Saving positions for snapshot: ${snapshotName}, nodes: ${Object.keys(positions).length}`)
        set((state) => {
          const newPositions = {
            ...state.positions,
            [snapshotName]: positions,
          }

          // Enforce MAX_SNAPSHOTS limit to prevent unbounded localStorage growth
          const snapshotKeys = Object.keys(newPositions)
          if (snapshotKeys.length > MAX_SNAPSHOTS) {
            // Remove oldest entries (first keys in object) to stay within limit
            const keysToRemove = snapshotKeys.slice(0, snapshotKeys.length - MAX_SNAPSHOTS)
            for (const key of keysToRemove) {
              delete newPositions[key]
            }
            logger.log(`[PositionStore] Removed ${keysToRemove.length} old snapshot positions to stay within limit`)
          }

          return { positions: newPositions }
        })
      },

      getPositions: (snapshotName) => {
        const positions = get().positions[snapshotName]
        if (positions) {
          logger.log(`[PositionStore] Retrieved ${Object.keys(positions).length} positions for snapshot: ${snapshotName}`)
        } else {
          logger.log(`[PositionStore] No saved positions found for snapshot: ${snapshotName}`)
        }
        return positions
      },

      clearPositions: (snapshotName) => {
        logger.log(`[PositionStore] Clearing positions for snapshot: ${snapshotName}`)
        set((state) => {
          const newPositions = { ...state.positions }
          delete newPositions[snapshotName]
          return { positions: newPositions }
        })
      },

      clearAllPositions: () => {
        logger.log('[PositionStore] Clearing all saved positions')
        set({ positions: {} })
      },
    }),
    {
      name: 'topologix-position-storage',
    }
  )
)
