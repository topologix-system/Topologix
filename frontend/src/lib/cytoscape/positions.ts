import type { ElementDefinition } from 'cytoscape'

export interface GraphPosition {
  x: number
  y: number
}

export type GraphPositions = Record<string, GraphPosition>

export type PositionValidationStatus = 'missing' | 'valid' | 'partial' | 'invalid'

export interface PositionValidationResult {
  status: PositionValidationStatus
  reason: string
  nodeCount: number
  savedCount: number
  validCount: number
  coverage: number
  validPositions: GraphPositions
  missingNodeIds: string[]
  invalidNodeIds: string[]
  extraNodeIds: string[]
  spread: {
    width: number
    height: number
  }
}

export interface PositionSaveValidationResult {
  valid: boolean
  reason: string
  nodeCount: number
  validCount: number
  spread: {
    width: number
    height: number
  }
}

interface PositionValidationOptions {
  partialCoverageThreshold?: number
  minSpread?: number
}

interface FallbackPositionOptions {
  spacing?: number
}

interface CytoscapeLikeElement {
  data?: {
    id?: string
    source?: string
    target?: string
    [key: string]: unknown
  }
  [key: string]: unknown
}

const DEFAULT_PARTIAL_COVERAGE_THRESHOLD = 0.5
const DEFAULT_FALLBACK_SPACING = 180

function isFinitePosition(position: unknown): position is GraphPosition {
  if (!position || typeof position !== 'object') return false

  const candidate = position as GraphPosition
  return Number.isFinite(candidate.x) && Number.isFinite(candidate.y)
}

function calculateMinimumSpread(nodeCount: number, override?: number): number {
  if (typeof override === 'number') return override
  if (nodeCount <= 1) return 0
  return Math.min(200, Math.max(40, nodeCount * 20))
}

function calculateSpread(positions: GraphPositions): { width: number; height: number } {
  const values = Object.values(positions)
  if (values.length === 0) {
    return { width: 0, height: 0 }
  }

  const xs = values.map((position) => position.x)
  const ys = values.map((position) => position.y)

  return {
    width: Math.max(...xs) - Math.min(...xs),
    height: Math.max(...ys) - Math.min(...ys),
  }
}

function isCollapsedSpread(
  spread: { width: number; height: number },
  nodeCount: number,
  minSpreadOverride?: number
): boolean {
  if (nodeCount <= 1) return false

  const minSpread = calculateMinimumSpread(nodeCount, minSpreadOverride)
  return spread.width < minSpread && spread.height < minSpread
}

export function validateSavedPositions(
  nodeIds: string[],
  savedPositions?: GraphPositions | null,
  options: PositionValidationOptions = {}
): PositionValidationResult {
  const uniqueNodeIds = Array.from(new Set(nodeIds.filter(Boolean)))
  const savedIds = savedPositions ? Object.keys(savedPositions) : []
  const nodeIdSet = new Set(uniqueNodeIds)
  const extraNodeIds = savedIds.filter((nodeId) => !nodeIdSet.has(nodeId))

  if (uniqueNodeIds.length === 0) {
    return {
      status: 'valid',
      reason: 'no-current-nodes',
      nodeCount: 0,
      savedCount: savedIds.length,
      validCount: 0,
      coverage: 1,
      validPositions: {},
      missingNodeIds: [],
      invalidNodeIds: [],
      extraNodeIds,
      spread: { width: 0, height: 0 },
    }
  }

  if (!savedPositions || savedIds.length === 0) {
    return {
      status: 'missing',
      reason: 'no-saved-positions',
      nodeCount: uniqueNodeIds.length,
      savedCount: 0,
      validCount: 0,
      coverage: 0,
      validPositions: {},
      missingNodeIds: uniqueNodeIds,
      invalidNodeIds: [],
      extraNodeIds,
      spread: { width: 0, height: 0 },
    }
  }

  const validPositions: GraphPositions = {}
  const missingNodeIds: string[] = []
  const invalidNodeIds: string[] = []

  for (const nodeId of uniqueNodeIds) {
    const position = savedPositions[nodeId]

    if (!position) {
      missingNodeIds.push(nodeId)
      continue
    }

    if (!isFinitePosition(position)) {
      invalidNodeIds.push(nodeId)
      continue
    }

    validPositions[nodeId] = { x: position.x, y: position.y }
  }

  const validCount = Object.keys(validPositions).length
  const coverage = validCount / uniqueNodeIds.length
  const spread = calculateSpread(validPositions)

  if (validCount === 0) {
    return {
      status: 'invalid',
      reason: 'no-valid-current-node-positions',
      nodeCount: uniqueNodeIds.length,
      savedCount: savedIds.length,
      validCount,
      coverage,
      validPositions,
      missingNodeIds,
      invalidNodeIds,
      extraNodeIds,
      spread,
    }
  }

  if (isCollapsedSpread(spread, validCount, options.minSpread)) {
    return {
      status: 'invalid',
      reason: 'saved-positions-collapsed',
      nodeCount: uniqueNodeIds.length,
      savedCount: savedIds.length,
      validCount,
      coverage,
      validPositions,
      missingNodeIds,
      invalidNodeIds,
      extraNodeIds,
      spread,
    }
  }

  if (validCount === uniqueNodeIds.length && invalidNodeIds.length === 0) {
    return {
      status: 'valid',
      reason: 'all-current-node-positions-valid',
      nodeCount: uniqueNodeIds.length,
      savedCount: savedIds.length,
      validCount,
      coverage,
      validPositions,
      missingNodeIds,
      invalidNodeIds,
      extraNodeIds,
      spread,
    }
  }

  const partialCoverageThreshold = options.partialCoverageThreshold ?? DEFAULT_PARTIAL_COVERAGE_THRESHOLD
  if (coverage >= partialCoverageThreshold) {
    return {
      status: 'partial',
      reason: 'partial-current-node-positions-valid',
      nodeCount: uniqueNodeIds.length,
      savedCount: savedIds.length,
      validCount,
      coverage,
      validPositions,
      missingNodeIds,
      invalidNodeIds,
      extraNodeIds,
      spread,
    }
  }

  return {
    status: 'invalid',
    reason: 'insufficient-current-node-position-coverage',
    nodeCount: uniqueNodeIds.length,
    savedCount: savedIds.length,
    validCount,
    coverage,
    validPositions,
    missingNodeIds,
    invalidNodeIds,
    extraNodeIds,
    spread,
  }
}

export function buildFallbackPositions(
  nodeIds: string[],
  options: FallbackPositionOptions = {}
): GraphPositions {
  const uniqueNodeIds = Array.from(new Set(nodeIds.filter(Boolean))).sort()
  const positions: GraphPositions = {}

  if (uniqueNodeIds.length === 0) {
    return positions
  }

  const spacing = options.spacing ?? DEFAULT_FALLBACK_SPACING
  const columns = Math.ceil(Math.sqrt(uniqueNodeIds.length))
  const rows = Math.ceil(uniqueNodeIds.length / columns)

  uniqueNodeIds.forEach((nodeId, index) => {
    const column = index % columns
    const row = Math.floor(index / columns)

    positions[nodeId] = {
      x: (column - (columns - 1) / 2) * spacing,
      y: (row - (rows - 1) / 2) * spacing,
    }
  })

  return positions
}

export function mergePositions(
  nodeIds: string[],
  primaryPositions: GraphPositions,
  fallbackPositions: GraphPositions
): GraphPositions {
  const mergedPositions: GraphPositions = {}

  for (const nodeId of Array.from(new Set(nodeIds.filter(Boolean)))) {
    const primaryPosition = primaryPositions[nodeId]
    const fallbackPosition = fallbackPositions[nodeId]

    if (isFinitePosition(primaryPosition)) {
      mergedPositions[nodeId] = { x: primaryPosition.x, y: primaryPosition.y }
    } else if (isFinitePosition(fallbackPosition)) {
      mergedPositions[nodeId] = { x: fallbackPosition.x, y: fallbackPosition.y }
    }
  }

  return mergedPositions
}

export function applyPositionsToElements(
  elements: CytoscapeLikeElement[],
  positions: GraphPositions
): ElementDefinition[] {
  return elements.map((element) => {
    const nodeId = element.data?.id
    const isEdge = Boolean(element.data?.source || element.data?.target)

    if (!nodeId || isEdge) {
      return element as ElementDefinition
    }

    const position = positions[nodeId]
    if (!isFinitePosition(position)) {
      return element as ElementDefinition
    }

    return {
      ...(element as ElementDefinition),
      position: { x: position.x, y: position.y },
    }
  })
}

export function validatePositionsForSave(
  positions: GraphPositions,
  expectedNodeCount?: number,
  options: PositionValidationOptions = {}
): PositionSaveValidationResult {
  const validPositions: GraphPositions = {}

  for (const [nodeId, position] of Object.entries(positions)) {
    if (isFinitePosition(position)) {
      validPositions[nodeId] = { x: position.x, y: position.y }
    }
  }

  const validCount = Object.keys(validPositions).length
  const nodeCount = expectedNodeCount ?? validCount
  const spread = calculateSpread(validPositions)

  if (nodeCount > 0 && validCount < nodeCount) {
    return {
      valid: false,
      reason: 'incomplete-node-position-set',
      nodeCount,
      validCount,
      spread,
    }
  }

  if (validCount === 0 && nodeCount > 0) {
    return {
      valid: false,
      reason: 'no-valid-node-positions',
      nodeCount,
      validCount,
      spread,
    }
  }

  if (isCollapsedSpread(spread, validCount, options.minSpread)) {
    return {
      valid: false,
      reason: 'node-positions-collapsed',
      nodeCount,
      validCount,
      spread,
    }
  }

  return {
    valid: true,
    reason: 'node-positions-valid',
    nodeCount,
    validCount,
    spread,
  }
}
