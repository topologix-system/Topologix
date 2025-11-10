/**
 * Cytoscape.js layout configurations for network topology visualization
 * - Defines layout algorithms (cola, cose, grid, circle, etc.) with optimized parameters
 * - Handles large graph performance with node/edge limits and smart spacing
 * - Provides layout switching for different network sizes and topologies
 * - Force-directed layouts for organic clustering, grid/circle for ordered views
 */
import type cytoscape from 'cytoscape'
import type { LayoutName } from './types'

/**
 * Pre-configured layout settings for each supported algorithm
 * Maps layout names to their optimized Cytoscape.js configuration
 * Tuned for network topology visualization with appropriate spacing and animation
 */
export const layoutConfigs: Record<LayoutName, cytoscape.LayoutOptions> = {
  cola: {
    name: 'cola',
    animate: true,
    animationDuration: 500,
    nodeSpacing: 80,
    edgeLength: 100,
    fit: true,
    padding: 50,
    randomize: false,
  },

  'cola-spaced': {
    name: 'cola',
    animate: true,
    animationDuration: 500,
    nodeSpacing: 150,
    edgeLength: 150,
    fit: true,
    padding: 50,
    randomize: false,
  },

  cose: {
    name: 'cose',
    animate: true,
    animationDuration: 500,
    nodeRepulsion: 8000,
    nodeOverlap: 20,
    idealEdgeLength: 100,
    edgeElasticity: 100,
    nestingFactor: 5,
    gravity: 80,
    numIter: 1000,
    initialTemp: 200,
    coolingFactor: 0.95,
    minTemp: 1.0,
    fit: true,
    padding: 50,
  },

  'cose-bilkent': {
    name: 'cose-bilkent',
    animate: true,
    animationDuration: 500,
    nodeRepulsion: 4500,
    idealEdgeLength: 100,
    edgeElasticity: 0.45,
    nestingFactor: 0.1,
    gravity: 0.25,
    numIter: 2500,
    tile: true,
    tilingPaddingVertical: 10,
    tilingPaddingHorizontal: 10,
    gravityRangeCompound: 1.5,
    gravityCompound: 1.0,
    gravityRange: 3.8,
    initialEnergyOnIncremental: 0.5,
    fit: true,
    padding: 50,
  },

  dagre: {
    name: 'dagre',
    animate: true,
    animationDuration: 500,
    rankDir: 'TB',
    nodeSep: 80,
    edgeSep: 10,
    rankSep: 100,
    fit: true,
    padding: 50,
  },

  circle: {
    name: 'circle',
    animate: true,
    animationDuration: 500,
    fit: true,
    padding: 50,
    avoidOverlap: true,
    radius: undefined,
    startAngle: (3 / 2) * Math.PI,
    sweep: undefined,
    clockwise: true,
    sort: undefined,
  },

  grid: {
    name: 'grid',
    animate: true,
    animationDuration: 500,
    fit: true,
    padding: 50,
    avoidOverlap: true,
    avoidOverlapPadding: 10,
    condense: false,
    rows: undefined,
    cols: undefined,
    position: undefined,
    sort: undefined,
  },

  random: {
    name: 'random',
    animate: false,
    fit: true,
    padding: 50,
  },

  breadthfirst: {
    name: 'breadthfirst',
    animate: true,
    animationDuration: 500,
    directed: false,
    padding: 50,
    fit: true,
    avoidOverlap: true,
    nodeDimensionsIncludeLabels: true,
    spacingFactor: 1.75,
    grid: false,
    circle: false,
    maximal: false,
  },
}

/**
 * Get layout configuration by name
 * Returns the specified layout config or defaults to 'cola' if not found
 * Used by topology hooks to apply user-selected layout algorithms
 * @param layoutName - Name of the layout algorithm to retrieve
 * @returns Cytoscape layout configuration object
 */
export function getLayoutConfig(layoutName: LayoutName): cytoscape.LayoutOptions {
  return layoutConfigs[layoutName] || layoutConfigs.cola
}