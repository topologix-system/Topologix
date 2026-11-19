/**
 * TypeScript type definitions for Cytoscape.js graph visualization
 * Defines node and edge data structures for network topology rendering
 */
import type cytoscape from 'cytoscape'

/**
 * Cytoscape node data structure for network devices
 */
export interface CytoscapeNode {
  data: {
    id: string
    label: string
    type?: string
    platform?: string
    hostname?: string
    ip_addresses?: string[]
    health_status?: string
    [key: string]: any
  }
  position?: {
    x: number
    y: number
  }
  classes?: string
  [key: string]: any
}

/**
 * Cytoscape edge data structure for network connections
 */
export interface CytoscapeEdge {
  data: {
    id: string
    source: string
    target: string
    label?: string
    protocol?: string
    bandwidth?: number
    source_port?: string
    target_port?: string
    [key: string]: any
  }
  classes?: string
  [key: string]: any
}

/**
 * Complete Cytoscape graph data structure
 * Contains both nodes (devices) and edges (connections) for rendering
 */
export interface CytoscapeElements {
  nodes: CytoscapeNode[]
  edges: CytoscapeEdge[]
}

/**
 * Supported Cytoscape layout algorithms
 */
export type LayoutName = 'cola' | 'cola-spaced' | 'cose' | 'cose-bilkent' | 'dagre' | 'circle' | 'grid' | 'random' | 'breadthfirst'

/**
 * Network topology layer types for filtering graph edges
 * Allows users to show/hide specific protocol layers in topology view
 */
export type LayerType = 'physical' | 'layer1' | 'layer3' | 'ospf' | 'bgp' | 'vxlan' | 'eigrp' | 'isis' | 'ipsec'

export type CytoscapeLayoutOptions = { name: string } & Record<string, any>
export type CytoscapeStylesheet = NonNullable<cytoscape.CytoscapeOptions['style']>

/**
 * Configuration options for Cytoscape.js graph instance
 * Overrides default settings for container, elements, style, layout, and zoom
 */
export interface CytoscapeConfig {
  container?: HTMLElement | null
  elements?: cytoscape.ElementDefinition[]
  style?: CytoscapeStylesheet
  layout?: CytoscapeLayoutOptions
  minZoom?: number
  maxZoom?: number
  wheelSensitivity?: number
}
