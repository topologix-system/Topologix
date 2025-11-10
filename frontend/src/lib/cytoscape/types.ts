/**
 * TypeScript type definitions for Cytoscape.js graph visualization
 * Defines node and edge data structures for network topology rendering
 */
import type cytoscape from 'cytoscape'

/**
 * Cytoscape node data structure for network devices
 * Represents routers, switches, firewalls, and other network elements
 * Used by TopologyViewer to render device nodes in the graph
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
  classes?: string
}

/**
 * Cytoscape edge data structure for network connections
 * Represents physical cables, layer 3 links, and protocol adjacencies (OSPF, BGP, etc.)
 * Supports multiple protocols and connection types with source/target port information
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
 * - cola: Force-directed with constraints (default, best for most networks)
 * - cola-spaced: Force-directed with increased node spacing for better visibility
 * - cose: Compound Spring Embedder (good for clustered networks)
 * - cose-bilkent: Advanced force-directed (best for large graphs)
 * - dagre: Hierarchical directed acyclic graph layout
 * - circle: Circular layout
 * - grid: Grid-based layout
 * - random: Random positioning
 * - breadthfirst: Tree-based hierarchical layout
 */
export type LayoutName = 'cola' | 'cola-spaced' | 'cose' | 'cose-bilkent' | 'dagre' | 'circle' | 'grid' | 'random' | 'breadthfirst'

/**
 * Network topology layer types for filtering graph edges
 * Allows users to show/hide specific protocol layers in topology view
 */
export type LayerType = 'physical' | 'layer1' | 'layer3' | 'ospf' | 'bgp' | 'vxlan' | 'eigrp' | 'isis' | 'ipsec'

/**
 * Configuration options for Cytoscape.js graph instance
 * Overrides default settings for container, elements, style, layout, and zoom
 */
export interface CytoscapeConfig {
  container?: HTMLElement | null
  elements?: cytoscape.ElementDefinition[]
  style?: cytoscape.Stylesheet[]
  layout?: cytoscape.LayoutOptions
  minZoom?: number
  maxZoom?: number
  wheelSensitivity?: number
}