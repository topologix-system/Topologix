/**
 * Graph data conversion utilities for Cytoscape.js visualization
 * - Converts Batfish network analysis data to Cytoscape-compatible graph format
 * - Handles multiple edge types: physical, layer3, OSPF, BGP, VXLAN, EIGRP, IS-IS, BFD, IPsec
 * - Implements edge deduplication and layer-based filtering logic
 * - Core utility for TopologyViewer component graph rendering
 */
import type { NodeProperties, PhysicalEdge, Layer1Edge, Layer3Edge, OSPFEdge, BGPEdge, VXLANEdge, EIGRPEdge, ISISEdge, IPsecEdge } from '../../types'
import type { CytoscapeElements, CytoscapeNode, CytoscapeEdge, LayerType } from './types'
import { logger } from '../../utils/logger'

/**
 * Generate stable edge ID from edge properties
 * Uses source-target-type-ports composite key for uniqueness
 */
function generateStableEdgeId(
  source: string,
  target: string,
  edgeType: string,
  sourcePort?: string,
  targetPort?: string
): string {
  const portSuffix = sourcePort && targetPort
    ? `-${sourcePort}-${targetPort}`
    : sourcePort
    ? `-${sourcePort}`
    : targetPort
    ? `-${targetPort}`
    : ''

  return `edge-${edgeType}-${source}-${target}${portSuffix}`
}

/**
 * Convert Batfish node properties to Cytoscape node elements
 * Transforms device information into graph-renderable format with proper labeling
 * Filters out invalid nodes and logs warnings for debugging
 * @param nodes - Array of Batfish node property objects
 * @returns Array of Cytoscape-compatible node elements
 */
export function convertNodesToElements(nodes: NodeProperties[]): CytoscapeNode[] {
  if (!nodes || !Array.isArray(nodes)) {
    logger.warn('[cytoscape/utils] Invalid nodes array provided to convertNodesToElements')
    return []
  }

  return nodes
    .filter(node => {
      if (!node || !node.node) {
        logger.warn('[cytoscape/utils] Skipping invalid node:', node)
        return false
      }
      return true
    })
    .map((node) => ({
      data: {
        id: node.node,
        label: node.hostname || node.node,
        type: determineNodeType(node.vendor || ''),
        platform: node.vendor || 'unknown',
        hostname: node.hostname,
        configuration_format: node.configuration_format,
        dns_servers: node.dns_servers,
        ntp_servers: node.ntp_servers,
        vrfs: node.vrfs,
        zones: node.zones,
      },
    }))
}

/**
 * Generic converter for interface-based edge types
 * Handles edge types that use interface-to-interface connections
 * @param edges - Array of edge objects with interface/remote_interface properties
 * @param edgeType - Type identifier ('physical', 'layer1', etc.)
 * @returns Array of Cytoscape-compatible edge elements
 */
function convertInterfaceBasedEdgesToElements(
  edges: (PhysicalEdge | Layer1Edge)[],
  edgeType: string
): CytoscapeEdge[] {
  if (!edges || !Array.isArray(edges)) {
    logger.warn(`[cytoscape/utils] Invalid ${edgeType} edges array`)
    return []
  }

  return edges
    .filter(edge => {
      if (!edge || !edge.interface || !edge.remote_interface) {
        logger.warn(`[cytoscape/utils] Skipping invalid ${edgeType} edge:`, edge)
        return false
      }
      return true
    })
    .map((edge) => {
      const [sourceNode, sourcePort] = parseInterface(edge.interface)
      const [targetNode, targetPort] = parseInterface(edge.remote_interface)

      return {
        data: {
          id: generateStableEdgeId(sourceNode, targetNode, edgeType, sourcePort, targetPort),
          source: sourceNode,
          target: targetNode,
          label: '',
          source_port: sourcePort,
          target_port: targetPort,
          edge_type: edgeType,
        },
      }
    })
}

/**
 * Convert Batfish physical layer edges to Cytoscape edge elements
 * Represents direct cable connections between network devices
 * Parses interface names to extract node and port information
 * @param edges - Array of Batfish physical edge objects
 * @returns Array of Cytoscape-compatible physical edge elements
 */
export function convertPhysicalEdgesToElements(edges: PhysicalEdge[]): CytoscapeEdge[] {
  return convertInterfaceBasedEdgesToElements(edges, 'physical')
}

/**
 * Convert Batfish layer 1 edges to Cytoscape edge elements
 * Represents manually defined physical connections from layer1_topology.json
 * Used to supplement auto-detected physical connections
 * @param edges - Array of Batfish layer 1 edge objects
 * @returns Array of Cytoscape-compatible layer 1 edge elements
 */
export function convertLayer1EdgesToElements(edges: Layer1Edge[]): CytoscapeEdge[] {
  return convertInterfaceBasedEdgesToElements(edges, 'layer1')
}

/**
 * Convert Batfish layer 3 edges to Cytoscape edge elements
 * Represents IP-based connections with address information
 * Includes source/target IPs for troubleshooting connectivity
 * @param edges - Array of Batfish layer 3 edge objects
 * @returns Array of Cytoscape-compatible layer 3 edge elements
 */
export function convertLayer3EdgesToElements(edges: Layer3Edge[]): CytoscapeEdge[] {
  if (!edges || !Array.isArray(edges)) {
    logger.warn('[Topology] Invalid layer3 edges array')
    return []
  }

  return edges
    .filter(edge => {
      if (!edge || !edge.interface || !edge.remote_interface) {
        logger.warn('[Topology] Skipping invalid layer3 edge:', edge)
        return false
      }
      return true
    })
    .map((edge) => {
      const [sourceNode, sourcePort] = parseInterface(edge.interface)
      const [targetNode, targetPort] = parseInterface(edge.remote_interface)

      return {
        data: {
          id: generateStableEdgeId(sourceNode, targetNode, 'layer3', sourcePort, targetPort),
          source: sourceNode,
          target: targetNode,
          label: edge.ips?.[0] || '',
          source_port: sourcePort,
          target_port: targetPort,
          ips: edge.ips,
          remote_ips: edge.remote_ips,
          edge_type: 'layer3',
        },
      }
    })
}

/**
 * Convert Batfish OSPF adjacency edges to Cytoscape edge elements
 * Represents OSPF neighbor relationships with IP addresses
 * Used for OSPF topology visualization and troubleshooting
 * @param edges - Array of Batfish OSPF edge objects
 * @returns Array of Cytoscape-compatible OSPF edge elements with protocol styling
 */
export function convertOSPFEdgesToElements(edges: OSPFEdge[]): CytoscapeEdge[] {
  return edges.map((edge) => {
    const [sourceNode, sourcePort] = parseInterface(edge.interface)
    const [targetNode, targetPort] = parseInterface(edge.remote_interface)

    return {
      data: {
        id: generateStableEdgeId(sourceNode, targetNode, 'ospf', sourcePort, targetPort),
        source: sourceNode,
        target: targetNode,
        label: 'OSPF',
        protocol: 'ospf',
        source_port: sourcePort,
        target_port: targetPort,
        ip: edge.ip,
        remote_ip: edge.remote_ip,
        edge_type: 'ospf',
      },
    }
  })
}

/**
 * Convert Batfish BGP session edges to Cytoscape edge elements
 * Represents BGP peer connections with ASN and IP information
 * Node-to-node connections without specific interface requirements
 * @param edges - Array of Batfish BGP edge objects
 * @returns Array of Cytoscape-compatible BGP edge elements with AS numbers
 */
export function convertBGPEdgesToElements(edges: BGPEdge[]): CytoscapeEdge[] {
  return edges.map((edge) => {
    // BGP edges use node-to-node connections
    const sourceNode = edge.node
    const targetNode = edge.remote_node

    // Extract port from interface if available
    const sourcePort = edge.interface ? parseInterface(edge.interface)[1] : ''
    const targetPort = edge.remote_interface ? parseInterface(edge.remote_interface)[1] : ''

    if (edge.interface && !sourcePort) {
      logger.debug(`[Topology] BGP edge missing source port: ${edge.interface}`)
    }
    if (edge.remote_interface && !targetPort) {
      logger.debug(`[Topology] BGP edge missing target port: ${edge.remote_interface}`)
    }

    return {
      data: {
        id: generateStableEdgeId(sourceNode, targetNode, 'bgp', sourcePort, targetPort),
        source: sourceNode,
        target: targetNode,
        label: `BGP AS${edge.local_asn}`,
        protocol: 'bgp',
        source_port: sourcePort,
        target_port: targetPort,
        local_asn: edge.local_asn,
        remote_asn: edge.remote_asn,
        local_ip: edge.local_ip,
        remote_ip: edge.remote_ip,
        edge_type: 'bgp',
      },
    }
  })
}

/**
 * Convert Batfish VXLAN tunnel edges to Cytoscape edge elements
 * Represents VXLAN overlay tunnels between VTEPs (VXLAN Tunnel Endpoints)
 * Includes VNI, VTEP addresses, and multicast group information
 * @param edges - Array of Batfish VXLAN edge objects
 * @returns Array of Cytoscape-compatible VXLAN edge elements (dashed lines)
 */
export function convertVXLANEdgesToElements(edges: VXLANEdge[]): CytoscapeEdge[] {
  if (!edges || !Array.isArray(edges)) {
    logger.warn('[Topology] Invalid VXLAN edges array')
    return []
  }

  return edges
    .filter(edge => {
      if (!edge) {
        logger.warn('[Topology] Null VXLAN edge found')
        return false
      }
      const sourceNode = edge.node
      const targetNode = edge.remote_node
      if (!sourceNode || !targetNode) {
        logger.warn('[Topology] Invalid VXLAN edge nodes:', { sourceNode, targetNode })
        return false
      }
      return true
    })
    .map((edge) => {
      const sourceNode = edge.node
      const targetNode = edge.remote_node

      return {
        data: {
          id: generateStableEdgeId(sourceNode, targetNode, 'vxlan'),
          source: sourceNode,
          target: targetNode,
          label: `VXLAN VNI ${edge.vni}`,
          protocol: 'vxlan',
          vni: edge.vni,
          vtep_address: edge.vtep_address,
          remote_vtep_address: edge.remote_vtep_address,
          multicast_group: edge.multicast_group,
          edge_type: 'vxlan',
        },
      }
    })
}

/**
 * Convert Batfish EIGRP adjacency edges to Cytoscape edge elements
 * Represents EIGRP neighbor relationships with IP addresses
 * Used for EIGRP topology visualization in Cisco networks
 * @param edges - Array of Batfish EIGRP edge objects
 * @returns Array of Cytoscape-compatible EIGRP edge elements with protocol styling
 */
export function convertEIGRPEdgesToElements(edges: EIGRPEdge[]): CytoscapeEdge[] {
  if (!edges || !Array.isArray(edges)) {
    logger.warn('[Topology] Invalid EIGRP edges array')
    return []
  }

  return edges
    .filter(edge => {
      if (!edge || !edge.interface || !edge.remote_interface) {
        logger.warn('[Topology] Skipping invalid EIGRP edge:', edge)
        return false
      }
      return true
    })
    .map((edge) => {
      const [sourceNode, sourcePort] = parseInterface(edge.interface)
      const [targetNode, targetPort] = parseInterface(edge.remote_interface)

      return {
        data: {
          id: generateStableEdgeId(sourceNode, targetNode, 'eigrp', sourcePort, targetPort),
          source: sourceNode,
          target: targetNode,
          label: 'EIGRP',
          protocol: 'eigrp',
          source_port: sourcePort,
          target_port: targetPort,
          ip: edge.ip,
          remote_ip: edge.remote_ip,
          edge_type: 'eigrp',
        },
      }
    })
}

/**
 * Convert Batfish IS-IS adjacency edges to Cytoscape edge elements
 * Represents IS-IS neighbor relationships with level information (L1/L2)
 * Used for IS-IS topology visualization in service provider networks
 * @param edges - Array of Batfish IS-IS edge objects
 * @returns Array of Cytoscape-compatible IS-IS edge elements with level labels
 */
export function convertISISEdgesToElements(edges: ISISEdge[]): CytoscapeEdge[] {
  if (!edges || !Array.isArray(edges)) {
    logger.warn('[Topology] Invalid IS-IS edges array')
    return []
  }

  return edges
    .filter(edge => {
      if (!edge || !edge.interface || !edge.remote_interface) {
        logger.warn('[Topology] Skipping invalid IS-IS edge:', edge)
        return false
      }
      return true
    })
    .map((edge) => {
      const [sourceNode, sourcePort] = parseInterface(edge.interface)
      const [targetNode, targetPort] = parseInterface(edge.remote_interface)

      return {
        data: {
          id: generateStableEdgeId(sourceNode, targetNode, 'isis', sourcePort, targetPort),
          source: sourceNode,
          target: targetNode,
          label: `IS-IS L${edge.level}`,
          protocol: 'isis',
          source_port: sourcePort,
          target_port: targetPort,
          level: edge.level,
          edge_type: 'isis',
        },
      }
    })
}

/**
 * Convert Batfish IPsec VPN tunnel edges to Cytoscape edge elements
 * Represents encrypted tunnel connections between IPsec peers
 * Node-to-node connections with tunnel interface information
 * @param edges - Array of Batfish IPsec edge objects
 * @returns Array of Cytoscape-compatible IPsec edge elements (dashed lines)
 */
export function convertIPsecEdgesToElements(edges: IPsecEdge[]): CytoscapeEdge[] {
  if (!edges || !Array.isArray(edges)) {
    logger.warn('[Topology] Invalid IPsec edges array')
    return []
  }

  return edges
    .filter(edge => {
      if (!edge) {
        logger.warn('[Topology] Null IPsec edge found')
        return false
      }
      const sourceNode = edge.node
      const targetNode = edge.remote_node
      if (!sourceNode || !targetNode) {
        logger.warn('[Topology] Invalid IPsec edge nodes:', { sourceNode, targetNode })
        return false
      }
      return true
    })
    .map((edge) => {
      const sourceNode = edge.node
      const targetNode = edge.remote_node

      return {
        data: {
          id: generateStableEdgeId(sourceNode, targetNode, 'ipsec'),
          source: sourceNode,
          target: targetNode,
          label: 'IPsec',
          protocol: 'ipsec',
          local_interface: edge.local_interface,
          remote_interface: edge.remote_interface,
          tunnel_interfaces: edge.tunnel_interfaces,
          edge_type: 'ipsec',
        },
      }
    })
}

/**
 * Parse Batfish interface string into node name and port/interface name
 * Handles multiple formats: "node[port]", "node:port", "node/port"
 * Returns tuple of [nodeName, portName] for edge creation
 * @param interfaceStr - Batfish interface string (e.g., "router1[GigabitEthernet0/0]")
 * @returns Tuple of [nodeName, portName] extracted from interface string
 */
export function parseInterface(interfaceStr: string): [string, string] {
  if (!interfaceStr || typeof interfaceStr !== 'string') {
    logger.warn('[cytoscape/utils] Invalid interface string:', interfaceStr)
    return ['unknown', '']
  }

  const match = interfaceStr.match(/^(.+?)\[(.+)\]$/)
  if (match) {
    return [match[1], match[2]]
  }

  // If no brackets, try to split by last colon or slash
  const parts = interfaceStr.split(/[:\/]/)
  if (parts.length > 1) {
    const port = parts[parts.length - 1]
    const node = parts.slice(0, -1).join(':')

    // Validate node is not empty
    if (!node || node.trim() === '') {
      logger.warn('[Topology] Empty node name in interface:', interfaceStr)
      return ['', port]
    }

    return [node, port]
  }

  return [interfaceStr, '']
}

/**
 * Determine device type from vendor/platform string
 * Maps vendor and model info to visual node types (router, switch, firewall)
 * Used for applying appropriate node shapes and colors in graph visualization
 * @param vendor - Vendor or platform string from Batfish node properties
 * @returns Device type string (router, switch, firewall, or unknown)
 */
export function determineNodeType(vendor: string): string {
  const v = vendor.toLowerCase()

  if (v.includes('cisco') || v.includes('juniper') || v.includes('arista')) {
    if (v.includes('asr') || v.includes('mx') || v.includes('router')) {
      return 'router'
    }
    if (v.includes('nexus') || v.includes('ex') || v.includes('switch')) {
      return 'switch'
    }
    if (v.includes('asa') || v.includes('firewall') || v.includes('srx')) {
      return 'firewall'
    }
  }

  return 'unknown'
}

/**
 * Merge multiple edge arrays while preventing duplicates
 * Deduplicates edges by source-target-edge_type key combination
 * Allows multiple edge types (OSPF, BGP) between same node pair
 * @param edgeArrays - Variable number of edge arrays to merge
 * @returns Single deduplicated array of Cytoscape edges
 */
export function mergeEdges(...edgeArrays: CytoscapeEdge[][]): CytoscapeEdge[] {
  const edgeMap = new Map<string, CytoscapeEdge>()

  for (const edges of edgeArrays) {
    if (!edges || !Array.isArray(edges)) {
      logger.warn('[cytoscape/utils] Skipping invalid edge array in mergeEdges')
      continue
    }

    for (const edge of edges) {
      if (!edge || !edge.data || !edge.data.source || !edge.data.target) {
        logger.warn('[cytoscape/utils] Skipping invalid edge in mergeEdges:', edge)
        continue
      }

      // Include edge_type in the key to allow multiple edge types between same nodes
      const edgeType = edge.data.edge_type || 'unknown'
      const key = `${edge.data.source}-${edge.data.target}-${edgeType}`
      if (!edgeMap.has(key)) {
        edgeMap.set(key, edge)
      }
    }
  }

  return Array.from(edgeMap.values())
}

/**
 * Build complete Cytoscape graph from Batfish network data
 * Primary function for converting Batfish analysis results to renderable graph
 * Supports selective layer visibility for protocol-specific views
 * Merges all edge types and deduplicates automatically
 * Used by TopologyViewer to construct graph visualization
 * @param nodes - Array of Batfish node properties (devices)
 * @param edges - Object containing edge arrays by protocol type
 * @param visibleLayers - Optional set of layers to include (defaults to all)
 * @returns Complete Cytoscape elements object with nodes and merged edges
 */
export function buildGraphElements(
  nodes: NodeProperties[],
  edges: {
    physical?: PhysicalEdge[]
    layer1?: Layer1Edge[]
    layer3?: Layer3Edge[]
    ospf?: OSPFEdge[]
    bgp?: BGPEdge[]
    vxlan?: VXLANEdge[]
    eigrp?: EIGRPEdge[]
    isis?: ISISEdge[]
    ipsec?: IPsecEdge[]
  } = {},
  visibleLayers?: Set<LayerType>
): CytoscapeElements {
  if (!nodes) {
    logger.error('[cytoscape/utils] No nodes provided to buildGraphElements')
    return { nodes: [], edges: [] }
  }

  const cytoscapeNodes = convertNodesToElements(nodes)

  if (!edges || typeof edges !== 'object') {
    logger.warn('[cytoscape/utils] No edges provided to buildGraphElements')
    return { nodes: cytoscapeNodes, edges: [] }
  }

  // If visibleLayers is not provided, show all layers by default
  const layers = visibleLayers || new Set(['physical', 'layer1', 'layer3', 'ospf', 'bgp', 'vxlan', 'eigrp', 'isis', 'ipsec'])

  // Conditionally convert edges based on visible layers
  const physicalEdges = layers.has('physical') && edges.physical ? convertPhysicalEdgesToElements(edges.physical) : []
  const layer1Edges = layers.has('layer1') && edges.layer1 ? convertLayer1EdgesToElements(edges.layer1) : []
  const layer3Edges = layers.has('layer3') && edges.layer3 ? convertLayer3EdgesToElements(edges.layer3) : []
  const ospfEdges = layers.has('ospf') && edges.ospf ? convertOSPFEdgesToElements(edges.ospf) : []
  const bgpEdges = layers.has('bgp') && edges.bgp ? convertBGPEdgesToElements(edges.bgp) : []
  const vxlanEdges = layers.has('vxlan') && edges.vxlan ? convertVXLANEdgesToElements(edges.vxlan) : []
  const eigrpEdges = layers.has('eigrp') && edges.eigrp ? convertEIGRPEdgesToElements(edges.eigrp) : []
  const isisEdges = layers.has('isis') && edges.isis ? convertISISEdgesToElements(edges.isis) : []
  const ipsecEdges = layers.has('ipsec') && edges.ipsec ? convertIPsecEdgesToElements(edges.ipsec) : []

  // Filter out empty arrays before merging to reduce merge overhead
  const allEdgeArrays = [
    physicalEdges,
    layer1Edges,
    layer3Edges,
    ospfEdges,
    bgpEdges,
    vxlanEdges,
    eigrpEdges,
    isisEdges,
    ipsecEdges
  ].filter(arr => arr.length > 0)

  const cytoscapeEdges = mergeEdges(...allEdgeArrays)

  logger.log('[cytoscape/utils] Built graph with', cytoscapeNodes.length, 'nodes and', cytoscapeEdges.length, 'edges (layers:', Array.from(layers).join(', '), ')')

  return {
    nodes: cytoscapeNodes,
    edges: cytoscapeEdges,
  }
}