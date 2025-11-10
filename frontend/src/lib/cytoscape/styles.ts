/**
 * Cytoscape.js visual styles for network topology elements
 * - Node styles by device type (router, switch, firewall, host, etc.)
 * - Edge styles by protocol layer (physical, layer3, OSPF, BGP, VXLAN, EIGRP, IS-IS)
 * - Selection, hover, and highlighting states with visual feedback
 * - Color-coded edges and nodes for easy protocol identification
 */
import type cytoscape from 'cytoscape'

export const defaultStyles: cytoscape.Stylesheet[] = [
  {
    selector: 'node',
    style: {
      'background-color': '#0ea5e9',
      'label': 'data(label)',
      'color': '#1e293b',
      'text-valign': 'center',
      'text-halign': 'center',
      'font-size': '12px',
      'font-weight': 'bold',
      'width': 50,
      'height': 50,
      'border-width': 2,
      'border-color': '#0284c7',
      'text-outline-width': 2,
      'text-outline-color': '#ffffff',
    },
  },

  {
    selector: 'node[type="router"]',
    style: {
      'background-color': '#3b82f6',
      'border-color': '#2563eb',
      'shape': 'round-rectangle',
    },
  },
  {
    selector: 'node[type="switch"]',
    style: {
      'background-color': '#10b981',
      'border-color': '#059669',
      'shape': 'rectangle',
    },
  },
  {
    selector: 'node[type="firewall"]',
    style: {
      'background-color': '#ef4444',
      'border-color': '#dc2626',
      'shape': 'diamond',
    },
  },
  {
    selector: 'node[type="load_balancer"]',
    style: {
      'background-color': '#f59e0b',
      'border-color': '#d97706',
      'shape': 'hexagon',
    },
  },

  {
    selector: 'node:selected',
    style: {
      'border-width': 4,
      'border-color': '#fbbf24',
      'background-color': '#fef3c7',
    },
  },
  {
    selector: 'node:active',
    style: {
      'overlay-opacity': 0.2,
      'overlay-color': '#0ea5e9',
    },
  },
  {
    selector: 'node.highlighted',
    style: {
      'border-width': 4,
      'border-color': '#fbbf24',
    },
  },
  {
    selector: 'node.dimmed',
    style: {
      'opacity': 0.3,
    },
  },

  {
    selector: 'edge',
    style: {
      'width': 2,
      'line-color': '#cbd5e1',
      'target-arrow-color': '#cbd5e1',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'label': 'data(label)',
      'font-size': '10px',
      'text-rotation': 'autorotate',
      'text-margin-y': -10,
      'color': '#475569',
    },
  },

  {
    selector: 'edge[protocol="ospf"]',
    style: {
      'line-color': '#3b82f6',
      'target-arrow-color': '#3b82f6',
      'width': 3,
    },
  },
  {
    selector: 'edge[protocol="bgp"]',
    style: {
      'line-color': '#10b981',
      'target-arrow-color': '#10b981',
      'width': 3,
    },
  },
  {
    selector: 'edge[protocol="vxlan"]',
    style: {
      'line-color': '#8b5cf6',
      'target-arrow-color': '#8b5cf6',
      'width': 3,
      'line-style': 'dashed',
    },
  },
  {
    selector: 'edge[protocol="eigrp"]',
    style: {
      'line-color': '#f59e0b',
      'target-arrow-color': '#f59e0b',
      'width': 3,
    },
  },
  {
    selector: 'edge[protocol="isis"]',
    style: {
      'line-color': '#ec4899',
      'target-arrow-color': '#ec4899',
      'width': 3,
    },
  },
  {
    selector: 'edge[protocol="ipsec"]',
    style: {
      'line-color': '#ef4444',
      'target-arrow-color': '#ef4444',
      'width': 3,
      'line-style': 'dashed',
    },
  },
  {
    selector: 'edge[protocol="vlan"]',
    style: {
      'line-color': '#06b6d4',
      'target-arrow-color': '#06b6d4',
      'width': 2,
    },
  },
  {
    selector: 'edge[edge_type="layer1"]',
    style: {
      'line-color': '#94a3b8',
      'target-arrow-color': '#94a3b8',
      'width': 2,
      'line-style': 'solid',
    },
  },

  {
    selector: 'edge:selected',
    style: {
      'line-color': '#fbbf24',
      'target-arrow-color': '#fbbf24',
      'width': 4,
    },
  },
  {
    selector: 'edge.highlighted',
    style: {
      'line-color': '#fbbf24',
      'target-arrow-color': '#fbbf24',
      'width': 4,
    },
  },
  {
    selector: 'edge.dimmed',
    style: {
      'opacity': 0.2,
    },
  },
]