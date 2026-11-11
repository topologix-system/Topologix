import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import type { AllNetworkData } from '../../types/api'
import { generateStableEdgeId } from '../../lib/cytoscape/utils'
import { useUIStore } from '../../store'
import { EdgeDetailsPanel, resolveEdgeDetails } from './EdgeDetailsPanel'

const networkData: Partial<AllNetworkData> = {
  node_properties: [
    { node: 'core-rtr1' },
    { node: 'core-rtr2' },
    { node: 'dc-leaf1' },
    { node: 'dc-spine1' },
  ] as AllNetworkData['node_properties'],
  edges: [{ interface: 'core-rtr1[GigabitEthernet0/0]', remote_interface: 'core-rtr2[GigabitEthernet0/0/0/0]' }],
  ospf_edges: [{ interface: 'core-rtr1[GigabitEthernet0/0]', remote_interface: 'core-rtr2[GigabitEthernet0/0/0/0]', ip: '', remote_ip: '' }],
  bgp_edges: [{
    node: 'dc-leaf1',
    interface: null,
    remote_node: 'dc-spine1',
    remote_interface: null,
    remote_ip: '10.255.1.1',
    local_ip: '10.255.1.2',
    remote_asn: '65000',
    local_asn: '65001',
  }],
  vxlan_edges: [{ node: 'dc-leaf1', vni: 10010, vtep_address: '10.0.0.11', remote_node: 'dc-spine1', remote_vtep_address: '10.0.0.12', multicast_group: '' }],
}

vi.mock('../../hooks', () => ({
  useAllNetworkData: () => ({ data: networkData, isLoading: false }),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

const physicalId = generateStableEdgeId('core-rtr1', 'core-rtr2', 'physical', 'GigabitEthernet0/0', 'GigabitEthernet0/0/0/0')
const bgpId = generateStableEdgeId('dc-leaf1', 'dc-spine1', 'bgp')
const ospfId = physicalId.replace('edge-physical-', 'edge-ospf-')

function fieldValue(label: string): string | null | undefined {
  return screen.getByText(label, { selector: 'span' }).nextElementSibling?.textContent
}

describe('resolveEdgeDetails', () => {
  it('matches physical, OSPF and BGP edges by their stable IDs', () => {
    expect(resolveEdgeDetails(physicalId, networkData)).toMatchObject({ type: 'physical', sourceNode: 'core-rtr1', targetNode: 'core-rtr2' })
    const ospf = resolveEdgeDetails(ospfId, networkData)
    expect(ospf).toMatchObject({ type: 'ospf', sourceNode: 'core-rtr1', targetNode: 'core-rtr2' })
    expect(ospf?.match?.edge).toBe(networkData.ospf_edges?.[0])
    expect(resolveEdgeDetails(bgpId, networkData)?.match?.edge).toBe(networkData.bgp_edges?.[0])
  })

  it('falls back to the type and endpoints encoded in the ID when no record matches', () => {
    expect(resolveEdgeDetails('edge-ipsec-core-rtr1-dc-leaf1', networkData)).toEqual({
      type: 'ipsec',
      match: null,
      sourceNode: 'core-rtr1',
      targetNode: 'dc-leaf1',
    })
  })

  it('returns null for IDs without a known edge type', () => {
    expect(resolveEdgeDetails('core-rtr1[GigabitEthernet0/0]-core-rtr2[GigabitEthernet0/0/0/0]', networkData)).toBeNull()
  })
})

describe('EdgeDetailsPanel', () => {
  it('shows the real endpoint node names and the type badge', () => {
    useUIStore.setState({ selectedEdgeId: physicalId })
    render(<EdgeDetailsPanel />)
    expect(fieldValue('edgeDetails.fields.sourceNode')).toBe('core-rtr1')
    expect(fieldValue('edgeDetails.fields.targetNode')).toBe('core-rtr2')
    expect(fieldValue('edgeDetails.fields.sourceInterface')).toBe('core-rtr1[GigabitEthernet0/0]')
    expect(screen.getByText('PHYSICAL')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'edgeDetails.regionLabel' })).toBeInTheDocument()
  })

  it('shows N/A for the empty IP fields of OSPF edges', () => {
    useUIStore.setState({ selectedEdgeId: ospfId })
    render(<EdgeDetailsPanel />)
    expect(screen.getByText('OSPF')).toBeInTheDocument()
    expect(fieldValue('edgeDetails.fields.sourceIp')).toBe('common.notAvailable')
    expect(fieldValue('edgeDetails.fields.targetIp')).toBe('common.notAvailable')
  })

  it('renders BGP addresses and ASNs', () => {
    useUIStore.setState({ selectedEdgeId: bgpId })
    render(<EdgeDetailsPanel />)
    expect(screen.getByText('BGP')).toBeInTheDocument()
    expect(fieldValue('edgeDetails.fields.localAsn')).toBe('65001')
    expect(fieldValue('edgeDetails.fields.remoteAsn')).toBe('65000')
    expect(fieldValue('edgeDetails.fields.localIp')).toBe('10.255.1.2')
    expect(fieldValue('edgeDetails.fields.remoteIp')).toBe('10.255.1.1')
    expect(screen.queryByText('edgeDetails.fields.importPolicy')).toBeNull()
    expect(screen.queryByText('edgeDetails.fields.exportPolicy')).toBeNull()
  })

  it('shows the type and endpoints of edge types without a dedicated record', () => {
    useUIStore.setState({ selectedEdgeId: 'edge-isis-core-rtr2-dc-spine1-Gi0-Eth1' })
    render(<EdgeDetailsPanel />)
    expect(screen.getByText('ISIS')).toBeInTheDocument()
    expect(fieldValue('edgeDetails.fields.sourceNode')).toBe('core-rtr2')
    expect(fieldValue('edgeDetails.fields.targetNode')).toBe('dc-spine1')
  })
})
