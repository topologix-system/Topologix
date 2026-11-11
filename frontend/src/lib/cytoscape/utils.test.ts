import { describe, expect, it } from 'vitest'

import type { NodeProperties } from '../../types'
import {
  buildGraphElements,
  findEdgeByStableId,
  generateStableEdgeId,
  getStableEdgeType,
  resolveStableEdgeEndpoints,
  type StableEdgeCollections,
} from './utils'

const NODE_NAMES = ['core-rtr1', 'core-rtr2', 'dc-leaf1', 'dc-spine1', 'dist-sw1']

const nodes = NODE_NAMES.map((name) => ({ node: name, hostname: name, vendor: 'CISCO' })) as unknown as NodeProperties[]

const collections: StableEdgeCollections = {
  physical: [{ interface: 'core-rtr1[GigabitEthernet0/0]', remote_interface: 'core-rtr2[GigabitEthernet0/0/0/0]' }],
  layer1: [{ interface: 'dist-sw1[Ethernet1]', remote_interface: 'core-rtr1[GigabitEthernet0/1]' }],
  layer3: [{ interface: 'dc-leaf1[Ethernet1/1]', remote_interface: 'dc-spine1[Ethernet1/1]', ips: ['10.1.1.1/30'], remote_ips: ['10.1.1.2/30'] }],
  ospf: [{ interface: 'core-rtr1[GigabitEthernet0/0]', remote_interface: 'core-rtr2[GigabitEthernet0/0/0/0]', ip: '10.0.0.1', remote_ip: '10.0.0.2' }],
  bgp: [{
    node: 'dc-leaf1',
    interface: null,
    remote_node: 'dc-spine1',
    remote_interface: null,
    remote_ip: '10.255.1.1',
    local_ip: '10.255.1.2',
    remote_asn: '65000',
    local_asn: '65001',
  }],
  vxlan: [{ node: 'dc-leaf1', vni: 10010, vtep_address: '10.0.0.11', remote_node: 'dc-spine1', remote_vtep_address: '10.0.0.12', multicast_group: '' }],
  eigrp: [{ interface: 'dist-sw1[Ethernet2]', remote_interface: 'core-rtr2[GigabitEthernet0/0/0/1]', ip: '10.3.0.1', remote_ip: '10.3.0.2' }],
  isis: [{ interface: 'core-rtr2[GigabitEthernet0/0/0/2]', remote_interface: 'dc-spine1[Ethernet1/2]', level: '2' }],
  ipsec: [{ node: 'core-rtr1', remote_node: 'dist-sw1', local_interface: 'core-rtr1[Tunnel0]', remote_interface: 'dist-sw1[Tunnel0]', tunnel_interfaces: ['Tunnel0'] }],
}

describe('findEdgeByStableId', () => {
  it('finds the source record of every edge rendered by buildGraphElements', () => {
    const { edges } = buildGraphElements(nodes, collections)
    expect(edges).toHaveLength(9)

    for (const element of edges) {
      const match = findEdgeByStableId(element.data.id, collections)
      expect(match, element.data.id).not.toBeNull()
      expect(match?.type).toBe(element.data.edge_type)
      expect(match?.source).toBe(element.data.source)
      expect(match?.target).toBe(element.data.target)
    }
  })

  it('returns the matching record with hostnames that contain "-"', () => {
    const id = generateStableEdgeId('core-rtr1', 'core-rtr2', 'ospf', 'GigabitEthernet0/0', 'GigabitEthernet0/0/0/0')
    const match = findEdgeByStableId(id, collections)
    expect(match).toMatchObject({ type: 'ospf', source: 'core-rtr1', target: 'core-rtr2' })
    expect(match?.edge).toBe(collections.ospf?.[0])
  })

  it('does not match an edge of another type or an interface-pair string', () => {
    const ospfId = generateStableEdgeId('core-rtr1', 'core-rtr2', 'ospf', 'GigabitEthernet0/0', 'GigabitEthernet0/0/0/0')
    expect(findEdgeByStableId(ospfId, { physical: collections.physical })).toBeNull()
    expect(findEdgeByStableId('core-rtr1[GigabitEthernet0/0]-core-rtr2[GigabitEthernet0/0/0/0]', collections)).toBeNull()
    expect(findEdgeByStableId('edge-physical-core-rtr1-core-rtr2-Gi9-Gi9', collections)).toBeNull()
  })

  it('tolerates missing collections', () => {
    expect(findEdgeByStableId('edge-bgp-dc-leaf1-dc-spine1', {})).toBeNull()
  })
})

describe('getStableEdgeType', () => {
  it('reads the type prefix of stable IDs only', () => {
    expect(getStableEdgeType('edge-layer1-dist-sw1-core-rtr1-Ethernet1-GigabitEthernet0/1')).toBe('layer1')
    expect(getStableEdgeType('edge-ipsec-core-rtr1-dist-sw1')).toBe('ipsec')
    expect(getStableEdgeType('edge-unknown-a-b')).toBeNull()
    expect(getStableEdgeType('core-rtr1-core-rtr2')).toBeNull()
  })
})

describe('resolveStableEdgeEndpoints', () => {
  it('resolves endpoints containing "-" from the node names', () => {
    expect(resolveStableEdgeEndpoints('edge-vxlan-dc-leaf1-dc-spine1', NODE_NAMES)).toEqual({ type: 'vxlan', source: 'dc-leaf1', target: 'dc-spine1' })
    expect(resolveStableEdgeEndpoints('edge-isis-core-rtr2-dc-spine1-GigabitEthernet0/0/0/2-Ethernet1/2', NODE_NAMES)).toEqual({ type: 'isis', source: 'core-rtr2', target: 'dc-spine1' })
  })

  it('prefers the longest node name when names share a prefix', () => {
    expect(resolveStableEdgeEndpoints('edge-physical-dc-leaf1-dc-leaf1-b-Eth1-Eth2', ['dc', 'dc-leaf1', 'dc-leaf1-b'])).toEqual({ type: 'physical', source: 'dc-leaf1', target: 'dc-leaf1-b' })
  })

  it('keeps the type when endpoints are unknown', () => {
    expect(resolveStableEdgeEndpoints('edge-eigrp-x-y', [])).toEqual({ type: 'eigrp', source: null, target: null })
    expect(resolveStableEdgeEndpoints('not-a-stable-id', NODE_NAMES)).toBeNull()
  })
})
