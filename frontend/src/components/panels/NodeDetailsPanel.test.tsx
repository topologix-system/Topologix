import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import type { InterfaceProperties, NodeProperties } from '../../types/network'
import type { DefinedStructure, ReferencedStructure } from '../../types/structures'
import type { FileParseStatus } from '../../types/validation'
import { useUIStore } from '../../store'
import {
  filterStructuresByFiles,
  getNodeConfigFiles,
  getSourceLineFilename,
  hasVlanData,
  NodeDetailsPanel,
} from './NodeDetailsPanel'

vi.mock('../../hooks', () => ({
  useAllNetworkData: () => ({
    data: {
      node_properties: [{
        node: 'core-rtr1',
        hostname: 'core-rtr1',
        vendor: 'CISCO',
        interfaces: [],
        ipsec_vpns: [],
        vrfs: [],
        zones: [],
        dns_servers: [],
        ntp_servers: [],
        logging_servers: [],
        snmp_trap_servers: [],
        tacacs_servers: [],
      }] as NodeProperties[],
      interface_properties: [],
    },
    isLoading: false,
  }),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

function iface(overrides: Partial<InterfaceProperties>): InterfaceProperties {
  return {
    hostname: 'dist-sw1',
    interface: 'Ethernet1',
    switchport: false,
    switchport_mode: 'NONE',
    allowed_vlans: '',
    ...overrides,
  } as InterfaceProperties
}

describe('hasVlanData', () => {
  it('ignores routed and loopback ports (switchport false, mode NONE)', () => {
    expect(hasVlanData(iface({}))).toBe(false)
    expect(hasVlanData(iface({ interface: 'Loopback0' }))).toBe(false)
    expect(hasVlanData(iface({ switchport_mode: 'none' }))).toBe(false)
  })

  it('ignores switchport attributes of interfaces that are not switchports', () => {
    expect(hasVlanData(iface({ switchport: false, switchport_mode: 'ACCESS', access_vlan: 1 }))).toBe(false)
  })

  it('accepts switchports and their VLAN settings', () => {
    expect(hasVlanData(iface({ switchport: true }))).toBe(true)
    expect(hasVlanData(iface({ switchport: undefined, switchport_mode: 'TRUNK' }))).toBe(true)
    expect(hasVlanData(iface({ switchport: true, switchport_mode: 'ACCESS', access_vlan: 10 }))).toBe(true)
    expect(hasVlanData(iface({ switchport: undefined, switchport_mode: '', allowed_vlans: '10-20' }))).toBe(true)
  })

  it('accepts VLAN interfaces and encapsulation VLANs on routed ports', () => {
    expect(hasVlanData(iface({ interface: 'Vlan10', vlan: 10 }))).toBe(true)
    expect(hasVlanData(iface({ interface: 'Ethernet1.100', encapsulation_vlan: 100 }))).toBe(true)
  })

  it('leaves nothing for a node with routed ports only', () => {
    const interfaces = ['Ethernet1', 'Ethernet2', 'Ethernet3', 'Loopback0'].map((name) => iface({ interface: name }))
    expect(interfaces.filter(hasVlanData)).toEqual([])
  })
})

describe('configuration structures of a node', () => {
  const fileParseStatus: FileParseStatus[] = [
    { file_name: 'configs/core-rtr1.txt', status: 'PASSED', nodes: ['core-rtr1'] },
    { file_name: 'configs/core-rtr2.txt', status: 'PASSED', nodes: ['core-rtr2'] },
    { file_name: 'configs/dc-leaf1.txt', status: 'PASSED', nodes: ['dc-leaf1'] },
  ]

  const defined: DefinedStructure[] = [
    { structure_type: 'extended ipv4 access-list', structure_name: 'BLOCK-DC-ICMP', source_lines: ['configs/core-rtr1.txt:[93, 94, 95]'] },
    { structure_type: 'interface', structure_name: 'GigabitEthernet0/0/0/0', source_lines: ['configs/core-rtr2.txt:[34, 35]'] },
    { structure_type: 'policy-map type queuing', structure_name: 'default-in-policy', source_lines: ['configs/dc-leaf1.txt:[0]'] },
  ]

  const referenced: ReferencedStructure[] = [
    { structure_type: 'bgp neighbor', structure_name: '10.255.0.2 (VRF default)', context: 'bgp neighbor self ref', source_lines: ['configs/core-rtr1.txt:[70, 71]'] },
    { structure_type: 'bgp neighbor', structure_name: '10.255.0.1 (VRF default)', context: 'bgp neighbor self ref', source_lines: ['configs/core-rtr2.txt:[12]'] },
  ]

  it('reads the file name of string and object source lines', () => {
    expect(getSourceLineFilename('configs/core-rtr1.txt:[93, 94, 95]')).toBe('configs/core-rtr1.txt')
    expect(getSourceLineFilename('configs/a:b.txt:[1]')).toBe('configs/a:b.txt')
    expect(getSourceLineFilename({ filename: 'configs/core-rtr2.txt', lines: [96] })).toBe('configs/core-rtr2.txt')
    expect(getSourceLineFilename(null)).toBeNull()
  })

  it('collects the files parsed into the node', () => {
    expect([...getNodeConfigFiles(fileParseStatus, 'core-rtr1')]).toEqual(['configs/core-rtr1.txt'])
    expect(getNodeConfigFiles(fileParseStatus, 'missing').size).toBe(0)
    expect(getNodeConfigFiles(undefined, 'core-rtr1').size).toBe(0)
  })

  it('keeps only the structures defined or referenced in the node files', () => {
    const files = getNodeConfigFiles(fileParseStatus, 'core-rtr1')
    expect(filterStructuresByFiles(defined, files).map((s) => s.structure_name)).toEqual(['BLOCK-DC-ICMP'])
    expect(filterStructuresByFiles(referenced, files).map((s) => s.structure_name)).toEqual(['10.255.0.2 (VRF default)'])
  })

  it('returns nothing when the node has no known file', () => {
    expect(filterStructuresByFiles(defined, new Set())).toEqual([])
    expect(filterStructuresByFiles(undefined, new Set(['configs/core-rtr1.txt']))).toEqual([])
  })
})

describe('NodeDetailsPanel tabs', () => {
  it('moves to the Interfaces sub-tab with ArrowRight from Basic', () => {
    useUIStore.setState({ selectedNodeId: 'core-rtr1' })
    render(<NodeDetailsPanel />)
    const basic = screen.getByRole('tab', { name: 'nodeDetails.tabs.basic' })
    const interfaces = screen.getByRole('tab', { name: 'common.interfaces' })
    expect(basic).toHaveAttribute('tabindex', '0')
    expect(interfaces).toHaveAttribute('tabindex', '-1')

    basic.focus()
    fireEvent.keyDown(basic, { key: 'ArrowRight' })
    expect(interfaces).toHaveAttribute('aria-selected', 'true')
    expect(document.activeElement).toBe(interfaces)

    fireEvent.keyDown(interfaces, { key: 'End' })
    const validation = screen.getByRole('tab', { name: 'validation.title' })
    expect(validation).toHaveAttribute('aria-selected', 'true')
    expect(document.activeElement).toBe(validation)
  })
})
