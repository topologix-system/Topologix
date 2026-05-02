import { describe, expect, it } from 'vitest'

import {
  cidrContainsIPv4,
  findHostOwnerMatches,
  findInterfaceNetworkMatches,
  normalizeHostSearchInput,
  parseCIDR,
  parseIPv4,
} from './ipSearch'
import type { IPOwner } from '../types/ip'
import type { InterfaceProperties } from '../types/network'

const baseInterface: InterfaceProperties = {
  hostname: 'node1',
  interface: 'Ethernet0',
  active: true,
  admin_up: true,
  all_prefixes: [],
  allowed_vlans: '',
  auto_state_vlan: false,
  blacklisted: false,
  channel_group_members: [],
  declared_names: [],
  description: '',
  hsrp_groups: [],
  interface_type: 'PHYSICAL',
  mtu: 1500,
  ospf_enabled: false,
  ospf_passive: false,
  proxy_arp: false,
  rip_enabled: false,
  rip_passive: false,
  switchport: false,
  switchport_mode: 'NONE',
  switchport_trunk_encapsulation: '',
  vrf: 'default',
}

describe('ipSearch', () => {
  it('parses valid IPv4 addresses and rejects invalid values', () => {
    expect(parseIPv4('192.0.2.10')?.value).toBe(3221225994)
    expect(parseIPv4('255.255.255.255')?.value).toBe(4294967295)
    expect(parseIPv4('192.0.2.256')).toBeNull()
    expect(parseIPv4('192.0.2')).toBeNull()
    expect(parseIPv4('192.0.2.-1')).toBeNull()
  })

  it('parses CIDR prefixes including /0, /31, and /32', () => {
    expect(parseCIDR('0.0.0.0/0')?.text).toBe('0.0.0.0/0')
    expect(parseCIDR('192.0.2.11/31')?.text).toBe('192.0.2.10/31')
    expect(parseCIDR('192.0.2.10/32')?.text).toBe('192.0.2.10/32')
    expect(parseCIDR('192.0.2.10/33')).toBeNull()
  })

  it('normalizes only host addresses and /32 input for search', () => {
    expect(normalizeHostSearchInput('192.0.2.10').ip?.text).toBe('192.0.2.10')
    expect(normalizeHostSearchInput('192.0.2.10/32').ip?.text).toBe('192.0.2.10')
    expect(normalizeHostSearchInput('192.0.2.0/24').error).toBe('nonHostCidr')
    expect(normalizeHostSearchInput('')).toEqual({ input: '', ip: null, error: 'empty' })
  })

  it('checks CIDR containment with unsigned IPv4 math', () => {
    const defaultRoute = parseCIDR('0.0.0.0/0')
    const hostRoute = parseCIDR('255.255.255.255/32')
    const host = parseIPv4('255.255.255.255')

    expect(defaultRoute && host && cidrContainsIPv4(defaultRoute, host)).toBe(true)
    expect(hostRoute && host && cidrContainsIPv4(hostRoute, host)).toBe(true)
  })

  it('finds exact IP owners and hides inactive owners unless requested', () => {
    const ip = parseIPv4('192.0.2.10')
    const owners: IPOwner[] = [
      { node: 'node1', vrf: 'default', interface: 'Ethernet0', ip: '192.0.2.10', mask: '32', active: true },
      { node: 'node2', vrf: 'default', interface: 'Ethernet1', ip: '192.0.2.10', mask: '32', active: false },
    ]

    expect(ip && findHostOwnerMatches(ip, owners)).toHaveLength(1)
    expect(ip && findHostOwnerMatches(ip, owners, { includeInactive: true })).toHaveLength(2)
  })

  it('finds containing interface networks by longest prefix first', () => {
    const ip = parseIPv4('192.0.2.10')
    const interfaces: InterfaceProperties[] = [
      { ...baseInterface, hostname: 'node1', interface: 'Ethernet0', primary_network: '192.0.2.0/24', all_prefixes: ['192.0.2.8/30'] },
      { ...baseInterface, hostname: 'node2', interface: 'Ethernet1', primary_network: '192.0.0.0/16' },
      { ...baseInterface, hostname: 'node3', interface: 'Ethernet2', active: false, primary_network: '192.0.2.10/32' },
    ]

    const visibleMatches = ip ? findInterfaceNetworkMatches(ip, interfaces) : []
    const allMatches = ip ? findInterfaceNetworkMatches(ip, interfaces, { includeInactive: true }) : []

    expect(visibleMatches.map((match) => match.prefix)).toEqual(['192.0.2.8/30', '192.0.2.0/24', '192.0.0.0/16'])
    expect(allMatches[0].prefix).toBe('192.0.2.10/32')
  })
})
