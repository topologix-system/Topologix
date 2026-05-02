export type HostSearchErrorCode = 'empty' | 'invalidIp' | 'nonHostCidr'

export interface ParsedIPv4 {
  text: string
  value: number
}

export interface ParsedCIDR {
  text: string
  address: ParsedIPv4
  networkText: string
  networkValue: number
  prefixLength: number
  maskValue: number
}

export interface HostSearchInput {
  input: string
  ip: ParsedIPv4 | null
  error: HostSearchErrorCode | null
}

export interface HostOwnerMatch {
  node: string
  vrf: string
  interface: string
  ip: string
  mask: string | number
  active: boolean
}

export type InterfaceNetworkMatchSource = 'primary_network' | 'all_prefixes'

export interface InterfaceNetworkMatch {
  hostname: string
  interface: string
  vrf: string
  prefix: string
  prefixLength: number
  primaryAddress?: string
  primaryNetwork?: string
  source: InterfaceNetworkMatchSource
  active: boolean
  adminUp: boolean
}
