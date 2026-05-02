import type { IPOwner } from '../types/ip'
import type { InterfaceProperties } from '../types/network'
import type {
  HostOwnerMatch,
  HostSearchInput,
  InterfaceNetworkMatch,
  InterfaceNetworkMatchSource,
  ParsedCIDR,
  ParsedIPv4,
} from '../types/ipSearch'

const IPV4_OCTET_COUNT = 4
const IPV4_MAX_OCTET = 255
const IPV4_MAX_PREFIX_LENGTH = 32
const UNSIGNED_32BIT_MAX = 0xffffffff

function formatIPv4(value: number): string {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join('.')
}

export function parseIPv4(input: string): ParsedIPv4 | null {
  const text = input.trim()
  const parts = text.split('.')

  if (parts.length !== IPV4_OCTET_COUNT) {
    return null
  }

  const octets = parts.map((part) => {
    if (!/^\d+$/.test(part)) {
      return null
    }

    const value = Number(part)
    if (!Number.isInteger(value) || value < 0 || value > IPV4_MAX_OCTET) {
      return null
    }

    return value
  })

  if (octets.some((octet) => octet === null)) {
    return null
  }

  const [a, b, c, d] = octets as [number, number, number, number]
  const value = (((a * 256 + b) * 256 + c) * 256 + d) >>> 0

  return {
    text: formatIPv4(value),
    value,
  }
}

function parsePrefixLength(input: string): number | null {
  if (!/^\d+$/.test(input.trim())) {
    return null
  }

  const prefixLength = Number(input)
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > IPV4_MAX_PREFIX_LENGTH) {
    return null
  }

  return prefixLength
}

function maskFromPrefixLength(prefixLength: number): number {
  if (prefixLength === 0) {
    return 0
  }

  return (UNSIGNED_32BIT_MAX << (IPV4_MAX_PREFIX_LENGTH - prefixLength)) >>> 0
}

export function parseCIDR(input: string): ParsedCIDR | null {
  const text = input.trim()
  const parts = text.split('/')

  if (parts.length !== 2) {
    return null
  }

  const address = parseIPv4(parts[0])
  const prefixLength = parsePrefixLength(parts[1])

  if (!address || prefixLength === null) {
    return null
  }

  const maskValue = maskFromPrefixLength(prefixLength)
  const networkValue = (address.value & maskValue) >>> 0
  const networkText = formatIPv4(networkValue)

  return {
    text: `${networkText}/${prefixLength}`,
    address,
    networkText,
    networkValue,
    prefixLength,
    maskValue,
  }
}

export function normalizeHostSearchInput(input: string): HostSearchInput {
  const trimmed = input.trim()

  if (!trimmed) {
    return { input, ip: null, error: 'empty' }
  }

  if (trimmed.includes('/')) {
    const cidr = parseCIDR(trimmed)
    if (!cidr) {
      return { input, ip: null, error: 'invalidIp' }
    }

    if (cidr.prefixLength !== IPV4_MAX_PREFIX_LENGTH) {
      return { input, ip: null, error: 'nonHostCidr' }
    }

    return { input, ip: cidr.address, error: null }
  }

  const ip = parseIPv4(trimmed)
  if (!ip) {
    return { input, ip: null, error: 'invalidIp' }
  }

  return { input, ip, error: null }
}

export function cidrContainsIPv4(cidr: ParsedCIDR, ip: ParsedIPv4): boolean {
  return ((ip.value & cidr.maskValue) >>> 0) === cidr.networkValue
}

export function findHostOwnerMatches(
  ip: ParsedIPv4,
  owners: IPOwner[] = [],
  options: { includeInactive?: boolean } = {},
): HostOwnerMatch[] {
  const includeInactive = options.includeInactive ?? false

  return owners
    .filter((owner) => {
      const ownerIp = parseIPv4(owner.ip)
      const active = owner.active !== false
      return ownerIp?.value === ip.value && (includeInactive || active)
    })
    .map((owner) => ({
      node: owner.node,
      vrf: owner.vrf,
      interface: owner.interface,
      ip: owner.ip,
      mask: owner.mask,
      active: owner.active !== false,
    }))
    .sort((a, b) => {
      if (a.active !== b.active) return a.active ? -1 : 1
      return `${a.node}\0${a.interface}\0${a.vrf}`.localeCompare(`${b.node}\0${b.interface}\0${b.vrf}`)
    })
}

function collectInterfacePrefixes(iface: InterfaceProperties): Array<{ cidr: ParsedCIDR; source: InterfaceNetworkMatchSource }> {
  const candidates: Array<{ raw: string | undefined; source: InterfaceNetworkMatchSource }> = [
    { raw: iface.primary_network, source: 'primary_network' },
    ...(Array.isArray(iface.all_prefixes)
      ? iface.all_prefixes.map((raw) => ({ raw, source: 'all_prefixes' as const }))
      : []),
  ]
  const seen = new Set<string>()
  const prefixes: Array<{ cidr: ParsedCIDR; source: InterfaceNetworkMatchSource }> = []

  for (const candidate of candidates) {
    if (!candidate.raw) {
      continue
    }

    const cidr = parseCIDR(candidate.raw)
    if (!cidr || seen.has(cidr.text)) {
      continue
    }

    seen.add(cidr.text)
    prefixes.push({ cidr, source: candidate.source })
  }

  return prefixes
}

export function findInterfaceNetworkMatches(
  ip: ParsedIPv4,
  interfaces: InterfaceProperties[] = [],
  options: { includeInactive?: boolean } = {},
): InterfaceNetworkMatch[] {
  const includeInactive = options.includeInactive ?? false
  const matches: InterfaceNetworkMatch[] = []

  for (const iface of interfaces) {
    const active = iface.active !== false
    if (!includeInactive && !active) {
      continue
    }

    for (const { cidr, source } of collectInterfacePrefixes(iface)) {
      if (!cidrContainsIPv4(cidr, ip)) {
        continue
      }

      matches.push({
        hostname: iface.hostname,
        interface: iface.interface,
        vrf: iface.vrf,
        prefix: cidr.text,
        prefixLength: cidr.prefixLength,
        primaryAddress: iface.primary_address,
        primaryNetwork: iface.primary_network,
        source,
        active,
        adminUp: iface.admin_up !== false,
      })
    }
  }

  return matches.sort((a, b) => {
    if (a.prefixLength !== b.prefixLength) return b.prefixLength - a.prefixLength
    if (a.active !== b.active) return a.active ? -1 : 1
    if (a.adminUp !== b.adminUp) return a.adminUp ? -1 : 1
    return `${a.hostname}\0${a.interface}\0${a.vrf}\0${a.prefix}`.localeCompare(`${b.hostname}\0${b.interface}\0${b.vrf}\0${b.prefix}`)
  })
}
