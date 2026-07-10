import { StreamLanguage, type StringStream } from '@codemirror/language'

const KEYWORDS = new Set([
  'access-list',
  'address',
  'aggregate-address',
  'area',
  'bgp',
  'bridge-domain',
  'community',
  'crypto',
  'deny',
  'description',
  'edit',
  'enable',
  'exit',
  'filter',
  'firewall',
  'hostname',
  'interface',
  'ip',
  'ipv6',
  'line',
  'logging',
  'match',
  'name-server',
  'nat',
  'neighbor',
  'network',
  'ntp',
  'ospf',
  'permit',
  'policy',
  'prefix-list',
  'protocols',
  'route',
  'route-map',
  'router',
  'security',
  'service',
  'set',
  'snmp-server',
  'spanning-tree',
  'static',
  'system',
  'term',
  'then',
  'unit',
  'version',
  'vlan',
  'vrf',
  'zone',
])

const INTERFACE_PATTERN =
  /(?:[A-Za-z]*Ethernet|Eth|Gi|Te|Fa|Fo|Hu|Lo|Loopback|Po|Port-channel|Vlan|Bundle-Ether|ae|ge-|xe-|et-|irb)[A-Za-z0-9/_.:-]*/i
const IPV4_PREFIX_PATTERN = /(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?/
const IPV6_PREFIX_PATTERN = /(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?:\/\d{1,3})?/i
const NUMBER_PATTERN = /(?:0x[0-9a-f]+|\d+(?:\.\d+)?)/i
const WORD_PATTERN = /[A-Za-z][A-Za-z0-9_-]*/

function eatKeyword(stream: StringStream) {
  const word = stream.match(WORD_PATTERN)
  if (!word || typeof word === 'boolean') return null

  const value = word[0]
  return KEYWORDS.has(value.toLowerCase()) ? 'keyword' : 'variableName'
}

export const networkConfigLanguage = StreamLanguage.define({
  name: 'network-config',
  token(stream) {
    if (stream.sol() && stream.match(/\s*[!#].*/)) {
      return 'comment'
    }

    if (stream.eatSpace()) {
      return null
    }

    if (stream.match(/"(?:[^"\\]|\\.)*"/) || stream.match(/'(?:[^'\\]|\\.)*'/)) {
      return 'string'
    }

    if (stream.match(INTERFACE_PATTERN)) {
      return 'tag'
    }

    if (stream.match(IPV4_PREFIX_PATTERN) || stream.match(IPV6_PREFIX_PATTERN)) {
      return 'atom'
    }

    if (stream.match(NUMBER_PATTERN)) {
      return 'number'
    }

    const keywordToken = eatKeyword(stream)
    if (keywordToken) {
      return keywordToken
    }

    stream.next()
    return null
  },
})
