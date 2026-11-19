import { describe, expect, it } from 'vitest'

import { describeStepDetail, type StepDetailValue } from './traceStepDetail'

const text = (value: string): StepDetailValue => ({ kind: 'text', text: value })

/** Plain-text lines of a described value, two spaces per nesting level and `N.` before list items */
function toLines(value: StepDetailValue | null, indent = ''): string[] {
  if (!value) return []
  if (value.kind === 'text') return [`${indent}${value.text}`]
  if (value.kind === 'list') {
    return value.items.flatMap((item, index) => [`${indent}${index + 1}.`, ...toLines(item, `${indent}  `)])
  }
  return value.entries.flatMap(({ key, value: entryValue }) =>
    entryValue.kind === 'text'
      ? [`${indent}${key}: ${entryValue.text}`]
      : [`${indent}${key}:`, ...toLines(entryValue, `${indent}  `)]
  )
}

describe('describeStepDetail', () => {
  it('lists every field of a routing step, nested objects and route lists indented under their key', () => {
    const detail = {
      arpIp: '10.0.3.2',
      forwardingDetail: {
        outputInterface: 'GigabitEthernet0/1',
        resolvedNextHopIp: '10.0.3.2',
        type: 'ForwardedOutInterface',
      },
      outputInterface: 'GigabitEthernet0/1',
      routes: [
        {
          admin: 110,
          metric: 47,
          network: '10.0.49.0/30',
          nextHop: { interface: 'GigabitEthernet0/1', ip: '10.0.3.2', type: 'interface' },
          nextHopIp: null,
          protocol: 'ospf',
        },
        {
          admin: 1,
          metric: 0,
          network: '10.0.50.0/30',
          nextHop: { ip: '10.0.4.2', type: 'ip' },
          nextHopIp: null,
          protocol: 'static',
        },
      ],
    }

    expect(toLines(describeStepDetail(detail))).toEqual([
      'arpIp: 10.0.3.2',
      'forwardingDetail:',
      '  type: ForwardedOutInterface',
      '  outputInterface: GigabitEthernet0/1',
      '  resolvedNextHopIp: 10.0.3.2',
      'outputInterface: GigabitEthernet0/1',
      'routes:',
      '  1.',
      '    admin: 110',
      '    metric: 47',
      '    network: 10.0.49.0/30',
      '    nextHop:',
      '      type: interface',
      '      interface: GigabitEthernet0/1',
      '      ip: 10.0.3.2',
      '    protocol: ospf',
      '  2.',
      '    admin: 1',
      '    metric: 0',
      '    network: 10.0.50.0/30',
      '    nextHop:',
      '      type: ip',
      '      ip: 10.0.4.2',
      '    protocol: static',
    ])
  })

  it('shows a transformation step with each flow diff as its own group', () => {
    const detail = {
      flowDiffs: [
        { fieldName: 'srcIp', newValue: '203.0.113.1', oldValue: '10.0.0.5' },
        { fieldName: 'srcPort', newValue: '40000', oldValue: '5000' },
      ],
      transformationType: 'SOURCE_NAT',
    }

    expect(toLines(describeStepDetail(detail))).toEqual([
      'flowDiffs:',
      '  1.',
      '    fieldName: srcIp',
      '    newValue: 203.0.113.1',
      '    oldValue: 10.0.0.5',
      '  2.',
      '    fieldName: srcPort',
      '    newValue: 40000',
      '    oldValue: 5000',
      'transformationType: SOURCE_NAT',
    ])
  })

  it('joins an array of scalars on one line and keeps zero and false values', () => {
    expect(
      describeStepDetail({
        sessionScope: { incomingInterfaces: ['ethernet1/1', 'ethernet1/2'] },
        flow: { dscp: 0, dstPort: 22, ingressVrf: 'default', tcpFlagsSyn: 1 },
        matched: false,
      })
    ).toEqual({
      kind: 'entries',
      entries: [
        {
          key: 'sessionScope',
          value: { kind: 'entries', entries: [{ key: 'incomingInterfaces', value: text('ethernet1/1, ethernet1/2') }] },
        },
        {
          key: 'flow',
          value: {
            kind: 'entries',
            entries: [
              { key: 'dscp', value: text('0') },
              { key: 'dstPort', value: text('22') },
              { key: 'ingressVrf', value: text('default') },
              { key: 'tcpFlagsSyn', value: text('1') },
            ],
          },
        },
        { key: 'matched', value: text('false') },
      ],
    })
  })

  it('leaves out null, undefined, empty strings, empty arrays and empty objects at every level', () => {
    expect(
      toLines(
        describeStepDetail({
          filter: 'acl-in',
          filterType: 'INGRESS_FILTER',
          flow: { dstIp: '10.0.0.1', dstPort: null, ingressInterface: undefined, ingressNode: '' },
          inputInterface: '',
          sessionAction: {},
          transformation: [],
          routes: [{ nextHop: {}, nextHopIp: null }],
          tags: [null, '', 'core'],
        })
      )
    ).toEqual([
      'filter: acl-in',
      'filterType: INGRESS_FILTER',
      'flow:',
      '  dstIp: 10.0.0.1',
      'tags: core',
    ])
  })

  it('returns nothing for a detail without any value to show', () => {
    expect(describeStepDetail(null)).toBeNull()
    expect(describeStepDetail(undefined)).toBeNull()
    expect(describeStepDetail('')).toBeNull()
    expect(describeStepDetail({})).toBeNull()
    expect(describeStepDetail([])).toBeNull()
    expect(describeStepDetail({ outputInterface: null, resolvedNexthopIp: null })).toBeNull()
  })

  it('shows a plain-text detail as it is', () => {
    expect(describeStepDetail('Forwarded out interface: GigabitEthernet0/1')).toEqual(
      text('Forwarded out interface: GigabitEthernet0/1')
    )
  })

  it('turns other shapes into readable lines without throwing', () => {
    expect(describeStepDetail(42)).toEqual(text('42'))
    expect(describeStepDetail(true)).toEqual(text('true'))
    expect(describeStepDetail(['a', 1, null])).toEqual(text('a, 1'))
    expect(toLines(describeStepDetail([{ node: 'r1' }, 'raw', [1, 2]]))).toEqual([
      '1.',
      '  node: r1',
      '2.',
      '  raw',
      '3.',
      '  1, 2',
    ])
  })

  it('puts a type field first and keeps the received order of the other fields', () => {
    const value = describeStepDetail({ vni: 5000, vtep: '192.0.2.1', type: 'ForwardedIntoVxlanTunnel' })
    expect(value?.kind === 'entries' && value.entries.map((entry) => entry.key)).toEqual(['type', 'vni', 'vtep'])
  })
})
