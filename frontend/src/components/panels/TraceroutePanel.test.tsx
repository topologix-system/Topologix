import { fireEvent, render, screen } from '@testing-library/react'
import { AxiosError, type AxiosResponse } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useSnapshotStore } from '../../store'
import {
  buildTracerouteRequest,
  EMPTY_HEADER_LIST_TEXT,
  splitCommaList,
  TraceroutePanel,
} from './TraceroutePanel'

const mocks = vi.hoisted(() => ({
  tracerouteMutate: vi.fn(),
  bidirectionalMutate: vi.fn(),
  tracerouteError: null as unknown,
  tracerouteData: undefined as unknown,
}))

vi.mock('../../hooks/useAnalysis', () => ({
  useTraceroute: () => ({
    mutate: mocks.tracerouteMutate,
    reset: vi.fn(),
    isPending: false,
    data: mocks.tracerouteData,
    error: mocks.tracerouteError,
  }),
  useBidirectionalTraceroute: () => ({
    mutate: mocks.bidirectionalMutate,
    reset: vi.fn(),
    isPending: false,
    data: undefined,
    error: null,
  }),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

vi.mock('../ProtocolSelector', () => ({
  ProtocolSelector: () => null,
}))

describe('splitCommaList', () => {
  it('trims items and drops empty ones', () => {
    expect(splitCommaList('ssh, https')).toEqual(['ssh', 'https'])
    expect(splitCommaList('ssh,')).toEqual(['ssh'])
    expect(splitCommaList(' , ,')).toEqual([])
    expect(splitCommaList('')).toEqual([])
  })
})

describe('buildTracerouteRequest', () => {
  it('sends applications as a list and numeric header fields as integer space strings', () => {
    const request = buildTracerouteRequest(
      { headers: { dstIps: '10.0.0.1' }, startLocation: 'core-rtr1' },
      { applications: 'ssh, https', icmpTypes: '0, 8', icmpCodes: '0', dscps: '0-63', ecns: '0, 1,' },
    )
    expect(request).toEqual({
      headers: {
        dstIps: '10.0.0.1',
        applications: ['ssh', 'https'],
        icmpTypes: '0,8',
        icmpCodes: '0',
        dscps: '0-63',
        ecns: '0,1',
      },
      startLocation: 'core-rtr1',
    })
  })

  it('omits empty list fields instead of sending 0 or empty lists', () => {
    const request = buildTracerouteRequest({ headers: { dstIps: '10.0.0.1' } }, { ...EMPTY_HEADER_LIST_TEXT, dscps: ' , ' })
    expect(request).toEqual({ headers: { dstIps: '10.0.0.1' } })
  })
})

describe('TraceroutePanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.tracerouteError = null
    mocks.tracerouteData = undefined
    useSnapshotStore.setState({ currentSnapshotName: 'fixture' })
  })

  function flowDetails() {
    const pairs: Record<string, string> = {}
    for (const dt of Array.from(document.querySelectorAll('dl dt'))) {
      pairs[dt.textContent ?? ''] = dt.nextElementSibling?.textContent ?? ''
    }
    return pairs
  }

  it('shows the ICMP type Batfish reports as icmpVar in the flow details', () => {
    mocks.tracerouteData = [{
      flow: { srcIp: '10.0.0.2', dstIp: '10.0.0.1', ipProtocol: 'ICMP', icmpVar: 8, icmpType: null, icmpCode: 0 },
      traces: [],
    }]
    render(<TraceroutePanel />)
    expect(flowDetails()).toMatchObject({ Protocol: 'ICMP', 'ICMP Type': '8', 'ICMP Code': '0' })
  })

  it('falls back to icmpType and hides the ICMP type when neither field is set', () => {
    mocks.tracerouteData = [
      { flow: { dstIp: '10.0.0.1', ipProtocol: 'ICMP', icmpType: 0 }, traces: [] },
    ]
    const { unmount } = render(<TraceroutePanel />)
    expect(flowDetails()['ICMP Type']).toBe('0')
    unmount()

    mocks.tracerouteData = [
      { flow: { dstIp: '10.0.0.1', ipProtocol: 'TCP', dstPort: 22, icmpVar: null, icmpType: null, icmpCode: null }, traces: [] },
    ]
    render(<TraceroutePanel />)
    expect(flowDetails()).not.toHaveProperty('ICMP Type')
    expect(flowDetails()).not.toHaveProperty('ICMP Code')
    expect(flowDetails()['Dst Port']).toBe('22')
  })

  it('keeps typed commas in the list inputs and parses them on submit', () => {
    render(<TraceroutePanel />)
    fireEvent.change(screen.getByLabelText(/traceroute.fields.destinationIp/), { target: { value: '10.0.0.1' } })
    fireEvent.click(screen.getByRole('button', { name: 'traceroute.sections.advanced' }))

    const applications = screen.getByLabelText('traceroute.fields.applications') as HTMLInputElement
    fireEvent.change(applications, { target: { value: 'ssh,' } })
    expect(applications.value).toBe('ssh,')
    fireEvent.change(applications, { target: { value: 'ssh, https' } })
    expect(applications.value).toBe('ssh, https')

    const dscps = screen.getByLabelText('traceroute.fields.dscpValues') as HTMLInputElement
    fireEvent.change(dscps, { target: { value: '0, ' } })
    expect(dscps.value).toBe('0, ')
    fireEvent.change(dscps, { target: { value: '0, 46' } })

    fireEvent.click(screen.getByRole('button', { name: 'traceroute.buttons.run' }))
    expect(mocks.tracerouteMutate).toHaveBeenCalledWith({
      headers: { dstIps: '10.0.0.1', applications: ['ssh', 'https'], dscps: '0,46' },
    })
  })

  it('shows the server error message instead of the generic request failure text', () => {
    mocks.tracerouteError = new AxiosError(
      'Request failed with status code 400',
      'ERR_BAD_REQUEST',
      undefined,
      undefined,
      { status: 400, data: { status: 'error', message: 'Invalid IP address: 999.1.1.1' } } as AxiosResponse,
    )
    render(<TraceroutePanel />)
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('Invalid IP address: 999.1.1.1')
    expect(alert).not.toHaveTextContent('Request failed with status code 400')
  })

  it('checks Bidirectional with ArrowRight in the trace mode radiogroup', () => {
    render(<TraceroutePanel />)
    const unidirectional = screen.getByRole('radio', { name: 'traceroute.modes.unidirectional' })
    const bidirectional = screen.getByRole('radio', { name: 'traceroute.modes.bidirectional' })
    expect(unidirectional).toHaveAttribute('tabindex', '0')
    expect(bidirectional).toHaveAttribute('tabindex', '-1')

    unidirectional.focus()
    fireEvent.keyDown(unidirectional, { key: 'ArrowRight' })
    expect(bidirectional).toHaveAttribute('aria-checked', 'true')
    expect(bidirectional).toHaveAttribute('tabindex', '0')
    expect(document.activeElement).toBe(bidirectional)
  })
})
