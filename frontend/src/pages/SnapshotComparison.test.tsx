import { fireEvent, render, screen, within } from '@testing-library/react'
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { ComparisonResult, ModifiedRoute } from '../types'
import { SnapshotComparison } from './SnapshotComparison'

type CompareOutcome = { data: ComparisonResult } | { error: unknown }

const testState = vi.hoisted(() => ({
  outcomes: [] as CompareOutcome[],
}))

vi.mock('../hooks', () => ({
  useSnapshots: () => ({
    data: [{ name: 'base' }, { name: 'after-1' }, { name: 'after-2' }],
    isLoading: false,
  }),
  useCompareSnapshots: () => ({
    isPending: false,
    mutate: (
      _request: unknown,
      options: { onSuccess?: (data: ComparisonResult) => void; onError?: (error: unknown) => void }
    ) => {
      const outcome = testState.outcomes.shift()
      if (!outcome) return
      if ('data' in outcome) options.onSuccess?.(outcome.data)
      else options.onError?.(outcome.error)
    },
  }),
}))

vi.mock('react-i18next', async () => {
  const { translateEn } = await import('../__tests__/translateEn')
  return { useTranslation: () => ({ t: translateEn }) }
})

function result(overrides: Partial<ComparisonResult> = {}): ComparisonResult {
  return {
    base_snapshot: 'base',
    comparison_snapshot: 'after-1',
    nodes: { added: ['new-node'], removed: [], total_base: 1, total_comparison: 2 },
    edges: { added: [], removed: [], total_base: 0, total_comparison: 0 },
    routes: { added: [], removed: [], modified: [], total_base: 0, total_comparison: 0 },
    reachability: [],
    ...overrides,
  }
}

function serverError(status: number, data: unknown) {
  const config = { headers: new AxiosHeaders() }
  const response: AxiosResponse = { status, statusText: '', headers: {}, config, data }
  return new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_RESPONSE', config, {}, response)
}

function compare(comparison: string) {
  fireEvent.change(screen.getByLabelText('Select base snapshot'), { target: { value: 'base' } })
  fireEvent.change(screen.getByLabelText('Select comparison snapshot'), { target: { value: comparison } })
  fireEvent.click(screen.getByRole('button', { name: 'Compare selected snapshots' }))
}

function openTab(name: string) {
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Comparison tabs' })).getByRole('button', { name }))
}

describe('SnapshotComparison', () => {
  beforeEach(() => {
    testState.outcomes = []
    render(
      <MemoryRouter>
        <SnapshotComparison />
      </MemoryRouter>
    )
  })

  it('removes the previous result and shows the server message when a later comparison fails', () => {
    testState.outcomes.push({ data: result() }, { error: serverError(500, { status: 'error', message: 'simulated failure' }) })

    compare('after-1')
    expect(screen.getAllByRole('heading', { name: 'Node Changes' }).length).toBeGreaterThan(0)
    expect(screen.getByText('+ new-node')).toBeInTheDocument()

    compare('after-2')
    expect(screen.getByRole('alert')).toHaveTextContent('Comparison failed: simulated failure')
    expect(screen.queryByRole('heading', { name: 'Node Changes' })).toBeNull()
    expect(screen.queryByText('+ new-node')).toBeNull()
  })

  it('removes the previous result and shows a localized error when the same snapshot is selected twice', () => {
    testState.outcomes.push({ data: result() })

    compare('after-1')
    expect(screen.getByText('+ new-node')).toBeInTheDocument()

    compare('base')
    expect(screen.getByRole('alert')).toHaveTextContent('Please select different snapshots to compare')
    expect(screen.queryByRole('heading', { name: 'Node Changes' })).toBeNull()
    expect(screen.queryByText('+ new-node')).toBeNull()
  })

  it('shows the localized reachability note with the reason while the other diffs still render', () => {
    testState.outcomes.push({
      data: result({
        reachability_error: { message: 'Differential reachability failed', reason: 'no matching startLocation in both snapshots' },
      }),
    })

    compare('after-1')
    expect(screen.getByText('+ new-node')).toBeInTheDocument()
    expect(screen.getAllByRole('heading', { name: 'Node Changes' })[0].parentElement).toHaveTextContent(/\+1 added\s*-0 removed/)
    expect(screen.getByText('N/A')).toBeInTheDocument()
    expect(screen.getByText('could not be computed')).toBeInTheDocument()

    openTab('Reachability')
    expect(screen.getByRole('heading', { name: 'Reachability Changes' })).toBeInTheDocument()
    const note = screen.getByRole('status')
    expect(note).toHaveTextContent(
      'Differential reachability could not be computed for these snapshots. Node, topology and route changes are still shown.'
    )
    expect(note).toHaveTextContent('Reason: no matching startLocation in both snapshots')
    expect(note).not.toHaveTextContent('Differential reachability failed')
    expect(screen.queryByText('No reachability changes detected')).toBeNull()
  })

  function modifiedRoute(
    nextHops: Pick<ModifiedRoute, 'base_next_hop' | 'comparison_next_hop' | 'base_next_hops' | 'comparison_next_hops'>
  ): ComparisonResult {
    return result({
      routes: {
        added: [],
        removed: [],
        modified: [{
          node: 'r1',
          vrf: 'default',
          network: '10.9.0.0/24',
          ...nextHops,
          base_protocol: 'ospf',
          comparison_protocol: 'ospf',
        }],
        total_base: 2,
        total_comparison: 1,
      },
    })
  }

  it('renders every ECMP next hop of a modified route from the next-hop arrays', () => {
    testState.outcomes.push({
      data: modifiedRoute({
        base_next_hop: 'base-string-only',
        comparison_next_hop: 'comparison-string-only',
        base_next_hops: ['10.2.12.2', '10.2.13.2'],
        comparison_next_hops: ['10.2.13.2'],
      }),
    })

    compare('after-1')
    openTab('Routes')
    expect(screen.getByRole('heading', { name: 'Modified Routes (1)' })).toBeInTheDocument()
    expect(screen.getByRole('row', { name: 'Node VRF Network Change' })).toBeInTheDocument()
    expect(screen.getByText(/^NH:/)).toBeInTheDocument()
    expect(screen.getByText('10.2.12.2, 10.2.13.2')).toBeInTheDocument()
    expect(screen.getByText('10.2.13.2')).toBeInTheDocument()
    expect(screen.queryByText('base-string-only')).toBeNull()
    expect(screen.queryByText('comparison-string-only')).toBeNull()
  })

  it('falls back to the next-hop strings when the arrays are absent', () => {
    testState.outcomes.push({
      data: modifiedRoute({ base_next_hop: '10.2.12.2', comparison_next_hop: '10.2.13.2' }),
    })

    compare('after-1')
    openTab('Routes')
    expect(screen.getByText('10.2.12.2')).toBeInTheDocument()
    expect(screen.getByText('10.2.13.2')).toBeInTheDocument()
  })
})
