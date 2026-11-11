import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { LpmRoute } from '../../types'
import {
  BatfishFeatureTools,
  buildRoutePolicyPathParams,
  projectLpmRoutesForDisplay,
  ROUTE_POLICY_PATH_OPTIONS,
} from './BatfishFeatureTools'

const testRoutePolicies = vi.hoisted(() => ({ mutate: vi.fn() }))

vi.mock('../../hooks', () => {
  const idleMutation = () => ({
    data: undefined,
    error: null,
    isPending: false,
    isError: false,
    isSuccess: false,
    mutate: vi.fn(),
  })
  return {
    useA10VirtualServerConfiguration: idleMutation,
    useBidirectionalReachability: idleMutation,
    useCompareFilters: idleMutation,
    useComparePeerGroupPolicies: idleMutation,
    useCompareRoutePolicies: idleMutation,
    useLpmRoutes: idleMutation,
    usePrefixTracer: idleMutation,
    useResolveFilterSpecifier: idleMutation,
    useResolveInterfaceSpecifier: idleMutation,
    useResolveIpSpecifier: idleMutation,
    useResolveIpsOfLocationSpecifier: idleMutation,
    useResolveLocationSpecifier: idleMutation,
    useResolveNodeSpecifier: idleMutation,
    useSearchRoutePolicies: idleMutation,
    useSnapshots: () => ({ data: [] }),
    useTestRoutePolicies: () => ({ ...idleMutation(), mutate: testRoutePolicies.mutate }),
    useTransferBDDValidation: idleMutation,
    useUserProvidedLayer1Edges: idleMutation,
  }
})

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

describe('projectLpmRoutesForDisplay', () => {
  it('keeps only fields returned by the Batfish lpmRoutes question', () => {
    const route: LpmRoute = {
      node: 'core-rtr1',
      vrf: 'default',
      ip: '10.0.0.1',
      network: '10.0.0.1/32',
      num_routes: 1,
      next_hop: '',
      next_hop_interface: null,
      protocol: '',
    }

    expect(projectLpmRoutesForDisplay([route])).toEqual([{
      node: 'core-rtr1',
      vrf: 'default',
      ip: '10.0.0.1',
      network: '10.0.0.1/32',
      num_routes: 1,
    }])
  })
})

describe('buildRoutePolicyPathParams', () => {
  it('sends nothing when neither per path nor a path option is set', () => {
    expect(buildRoutePolicyPathParams(false, '')).toEqual({})
  })

  it('sends perPath only when it is checked and no path option is set', () => {
    expect(buildRoutePolicyPathParams(true, '')).toEqual({ perPath: true })
    expect(buildRoutePolicyPathParams(true, '  ')).toEqual({ perPath: true })
  })

  it('sends pathOption alone when one is selected', () => {
    expect(buildRoutePolicyPathParams(false, 'NON_OVERLAP')).toEqual({ pathOption: 'NON_OVERLAP' })
    expect(buildRoutePolicyPathParams(true, 'PER_PATH')).toEqual({ pathOption: 'PER_PATH' })
  })

  it('offers the Batfish path options', () => {
    expect(ROUTE_POLICY_PATH_OPTIONS).toEqual(['SINGLE', 'PER_PATH', 'NON_OVERLAP'])
  })
})

describe('BatfishFeatureTools test-route-policies direction', () => {
  it('sends the selected direction as in or out', () => {
    render(<BatfishFeatureTools />)
    fireEvent.click(screen.getByRole('button', { name: 'batfishTools.categories.policies' }))
    fireEvent.click(screen.getByRole('button', { name: 'batfishTools.operations.policies.test' }))
    const route = { network: '192.0.2.0/24', originatorIp: '0.0.0.0', originType: 'igp', protocol: 'bgp' }
    fireEvent.change(screen.getByLabelText('batfishTools.fields.inputRoutesJson'), {
      target: { value: JSON.stringify(route) },
    })
    const direction = screen.getByLabelText('batfishTools.fields.testDirection') as HTMLSelectElement
    expect(Array.from(direction.options, (option) => option.value)).toEqual(['in', 'out'])
    const run = () => fireEvent.click(screen.getByRole('button', { name: 'batfishTools.buttons.testRoutePolicies' }))

    run()
    expect(testRoutePolicies.mutate).toHaveBeenLastCalledWith({
      direction: 'in',
      inputRoutes: route,
      nodes: undefined,
      policies: undefined,
    })

    fireEvent.change(direction, { target: { value: 'out' } })
    run()
    expect(testRoutePolicies.mutate.mock.lastCall?.[0]).toMatchObject({ direction: 'out', inputRoutes: route })

    fireEvent.change(direction, { target: { value: 'in' } })
    run()
    expect(testRoutePolicies.mutate.mock.lastCall?.[0]).toMatchObject({ direction: 'in' })
    expect(testRoutePolicies.mutate).toHaveBeenCalledTimes(3)
  })
})
