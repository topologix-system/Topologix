import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useSnapshotStore } from '../../store'
import { NetworkAnalysisPanel } from './NetworkAnalysisPanel'

const filterLineReachability = vi.hoisted(() => ({ mutate: vi.fn() }))

vi.mock('../../hooks', () => {
  const query = () => ({ data: undefined, isLoading: false, error: null })
  const idleMutation = () => ({
    data: undefined,
    error: null,
    isPending: false,
    isError: false,
    isSuccess: false,
    mutate: vi.fn(),
  })
  const queryHooks = [
    'useVRRPProperties', 'useHSRPProperties', 'useMLAGProperties', 'useDuplicateRouterIDs', 'useSwitchingProperties',
    'useBGPEdges', 'useBGPProcessConfiguration', 'useBGPPeerConfiguration', 'useBGPSessionStatus',
    'useBGPSessionCompatibility', 'useBGPRib', 'useEIGRPEdges', 'useEIGRPInterfaces', 'useISISEdges',
    'useISISInterfaces', 'useISISLoopbackInterfaces', 'useBFDSessionStatus', 'useEVPNRib', 'useOSPFProcesses',
    'useOSPFAreas', 'useOSPFInterfaces', 'useOSPFSessions', 'useOSPFEdges', 'useNodes', 'useInterfaces', 'useRoutes',
    'useVlans', 'useIPOwners', 'usePhysicalEdges', 'useLayer3Edges', 'useLayer1Topology', 'useLayer2Topology',
    'useVXLANVNIProperties', 'useVXLANEdges', 'useIPSecSessionStatus', 'useIPSecEdges', 'useIPSecPeerConfiguration',
    'useInterfaceMTU', 'useIPSpaceAssignment', 'useF5VIPs', 'useVIModel', 'useDefinedStructures',
    'useReferencedStructures', 'useNamedStructures', 'useAAAAuthentication', 'useRoutePolicies',
  ]
  return {
    ...Object.fromEntries(queryHooks.map((name) => [name, query])),
    useFilterLineReachability: () => ({ ...idleMutation(), mutate: filterLineReachability.mutate }),
    useTestFilters: idleMutation,
    useFindMatchingFilterLines: idleMutation,
    useSearchFilters: idleMutation,
    useSearchRoutePolicies: idleMutation,
    useReduceReachability: idleMutation,
  }
})

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

vi.mock('./BatfishFeatureTools', () => ({ BatfishFeatureTools: () => null }))
vi.mock('./IPSearchPanel', () => ({ IPSearchPanel: () => null }))

function openFilterLineReachability() {
  render(<NetworkAnalysisPanel />)
  fireEvent.click(screen.getByRole('tab', { name: 'analysis.tabs.acl' }))
  fireEvent.click(screen.getByRole('button', { name: 'analysis.acl.filterLineReachability' }))
}

const lastRequest = () => filterLineReachability.mutate.mock.lastCall?.[0]

describe('NetworkAnalysisPanel filterLineReachability', () => {
  beforeEach(() => {
    filterLineReachability.mutate.mockReset()
    useSnapshotStore.setState({ currentSnapshotName: 'snapshot-a' })
  })

  it('sends ignoreComposites=true only when the box is checked', () => {
    openFilterLineReachability()
    const execute = () => fireEvent.click(screen.getByRole('button', { name: 'analysis.acl.execute' }))
    const ignoreComposites = screen.getByRole('checkbox', { name: 'analysis.acl.ignoreComposites' })
    expect(ignoreComposites).not.toBeChecked()

    execute()
    expect(lastRequest()).toBeUndefined()

    fireEvent.click(ignoreComposites)
    execute()
    expect(lastRequest()).toStrictEqual({ ignoreComposites: true })

    fireEvent.change(screen.getByRole('textbox', { name: 'analysis.acl.aria.filterName' }), { target: { value: ' ACL1 ' } })
    execute()
    expect(lastRequest()).toStrictEqual({ filters: 'ACL1', ignoreComposites: true })

    fireEvent.click(ignoreComposites)
    execute()
    expect(lastRequest()).toStrictEqual({ filters: 'ACL1' })
    expect(filterLineReachability.mutate).toHaveBeenCalledTimes(4)
  })
})
