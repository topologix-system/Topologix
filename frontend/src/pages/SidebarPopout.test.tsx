import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useUIStore } from '../store'
import { SidebarPopout } from './SidebarPopout'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

vi.mock('../components/NodeSelector', () => ({
  NodeSelector: () => <div>node selector</div>,
}))

vi.mock('../components/panels/OverviewPanel', () => ({ default: () => <div>overview panel</div> }))
vi.mock('../components/panels/NodeDetailsPanel', () => ({ default: () => <div>node panel</div> }))
vi.mock('../components/panels/EdgeDetailsPanel', () => ({ default: () => <div>edge panel</div> }))
vi.mock('../components/panels/ValidationPanel', () => ({ default: () => <div>validation panel</div> }))
vi.mock('../components/panels/NetworkAnalysisPanel', () => ({ default: () => <div>analysis panel</div> }))
vi.mock('../components/panels/TraceroutePanel', () => ({ default: () => <div>traceroute panel</div> }))

const originalUrl = window.location.href

describe('SidebarPopout', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/sidebar-popout?tab=overview')
    useUIStore.setState({ sidebarTab: 'overview', selectedNodeId: null, selectedEdgeId: null })
  })

  afterEach(() => {
    window.history.replaceState({}, '', originalUrl)
  })

  it('switches to the Node tab when a node is selected through the store', async () => {
    render(<SidebarPopout />)
    expect(await screen.findByText('overview panel')).toBeInTheDocument()
    expect(document.getElementById('tab-overview')).toHaveAttribute('aria-selected', 'true')

    act(() => {
      useUIStore.getState().setSelectedNode('core-rtr1')
    })

    expect(await screen.findByText('node panel')).toBeInTheDocument()
    expect(document.getElementById('tab-node-details')).toHaveAttribute('aria-selected', 'true')
  })

  it('opens the tab requested in the URL', async () => {
    window.history.replaceState({}, '', '/sidebar-popout?tab=traceroute')
    render(<SidebarPopout />)
    expect(await screen.findByText('traceroute panel')).toBeInTheDocument()
    expect(document.getElementById('tab-traceroute')).toHaveAttribute('aria-selected', 'true')
    expect(useUIStore.getState().sidebarTab).toBe('traceroute')
  })

  it('moves to the next tab with ArrowRight', async () => {
    render(<SidebarPopout />)
    await screen.findByText('overview panel')
    const overview = document.getElementById('tab-overview') as HTMLElement
    overview.focus()
    fireEvent.keyDown(overview, { key: 'ArrowRight' })

    const nodeTab = document.getElementById('tab-node-details')
    expect(nodeTab).toHaveAttribute('aria-selected', 'true')
    expect(document.activeElement).toBe(nodeTab)
    expect(useUIStore.getState().sidebarTab).toBe('node-details')
  })
})
