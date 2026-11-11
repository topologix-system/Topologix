import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { Layer1Edge, SnapshotInterfaces } from '../types/layer1'
import { Layer1TopologyEditor } from './Layer1TopologyEditor'

interface QueryState<T> {
  data: T | undefined
  isLoading: boolean
  isLoadingError: boolean
  error: unknown
}

const testState = vi.hoisted(() => ({
  topology: { data: undefined, isLoading: false, isLoadingError: false, error: null } as QueryState<unknown>,
  interfaces: { data: undefined, isLoading: false, isLoadingError: false, error: null } as QueryState<unknown>,
}))

vi.mock('../hooks', async () => {
  const { useComboboxFilter } = await import('../hooks/useComboboxFilter')
  return {
    useComboboxFilter,
    useLayer1TopologyEditor: () => testState.topology,
    useSnapshotInterfacesList: () => testState.interfaces,
    useSaveLayer1TopologyEditor: () => ({ isPending: false, isError: false, error: null, mutate: vi.fn() }),
  }
})

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, params?: Record<string, unknown>) =>
      params?.name !== undefined ? `${key}:${String(params.name)}` : key,
  }),
}))

vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
)

const INTERFACES: SnapshotInterfaces = {
  r1: { hostname: 'r1', interfaces: [{ name: 'Gi0/0', active: true }, { name: 'Gi0/1', active: true }] },
  r2: { hostname: 'r2', interfaces: [{ name: 'Gi0/0', active: true }] },
}
const EDGE: Layer1Edge = {
  node1: { hostname: 'r1', interfaceName: 'Gi0/1' },
  node2: { hostname: 'r2', interfaceName: 'Gi0/0' },
}

function httpError(status: number, data: unknown) {
  const config = { headers: new AxiosHeaders() }
  const response: AxiosResponse = { status, statusText: '', headers: {}, config, data }
  return new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_REQUEST', config, {}, response)
}

function failed(error: unknown): QueryState<unknown> {
  return { data: undefined, isLoading: false, isLoadingError: true, error }
}

function loaded<T>(data: T): QueryState<unknown> {
  return { data, isLoading: false, isLoadingError: false, error: null }
}

function renderEditor() {
  return render(
    <MemoryRouter initialEntries={['/snapshots/snap-a/layer1-editor']}>
      <Routes>
        <Route path="/snapshots/:snapshotName/layer1-editor" element={<Layer1TopologyEditor />} />
      </Routes>
    </MemoryRouter>
  )
}

function formValues() {
  return screen.getAllByRole('combobox').map((input) => (input as HTMLInputElement).value)
}

function edge(hostname1: string, interfaceName1: string, hostname2: string, interfaceName2: string): Layer1Edge {
  return { node1: { hostname: hostname1, interfaceName: interfaceName1 }, node2: { hostname: hostname2, interfaceName: interfaceName2 } }
}

function tableRows() {
  const [, body] = within(screen.getByRole('table')).getAllByRole('rowgroup')
  return within(body).getAllByRole('row').map((row) => {
    const cells = within(row).getAllByRole('cell').map((cell) => cell.textContent?.trim() ?? '')
    return `${cells[1]} ${cells[2]} - ${cells[4]} ${cells[5]}`
  })
}

function deleteRow(index: number) {
  fireEvent.click(screen.getAllByTitle('layer1Editor.delete')[index])
}

describe('Layer1TopologyEditor load errors', () => {
  beforeEach(() => {
    testState.topology = loaded({ edges: [] })
    testState.interfaces = loaded(INTERFACES)
  })

  it('shows a not-found error instead of an empty editor for a 404', () => {
    testState.topology = failed(httpError(404, { status: 'error', message: "Snapshot 'snap-a' not found" }))
    testState.interfaces = failed(httpError(404, { status: 'error', message: "Snapshot 'snap-a' not found" }))
    renderEditor()

    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('layer1Editor.errors.loadFailed')
    expect(alert).toHaveTextContent('layer1Editor.errors.notFound:snap-a')
    expect(screen.getByRole('heading', { level: 1, name: 'layer1Editor.title' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'layer1Editor.back' })).toHaveAttribute('href', '/snapshots')
    expect(screen.queryByRole('button', { name: 'layer1Editor.saveAll' })).toBeNull()
    expect(screen.queryByText('layer1Editor.addConnection')).toBeNull()
    expect(screen.queryByText('layer1Editor.noDevices')).toBeNull()
  })

  it('shows an access-denied error when only the interfaces query is forbidden', () => {
    testState.interfaces = failed(httpError(403, { status: 'error', message: 'Permission denied' }))
    renderEditor()

    expect(screen.getByRole('alert')).toHaveTextContent('layer1Editor.errors.accessDenied:snap-a')
    expect(screen.queryByRole('button', { name: 'layer1Editor.saveAll' })).toBeNull()
  })

  it('shows the server message for other failures', () => {
    testState.topology = failed(httpError(500, { status: 'error', message: 'Batfish is unreachable' }))
    renderEditor()

    expect(screen.getByRole('alert')).toHaveTextContent('Batfish is unreachable')
  })

  it('keeps the editor when a refetch fails after the data loaded', () => {
    testState.topology = { data: { edges: [] }, isLoading: false, isLoadingError: false, error: httpError(500, {}) }
    renderEditor()

    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.getByRole('button', { name: 'layer1Editor.saveAll' })).toBeInTheDocument()
  })
})

describe('Layer1TopologyEditor connection form', () => {
  beforeEach(() => {
    testState.topology = loaded({ edges: [EDGE] })
    testState.interfaces = loaded(INTERFACES)
  })

  it('pre-fills the form on Edit and returns to an empty Add form on Cancel', () => {
    renderEditor()
    expect(screen.getByText('layer1Editor.addConnection')).toBeInTheDocument()
    expect(formValues()).toEqual(['', '', '', ''])

    fireEvent.click(screen.getByTitle('layer1Editor.edit'))
    expect(screen.getByText('layer1Editor.editConnection')).toBeInTheDocument()
    expect(formValues()).toEqual(['r1', 'Gi0/1', 'r2', 'Gi0/0'])

    fireEvent.click(screen.getByRole('button', { name: 'layer1Editor.cancel' }))
    expect(screen.getByText('layer1Editor.addConnection')).toBeInTheDocument()
    expect(formValues()).toEqual(['', '', '', ''])
  })
})

describe('Layer1TopologyEditor delete while editing', () => {
  beforeEach(() => {
    testState.topology = loaded({
      edges: [edge('r2', 'Gi0/0', 'r1', 'Gi0/0'), edge('r2', 'Gi0/0', 'r1', 'Gi0/1'), edge('r1', 'Gi0/1', 'r2', 'Gi0/0')],
    })
    testState.interfaces = loaded(INTERFACES)
    vi.spyOn(window, 'confirm').mockReturnValue(true)
  })

  it('keeps editing the same connection when a row above it is deleted, and Update overwrites that connection', async () => {
    renderEditor()
    fireEvent.click(screen.getAllByTitle('layer1Editor.edit')[2])
    expect(formValues()).toEqual(['r1', 'Gi0/1', 'r2', 'Gi0/0'])

    const interface1 = screen.getAllByRole('combobox')[1]
    fireEvent.change(interface1, { target: { value: 'Gi0/0' } })
    fireEvent.mouseDown(await screen.findByRole('option', { name: 'Gi0/0' }), { button: 0 })
    await waitFor(() => expect(formValues()).toEqual(['r1', 'Gi0/0', 'r2', 'Gi0/0']))

    deleteRow(0)
    expect(tableRows()).toEqual(['r2 Gi0/0 - r1 Gi0/1', 'r1 Gi0/1 - r2 Gi0/0'])
    expect(screen.getByText('layer1Editor.editConnection')).toBeInTheDocument()
    expect(formValues()).toEqual(['r1', 'Gi0/0', 'r2', 'Gi0/0'])

    fireEvent.click(screen.getByRole('button', { name: 'layer1Editor.update' }))
    expect(tableRows()).toEqual(['r2 Gi0/0 - r1 Gi0/1', 'r1 Gi0/0 - r2 Gi0/0'])
    expect(screen.getByText('layer1Editor.addConnection')).toBeInTheDocument()
  })

  it('returns to the Add form when the connection being edited is deleted', () => {
    renderEditor()
    fireEvent.click(screen.getAllByTitle('layer1Editor.edit')[1])
    expect(formValues()).toEqual(['r2', 'Gi0/0', 'r1', 'Gi0/1'])

    deleteRow(1)
    expect(tableRows()).toEqual(['r2 Gi0/0 - r1 Gi0/0', 'r1 Gi0/1 - r2 Gi0/0'])
    expect(screen.getByText('layer1Editor.addConnection')).toBeInTheDocument()
    expect(formValues()).toEqual(['', '', '', ''])
  })

  it('keeps the edited index when a row below it is deleted', () => {
    renderEditor()
    fireEvent.click(screen.getAllByTitle('layer1Editor.edit')[0])
    deleteRow(2)
    fireEvent.click(screen.getByRole('button', { name: 'layer1Editor.update' }))
    expect(tableRows()).toEqual(['r2 Gi0/0 - r1 Gi0/0', 'r2 Gi0/0 - r1 Gi0/1'])
  })
})
