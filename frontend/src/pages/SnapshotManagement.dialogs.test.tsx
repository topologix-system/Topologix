import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { flushSync } from 'react-dom'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { Snapshot } from '../types'
import { useSnapshotStore } from '../store'
import { SnapshotManagement } from './SnapshotManagement'

const testState = vi.hoisted(() => ({
  snapshots: [] as Snapshot[],
  uploadPending: false,
  failCreate: null as ((error: unknown) => void) | null,
}))

vi.mock('../hooks', async () => {
  const { useState } = await import('react')
  const idleMutation = () => ({ isPending: false, variables: undefined, mutate: vi.fn() })
  /** Create mutation that stays pending until testState.failCreate settles it with an error */
  const useCreateSnapshot = () => {
    const [isPending, setIsPending] = useState(false)
    return {
      isPending,
      variables: undefined,
      mutate: (_variables: unknown, options?: { onError?: (error: unknown) => void }) => {
        setIsPending(true)
        testState.failCreate = (error) => {
          setIsPending(false)
          options?.onError?.(error)
        }
      },
    }
  }
  return {
    snapshotKeys: { files: (name: string) => ['snapshots', name, 'files'] },
    useSnapshots: () => ({ data: testState.snapshots, isLoading: false }),
    useSnapshotFiles: () => ({ data: [] }),
    useConfigFileContent: () => ({ data: undefined, isLoading: false, isError: false, error: null, refetch: vi.fn() }),
    useCreateSnapshot,
    useDeleteSnapshot: idleMutation,
    useUpdateSnapshot: idleMutation,
    useUploadFile: () => ({ isPending: testState.uploadPending, variables: undefined, mutate: vi.fn() }),
    useUpdateSnapshotFileFormat: idleMutation,
    useUpdateConfigFileContent: idleMutation,
    useDeleteSnapshotFile: idleMutation,
    useActivateSnapshot: idleMutation,
    useParseResultSummary: () => ({
      summary: {
        severity: 'success',
        totalFiles: 0,
        passedFiles: 0,
        partialFiles: 0,
        failedFiles: 0,
        unknownFiles: 0,
        warningFiles: 0,
        initIssues: 0,
        parseWarnings: 0,
        formats: {},
        failedFileNames: [],
        partialFileNames: [],
        unknownFileNames: [],
      },
      isLoading: false,
      isError: false,
    }),
  }
})

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
)

Element.prototype.getAnimations = () => []

vi.mock('../components/ConfigFileEditor', () => ({ ConfigFileEditor: () => null }))
vi.mock('../components/AdvancedArtifactPanel', () => ({ AdvancedArtifactPanel: () => null }))
vi.mock('../components/validation/ParseResultDetails', () => ({ ParseResultSummaryCard: () => null }))

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const router = createMemoryRouter([{ path: '/snapshots', element: <SnapshotManagement /> }], {
    initialEntries: ['/snapshots'],
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
}

const createDialog = () => document.querySelector('[role="dialog"][aria-labelledby="create-dialog-title"]')
const pasteDialog = () => document.querySelector('[role="dialog"][aria-labelledby="paste-create-dialog-title"]')
const pressEscape = (target: Element | Document = document.activeElement ?? document) =>
  fireEvent.keyDown(target, { key: 'Escape' })
const discardConfirm = () => screen.queryByRole('dialog', { name: 'snapshots.pasteCreate.discardTitle' })
const pressComposingEscape = (target: Element, init: KeyboardEventInit) =>
  fireEvent.keyDown(target, { key: 'Escape', ...init })

function startCreateRequest(name = 'new-snapshot') {
  fireEvent.click(screen.getByRole('button', { name: 'snapshots.newSnapshot' }))
  fireEvent.change(document.getElementById('snapshot-name-input')!, { target: { value: name } })
  fireEvent.click(screen.getByRole('button', { name: 'common.create' }))
  expect(screen.getByRole('button', { name: 'snapshots.createDialog.creating' })).toBeDisabled()
}

/**
 * Runs a dispatch with a document listener (added after the page's own) that flushes React's pending
 * work synchronously, like the browser's microtask checkpoint between listeners of a real user event:
 * a dialog mounted by the page's listener registers its window listeners before the event reaches window
 */
function withBrowserFlush(type: string, dispatch: () => void) {
  const flush = () => flushSync(() => {})
  document.addEventListener(type, flush)
  try {
    dispatch()
  } finally {
    document.removeEventListener(type, flush)
  }
}

const settle = () => act(() => new Promise<void>((resolve) => setTimeout(resolve, 50)))

function openPasteDialog({ selectSnapshot = true } = {}) {
  if (selectSnapshot) fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
  fireEvent.click(screen.getByRole('button', { name: 'snapshots.pasteCreate.open' }))
  expect(pasteDialog()).not.toBeNull()
  return screen.getByRole('textbox', { name: 'snapshots.pasteCreate.contentLabel' }) as HTMLTextAreaElement
}

describe('SnapshotManagement dialogs and Escape', () => {
  beforeEach(() => {
    testState.snapshots = [{ name: 'snapshot-a', file_count: 0, created_at: '2026-01-01T00:00:00Z', size_bytes: 0 }]
    testState.uploadPending = false
    testState.failCreate = null
    useSnapshotStore.setState({ currentSnapshotName: null, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
  })

  it('closes the create dialog on Escape and resets its fields', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'snapshots.newSnapshot' }))
    const name = document.getElementById('snapshot-name-input') as HTMLInputElement
    expect(document.activeElement).toBe(name)
    fireEvent.change(name, { target: { value: 'draft-name' } })

    pressEscape()
    expect(createDialog()).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'snapshots.newSnapshot' }))
    expect((document.getElementById('snapshot-name-input') as HTMLInputElement).value).toBe('')
  })

  it('keeps the create dialog open when Escape only closes the open folder list', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'snapshots.newSnapshot' }))
    const folder = document.getElementById('snapshot-folder-create-input') as HTMLInputElement
    act(() => folder.focus())
    fireEvent.change(folder, { target: { value: 'group-a' } })
    expect(await screen.findByRole('listbox')).toBeInTheDocument()

    pressEscape(folder)
    await waitFor(() => expect(screen.queryByRole('listbox')).toBeNull())
    expect(createDialog()).not.toBeNull()
    expect(folder.value).toBe('group-a')

    pressEscape(folder)
    await waitFor(() => expect(createDialog()).toBeNull())
  })

  it('closes the paste-create dialog on Escape', () => {
    renderPage()
    const content = openPasteDialog()

    pressEscape(content)
    expect(pasteDialog()).toBeNull()
    expect(discardConfirm()).toBeNull()
  })

  it('asks before Escape or a backdrop click discards pasted text', async () => {
    renderPage()
    const content = openPasteDialog()
    fireEvent.change(content, { target: { value: 'hostname r1\n' } })

    pressEscape(content)
    const confirm = await screen.findByRole('dialog', { name: 'snapshots.pasteCreate.discardTitle' })
    expect(pasteDialog()).not.toBeNull()
    fireEvent.click(within(confirm).getByRole('button', { name: 'common.cancel' }))
    await waitFor(() => expect(discardConfirm()).toBeNull())
    expect(pasteDialog()).not.toBeNull()
    expect(content.value).toBe('hostname r1\n')

    fireEvent.click(pasteDialog()!)
    const again = await screen.findByRole('dialog', { name: 'snapshots.pasteCreate.discardTitle' })
    fireEvent.click(within(again).getByRole('button', { name: 'snapshots.pasteCreate.discardConfirm' }))
    await waitFor(() => expect(pasteDialog()).toBeNull())
    await waitFor(() => expect(discardConfirm()).toBeNull())

    expect(openPasteDialog({ selectSnapshot: false }).value).toBe('')
  })

  it('keeps the discard confirmation opened by Escape open; a second Escape cancels it and keeps the draft', async () => {
    renderPage()
    const content = openPasteDialog()
    fireEvent.change(content, { target: { value: 'hostname r1\n' } })

    withBrowserFlush('keydown', () => pressEscape(content))
    await screen.findByRole('dialog', { name: 'snapshots.pasteCreate.discardTitle' })
    await settle()
    expect(discardConfirm()).not.toBeNull()
    expect(pasteDialog()).not.toBeNull()

    withBrowserFlush('keydown', () => pressEscape())
    await waitFor(() => expect(discardConfirm()).toBeNull())
    await settle()
    expect(pasteDialog()).not.toBeNull()
    expect(content.value).toBe('hostname r1\n')
  })

  it('keeps the discard confirmation opened by a backdrop click open', async () => {
    renderPage()
    const content = openPasteDialog()
    fireEvent.change(content, { target: { value: 'hostname r1\n' } })

    const backdrop = pasteDialog()!
    withBrowserFlush('click', () => {
      fireEvent.pointerDown(backdrop)
      fireEvent.mouseDown(backdrop)
      fireEvent.pointerUp(backdrop)
      fireEvent.mouseUp(backdrop)
      fireEvent.click(backdrop)
    })
    await screen.findByRole('dialog', { name: 'snapshots.pasteCreate.discardTitle' })
    await settle()
    expect(discardConfirm()).not.toBeNull()
    expect(pasteDialog()).not.toBeNull()
    expect(content.value).toBe('hostname r1\n')
  })

  it('ignores Escape and backdrop clicks while the create request is pending and shows its error', () => {
    renderPage()
    startCreateRequest()

    pressEscape()
    fireEvent.click(createDialog()!)
    expect(createDialog()).not.toBeNull()
    expect((document.getElementById('snapshot-name-input') as HTMLInputElement).value).toBe('new-snapshot')

    act(() => testState.failCreate?.(new Error('Snapshot already exists')))
    expect(within(createDialog() as HTMLElement).getByRole('alert')).toHaveTextContent('Snapshot already exists')
  })

  it('does not show an error from a request that failed after the create dialog was closed', () => {
    renderPage()
    startCreateRequest()
    fireEvent.click(within(createDialog() as HTMLElement).getByRole('button', { name: 'common.cancel' }))
    expect(createDialog()).toBeNull()

    act(() => testState.failCreate?.(new Error('Snapshot already exists')))
    fireEvent.click(screen.getByRole('button', { name: 'snapshots.newSnapshot' }))

    expect(createDialog()).not.toBeNull()
    expect(within(createDialog() as HTMLElement).queryByRole('alert')).toBeNull()
    expect(document.getElementById('snapshot-name-input')).toHaveAttribute('aria-invalid', 'false')
  })

  it('keeps the create dialog open when Escape ends an IME composition in the folder field', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'snapshots.newSnapshot' }))
    const folder = document.getElementById('snapshot-folder-create-input') as HTMLInputElement
    act(() => folder.focus())
    fireEvent.change(folder, { target: { value: 'ぐるーぷ' } })

    pressComposingEscape(folder, { isComposing: true })
    pressComposingEscape(folder, { keyCode: 229 })
    expect(createDialog()).not.toBeNull()
    expect(folder.value).toBe('ぐるーぷ')
  })

  it('keeps the paste-create dialog open when Escape ends an IME composition', () => {
    renderPage()
    const content = openPasteDialog()

    pressComposingEscape(content, { isComposing: true })
    pressComposingEscape(content, { keyCode: 229 })
    expect(pasteDialog()).not.toBeNull()
    expect(discardConfirm()).toBeNull()
  })

  it('ignores Escape and backdrop clicks while the paste upload is pending', () => {
    testState.uploadPending = true
    renderPage()
    const content = openPasteDialog()
    fireEvent.change(content, { target: { value: 'hostname r1\n' } })

    pressEscape(content)
    fireEvent.click(pasteDialog()!)
    expect(pasteDialog()).not.toBeNull()
    expect(discardConfirm()).toBeNull()
    expect(content.value).toBe('hostname r1\n')
  })
})
