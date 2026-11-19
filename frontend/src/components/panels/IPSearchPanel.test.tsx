import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { translateJa } from '../../__tests__/translateJa'
import { httpError } from '../../__tests__/versioning'
import { ContentHashMismatchError, SnapshotMismatchError } from '../../hooks/useNetwork'
import ja from '../../i18n/locales/ja.json'
import { IPSearchPanel } from './IPSearchPanel'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: translateJa }),
}))

describe('IPSearchPanel data errors in Japanese', () => {
  it.each([
    ['SnapshotMismatchError', new SnapshotMismatchError(), ja.overview.version.snapshotMismatch],
    ['ContentHashMismatchError', new ContentHashMismatchError(), ja.overview.version.contentMismatch],
  ])('shows the localized detail for a %s and no English text', (_label, error, detail) => {
    const { container } = render(<IPSearchPanel isLoading={false} error={error} />)

    expect(screen.getByText(ja.ipSearch.dataUnavailable)).toBeInTheDocument()
    expect(screen.getByText(detail)).toBeInTheDocument()
    expect(container.textContent).not.toContain(error.message)
    expect(container.textContent).not.toMatch(/The server answered/)
  })

  it('shows the response message for other data errors', () => {
    render(<IPSearchPanel isLoading={false} error={httpError(500, { message: 'Batfish query failed' })} />)

    expect(screen.getByText('Batfish query failed')).toBeInTheDocument()
  })
})
