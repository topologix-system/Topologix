import { useEffect, useRef, useState } from 'react'
import { Loader2, Save, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import {
  loadNetworkConfigCodeMirror,
  type CodeMirrorBundle,
} from '../lib/codemirror/loadCodeMirror'

export interface ConfigFileEditorProps {
  filename: string
  draft: string
  forceFallback?: boolean
  isSaving?: boolean
  onDraftChange: (content: string) => void
  onSave: () => void
  onCancel: () => void
}

export function ConfigFileEditor({
  filename,
  draft,
  forceFallback = false,
  isSaving = false,
  onDraftChange,
  onSave,
  onCancel,
}: ConfigFileEditorProps) {
  const { t } = useTranslation()
  const [bundle, setBundle] = useState<CodeMirrorBundle | null>(null)
  const [editorMode, setEditorMode] = useState<'loading' | 'codemirror' | 'fallback'>(
    forceFallback ? 'fallback' : 'loading'
  )
  const containerRef = useRef<HTMLDivElement | null>(null)
  const viewRef = useRef<import('@codemirror/view').EditorView | null>(null)
  const latestDraftRef = useRef(draft)

  useEffect(() => {
    latestDraftRef.current = draft
  }, [draft])

  useEffect(() => {
    let cancelled = false

    if (forceFallback) {
      setEditorMode('fallback')
      setBundle(null)
      return () => {
        cancelled = true
      }
    }

    setEditorMode('loading')
    loadNetworkConfigCodeMirror()
      .then((loadedBundle) => {
        if (cancelled) return
        setBundle(loadedBundle)
        setEditorMode('codemirror')
      })
      .catch(() => {
        if (cancelled) return
        setBundle(null)
        setEditorMode('fallback')
      })

    return () => {
      cancelled = true
    }
  }, [forceFallback])

  useEffect(() => {
    if (editorMode !== 'codemirror' || !bundle || !containerRef.current) {
      if (editorMode === 'fallback' && viewRef.current) {
        viewRef.current.destroy()
        viewRef.current = null
      }
      return
    }

    viewRef.current?.destroy()
    const view = new bundle.EditorView({
      state: bundle.createState(latestDraftRef.current, onDraftChange),
      parent: containerRef.current,
    })
    viewRef.current = view

    return () => {
      view.destroy()
      if (viewRef.current === view) {
        viewRef.current = null
      }
    }
  }, [bundle, editorMode, onDraftChange])

  const renderEditorSurface = () => {
    if (editorMode === 'fallback') {
      return (
        <textarea
          value={draft}
          onChange={(event) => onDraftChange(event.target.value)}
          spellCheck={false}
          className="h-96 w-full resize-y rounded-lg border border-gray-300 bg-white p-3 font-mono text-sm leading-6 text-gray-900 shadow-sm focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
          aria-label={t('snapshots.configEditor.textareaAria', { name: filename })}
        />
      )
    }

    if (editorMode === 'loading') {
      return (
        <div className="flex h-96 items-center justify-center rounded-lg border border-gray-300 bg-gray-50 text-sm font-medium text-gray-700">
          <Loader2 className="mr-2 h-4 w-4 animate-spin text-blue-600" aria-hidden="true" />
          {t('snapshots.configEditor.loadingEditor')}
        </div>
      )
    }

    return (
      <div
        ref={containerRef}
        className="rounded-lg bg-white"
        aria-label={t('snapshots.configEditor.codemirrorAria', { name: filename })}
      />
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h4 className="break-all text-sm font-semibold text-gray-900">
            {t('snapshots.configEditor.title', { name: filename })}
          </h4>
          <p className="mt-1 text-xs text-gray-600">{t('snapshots.configEditor.rancidHint')}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onSave()}
            disabled={isSaving}
            className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-3 py-2 text-sm font-semibold text-white transition-colors hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50"
            aria-busy={isSaving}
          >
            {isSaving ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <Save className="h-4 w-4" aria-hidden="true" />
            )}
            {isSaving ? t('snapshots.configEditor.saving') : t('common.save')}
          </button>
          <button
            type="button"
            onClick={onCancel}
            disabled={isSaving}
            className="inline-flex items-center gap-2 rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-semibold text-gray-800 transition-colors hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <X className="h-4 w-4" aria-hidden="true" />
            {t('common.cancel')}
          </button>
        </div>
      </div>
      {renderEditorSurface()}
    </div>
  )
}
