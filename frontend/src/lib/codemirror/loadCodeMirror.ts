import type { Extension } from '@codemirror/state'

export interface CodeMirrorBundle {
  createState: (doc: string, onChange: (value: string) => void) => import('@codemirror/state').EditorState
  EditorView: typeof import('@codemirror/view').EditorView
}

export async function loadNetworkConfigCodeMirror(): Promise<CodeMirrorBundle> {
  const [stateModule, viewModule, languageModule, commandsModule, grammarModule] = await Promise.all([
    import('@codemirror/state'),
    import('@codemirror/view'),
    import('@codemirror/language'),
    import('@codemirror/commands'),
    import('./networkConfigLanguage'),
  ])

  const createExtensions = (onChange: (value: string) => void): Extension[] => [
    viewModule.lineNumbers(),
    viewModule.highlightActiveLineGutter(),
    viewModule.highlightSpecialChars(),
    commandsModule.history(),
    languageModule.indentOnInput(),
    languageModule.bracketMatching(),
    viewModule.drawSelection(),
    viewModule.dropCursor(),
    stateModule.EditorState.allowMultipleSelections.of(true),
    languageModule.syntaxHighlighting(languageModule.defaultHighlightStyle, { fallback: true }),
    grammarModule.networkConfigLanguage,
    viewModule.keymap.of([
      ...commandsModule.defaultKeymap,
      ...commandsModule.historyKeymap,
      commandsModule.indentWithTab,
    ]),
    viewModule.EditorView.lineWrapping,
    viewModule.EditorView.updateListener.of((update) => {
      if (update.docChanged) {
        onChange(update.state.doc.toString())
      }
    }),
    viewModule.EditorView.theme({
      '&': {
        minHeight: '24rem',
        fontSize: '0.875rem',
        border: '1px solid #d1d5db',
        borderRadius: '0.5rem',
        backgroundColor: '#ffffff',
      },
      '&.cm-focused': {
        outline: '2px solid #2563eb',
        outlineOffset: '2px',
      },
      '.cm-scroller': {
        fontFamily:
          'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
        lineHeight: '1.5',
      },
      '.cm-content': {
        minHeight: '24rem',
        padding: '0.75rem',
      },
      '.cm-gutters': {
        backgroundColor: '#f9fafb',
        borderRight: '1px solid #e5e7eb',
        color: '#6b7280',
      },
      '.cm-activeLineGutter, .cm-activeLine': {
        backgroundColor: '#eff6ff',
      },
    }),
  ]

  return {
    createState: (doc: string, onChange: (value: string) => void) =>
      stateModule.EditorState.create({
        doc,
        extensions: createExtensions(onChange),
      }),
    EditorView: viewModule.EditorView,
  }
}
