/**
 * Line separator of a config file opened in the editor
 * CodeMirror documents and textarea values use LF line breaks; a CRLF file is saved with CRLF again
 */
export type LineSeparator = '\r\n' | '\n'

/**
 * CRLF when the loaded content contains a CRLF line break, LF otherwise
 */
export function detectLineSeparator(content: string): LineSeparator {
  return content.includes('\r\n') ? '\r\n' : '\n'
}

/**
 * Editor text with its line breaks written as the given separator (LF text is returned unchanged)
 */
export function applyLineSeparator(text: string, separator: LineSeparator): string {
  return separator === '\n' ? text : text.replace(/\r?\n/g, separator)
}
