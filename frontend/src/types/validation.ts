/**
 * Configuration validation type definitions
 * File parsing status, initialization issues, warnings, conversion status
 * Critical for identifying config errors before deployment
 */
export interface FileParseStatus {
  file_name: string
  status: string
  file_format?: string
  nodes: string[]
}

export interface InitIssue {
  nodes?: string[]
  source_lines: string[]
  type: string
  details: string
  line_text: string
  parser_context: string
}

export interface ParseWarning {
  filename: string
  line: number
  text: string
  parser_context: string
  comment: string
}

export interface ViConversionStatus {
  node: string
  status: string
}

export interface DuplicateRouterID {
  node: string
  vrf: string
  router_id: string
  protocol: string
  area?: string
  remote_node?: string
  session_status: string
}