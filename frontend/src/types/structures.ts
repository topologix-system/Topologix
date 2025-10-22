/**
 * Configuration structure type definitions
 * Defined, referenced, and named structures for config analysis and cross-reference validation
 */
export interface DefinedStructure {
  structure_type: string
  structure_name: string
  source_lines: string[]
}

export interface ReferencedStructure {
  structure_type: string
  structure_name: string
  context: string
  source_lines: string[]
}

export interface NamedStructure {
  node: string
  structure_type: string
  structure_name: string
  structure_definition: Record<string, any>
}