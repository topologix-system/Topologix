/**
 * TypeScript type definitions central export file
 * Provides barrel exports for all network analysis, validation, and API types
 * Organized by domain: enums, network, protocols (OSPF, BGP), validation, structures, edges, etc.
 */
export * from './enums'
export * from './network'
export * from './ospf'
export * from './bgp'
export * from './validation'
export * from './structures'
export * from './reachability'
export * from './edges'
export * from './vlan'
export * from './ip'
export * from './ipSearch'
export * from './policy'
export * from './api'
export * from './snapshot'
export * from './topology'
export type {
  Layer1Node,
  Layer1Topology,
  Layer1ValidationError,
  DeviceInterface,
  DeviceWithInterfaces,
  SnapshotInterfaces,
  Layer1TopologySaveResult,
} from './layer1'
export * from './comparison'
export * from './errors'
