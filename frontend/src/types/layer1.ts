export interface Layer1Node {
  hostname: string
  interfaceName: string
}

export interface Layer1Edge {
  node1: Layer1Node
  node2: Layer1Node
}

export interface Layer1Topology {
  edges: Layer1Edge[]
}

export interface Layer1ValidationError {
  type: 'hostname_not_found' | 'interface_not_found' | 'duplicate_connection' | 'self_connection' | 'invalid_structure' | 'validation_error'
  message: string
  edge_index?: number
}

export interface DeviceInterface {
  name: string
  active: boolean
  description?: string
}

export interface DeviceWithInterfaces {
  hostname: string
  interfaces: DeviceInterface[]
}

export interface SnapshotInterfaces {
  [hostname: string]: DeviceWithInterfaces
}

export interface Layer1TopologySaveResult {
  snapshot_name: string
  edge_count: number
  file_size_bytes: number
}
