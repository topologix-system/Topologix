/**
 * VLAN configuration type definitions
 * Switched VLAN properties, trunk configurations, and VXLAN VNI mappings
 */
export interface SwitchedVlanProperties {
  node: string
  vlan_id: number
  interfaces: string[]
  interface_vlans: string[]
  vxlan_vni?: number
}