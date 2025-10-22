/**
 * IP address and ownership type definitions
 * Maps IP addresses to owning devices and interfaces
 */
export interface IPOwner {
  node: string
  vrf: string
  interface: string
  ip: string
  mask: string
  active: boolean
}