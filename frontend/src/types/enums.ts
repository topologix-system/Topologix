/**
 * Enumeration type definitions
 * Device types, protocol types, session states, and other categorical values
 */
export enum NodeType {
  ROUTER = 'router',
  SWITCH = 'switch',
  FIREWALL = 'firewall',
  LOAD_BALANCER = 'load_balancer',
  UNKNOWN = 'unknown',
}

export enum ProtocolType {
  OSPF = 'ospf',
  BGP = 'bgp',
  EIGRP = 'eigrp',
  ISIS = 'isis',
  RIP = 'rip',
  STATIC = 'static',
  CONNECTED = 'connected',
}