"""
Enumeration types for network topology and protocols
- NodeType: Network device types (router, switch, firewall, load_balancer, unknown)
- ProtocolType: Routing protocol types (OSPF, BGP, EIGRP, IS-IS, RIP, static, connected)
- Used throughout the application for type-safe categorization
"""
from enum import Enum


class NodeType(Enum):
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    UNKNOWN = "unknown"


class ProtocolType(Enum):
    OSPF = "ospf"
    BGP = "bgp"
    EIGRP = "eigrp"
    ISIS = "isis"
    RIP = "rip"
    STATIC = "static"
    CONNECTED = "connected"