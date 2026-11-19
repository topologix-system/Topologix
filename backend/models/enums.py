"""Enumeration types for network topology and protocols"""
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