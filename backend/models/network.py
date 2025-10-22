"""
Network topology data models (Pydantic/dataclass)
- Node properties, interface details, routing tables
- IP ownership and VLAN configurations
- Maps to Batfish API response structures
"""
from dataclasses import dataclass, field, asdict
from typing import Any
from .enums import NodeType


@dataclass
class InterfaceDetail:
    """Interface detailed information"""
    name: str
    admin_up: bool
    active: bool
    description: str = ""
    speed: int | None = None
    mtu: int = 1500
    vlan: int | None = None
    allowed_vlans: list[int] = field(default_factory=list)
    primary_address: str | None = None
    bandwidth: int | None = None
    inactive_reason: str | None = None


@dataclass
class VLANInfo:
    """VLAN information"""
    id: int
    name: str = ""
    interfaces_count: int = 0
    interfaces: list[str] = field(default_factory=list)
    vxlan_vni: int | None = None


@dataclass
class RouteEntry:
    """Routing table entry"""
    network: str
    next_hop: str
    next_hop_ip: str | None = None
    next_hop_interface: str | None = None
    protocol: str = "static"
    metric: int | None = None
    admin_distance: int | None = None
    tag: int | None = None


@dataclass
class NetworkNode:
    """Network node/device data class"""
    id: str
    name: str
    type: NodeType
    platform: str
    hostname: str = ""
    interfaces: list[InterfaceDetail] = field(default_factory=list)
    vlans: list[VLANInfo] = field(default_factory=list)
    routes: dict[str, int] = field(default_factory=dict)
    ip_addresses: list[str] = field(default_factory=list)
    protocols: dict[str, Any] = field(default_factory=dict)
    health_status: str = "healthy"
    config_issues: list[str] = field(default_factory=list)

    # Additional properties from nodeProperties (22種類のデータ対応)
    configuration_format: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    domain_name: str | None = None
    ntp_servers: list[str] = field(default_factory=list)
    logging_servers: list[str] = field(default_factory=list)
    snmp_trap_servers: list[str] = field(default_factory=list)
    tacacs_servers: list[str] = field(default_factory=list)
    vrfs: list[str] = field(default_factory=list)
    zones: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['type'] = self.type.value
        return data


@dataclass
class NetworkEdge:
    """Network edge/link data class"""
    source: str
    target: str
    source_port: str
    target_port: str
    source_ip: str | None = None
    target_ip: str | None = None
    protocol: str | None = None
    bandwidth: int | None = None
    utilization: float | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)