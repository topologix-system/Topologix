"""
OSPF protocol data models (dataclasses)
- OSPFProcessConfig: OSPF process configuration per node/VRF
- OSPFAreaConfig: OSPF area configuration with active/passive interfaces
- OSPFInterfaceConfig: OSPF interface-level configuration
- OSPFSessionCompat: OSPF neighbor session compatibility information
- Maps to Batfish OSPF query results
- Supports OSPF cost, network types, hello/dead intervals
"""
from dataclasses import dataclass, field, asdict


@dataclass
class OSPFProcessConfig:
    """OSPF process configuration"""
    node: str
    vrf: str
    process_id: int
    areas: list[str] = field(default_factory=list)
    reference_bandwidth: float | None = None
    router_id: str | None = None
    export_policy_sources: list[str] = field(default_factory=list)
    area_border_router: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OSPFAreaConfig:
    """OSPF area configuration"""
    node: str
    vrf: str
    process_id: int
    area: str
    area_type: str = "NONE"
    active_interfaces: list[str] = field(default_factory=list)
    passive_interfaces: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OSPFInterfaceConfig:
    """OSPF interface configuration"""
    interface: str
    vrf: str
    process_id: int
    ospf_area_name: str
    ospf_enabled: bool = True
    ospf_passive: bool = False
    ospf_cost: int | None = None
    ospf_network_type: str | None = None
    ospf_hello_interval: int | None = None
    ospf_dead_interval: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OSPFSessionCompat:
    """OSPF session compatibility"""
    interface: str
    vrf: str
    ip: str
    area: str
    remote_interface: str
    remote_vrf: str
    remote_ip: str
    remote_area: str
    session_status: str = "UNKNOWN"

    def to_dict(self) -> dict:
        return asdict(self)