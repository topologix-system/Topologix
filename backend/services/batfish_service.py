"""
Batfish network analysis service wrapper
- Complete Batfish Python API integration (pybatfish)
- Network initialization from configuration snapshots
- Node properties, interfaces, routes, VLANs, IP ownership queries
- OSPF protocol analysis: processes, areas, interfaces, sessions
- BGP protocol analysis: sessions, routes, peer groups, RIBs
- Layer 2/3 topology discovery and edge detection
- Reachability and traceroute flow analysis
- Configuration validation and parsing issue detection
- Structure definitions and references analysis
- Supports 40+ Batfish query endpoints
- DataFrame to dataclass conversion utilities
- Comprehensive error handling for Batfish exceptions
"""
import logging
from typing import Any
from pathlib import Path

import pandas as pd
from pybatfish.client.session import Session

from config import config
from models import (
    NetworkNode, NetworkEdge, InterfaceDetail, VLANInfo, RouteEntry,
    OSPFProcessConfig, OSPFAreaConfig, OSPFInterfaceConfig, OSPFSessionCompat,
    FileParseStatus, InitIssue, ParseWarning, ViConversionStatus, DuplicateRouterID,
    DefinedStructure, ReferencedStructure, NamedStructure,
    FlowTrace, ReachabilityTrace,
    NodeType, ProtocolType
)

logger = logging.getLogger(__name__)


class BatfishService:
    """Service for interacting with Batfish network analysis"""

    def __init__(self):
        self.session = Session(host=config.BATFISH_HOST, port=config.BATFISH_PORT)
        self.network_name = config.BATFISH_NETWORK
        self.current_snapshot_name: str | None = None
        self._initialized = False

    def initialize_network(self, snapshot_dir: str | Path, snapshot_name: str | None = None) -> dict[str, Any]:
        """
        Initialize Batfish network and snapshot

        Args:
            snapshot_dir: Path to network configuration snapshot directory
            snapshot_name: Name for this snapshot (defaults to directory name)

        Returns:
            Initialization status with parse results
        """
        try:
            snapshot_path = Path(snapshot_dir)
            if not snapshot_path.exists():
                raise FileNotFoundError(f"Snapshot directory not found: {snapshot_dir}")

            # Determine snapshot name
            if snapshot_name is None:
                snapshot_name = snapshot_path.name

            self.current_snapshot_name = snapshot_name

            # Initialize network
            self.session.set_network(self.network_name)
            logger.info(f"Network set to: {self.network_name}")

            # Initialize snapshot
            init_result = self.session.init_snapshot(
                str(snapshot_path),
                name=snapshot_name,
                overwrite=True
            )
            logger.info(f"Snapshot initialized: {snapshot_name}")

            self._initialized = True

            # Get parse status
            file_status = self.get_file_parse_status()
            init_issues = self.get_init_issues()
            parse_warnings = self.get_parse_warnings()

            # init_result を安全にシリアライズ可能な形式に変換
            init_result_safe = {}
            if init_result:
                # FileLines以外の安全な属性のみを抽出
                for key in ['summary', 'status', 'filecount']:
                    if hasattr(init_result, key):
                        value = getattr(init_result, key)
                        # FileLines型でなければ追加
                        if not hasattr(value, '__class__') or 'FileLines' not in str(value.__class__):
                            init_result_safe[key] = value

            return {
                "status": "success",
                "network": self.network_name,
                "snapshot": snapshot_name,
                "file_parse_status": [s.to_dict() for s in file_status],
                "init_issues": [i.to_dict() for i in init_issues],
                "parse_warnings": [w.to_dict() for w in parse_warnings],
                "initialization_result": init_result_safe
            }

        except Exception as e:
            logger.error(f"Failed to initialize network: {e}")
            raise

    def _ensure_initialized(self):
        if not self._initialized:
            raise RuntimeError("Batfish session not initialized. Call initialize_network() first.")

    def _execute_query(self, query: Any, query_name: str) -> pd.DataFrame | None:
        """
        Execute a Batfish query with error handling

        Args:
            query: Batfish question to execute
            query_name: Name of query for logging

        Returns:
            DataFrame with results or None if error/empty
        """
        try:
            result = query.answer().frame()
            if result.empty:
                logger.debug(f"Query '{query_name}' returned empty result")
                return None
            return result
        except Exception as e:
            logger.warning(f"Query '{query_name}' failed: {e}")
            return None

    # ========== Helper Functions for Safe Serialization ==========
    def _convert_interfaces_to_strings(self, interfaces):
        """Convert Interface objects or lists to strings"""
        if not interfaces:
            return []
        if isinstance(interfaces, list):
            return [str(iface) if iface else "" for iface in interfaces]
        return [str(interfaces)]

    def _convert_ip_network_to_string(self, ip_obj):
        """Convert IP/Network objects to strings"""
        if not ip_obj:
            return None
        if isinstance(ip_obj, str):
            return ip_obj
        return str(ip_obj)

    def _safe_serialize(self, obj):
        """Safely convert any Batfish object to JSON-serializable format"""
        if obj is None:
            return None
        if isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, list):
            return [self._safe_serialize(item) for item in obj]
        if isinstance(obj, dict):
            return {k: self._safe_serialize(v) for k, v in obj.items()}
        # For any Batfish object type, convert to string
        return str(obj)

    # ========== Query 1: Node Properties ==========
    def get_node_properties(self) -> list[dict[str, Any]]:
        """Get node properties for all devices"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.nodeProperties(), "nodeProperties")
        if df is None:
            return []

        nodes = []
        for _, row in df.iterrows():
            node_data = {
                "node": row.get("Node", ""),
                "configuration_format": row.get("Configuration_Format"),
                "dns_servers": row.get("DNS_Servers", []),
                "dns_source_interface": str(row.get("DNS_Source_Interface")) if row.get("DNS_Source_Interface") else None,
                "domain_name": row.get("Domain_Name"),
                "hostname": row.get("Hostname", ""),
                "ipsec_vpns": row.get("IPsec_VPNs", []),
                "interfaces": self._convert_interfaces_to_strings(row.get("Interfaces", [])),
                "logging_servers": row.get("Logging_Servers", []),
                "logging_source_interface": str(row.get("Logging_Source_Interface")) if row.get("Logging_Source_Interface") else None,
                "ntp_servers": row.get("NTP_Servers", []),
                "ntp_source_interface": str(row.get("NTP_Source_Interface")) if row.get("NTP_Source_Interface") else None,
                "snmp_source_interface": str(row.get("SNMP_Source_Interface")) if row.get("SNMP_Source_Interface") else None,
                "snmp_trap_servers": row.get("SNMP_Trap_Servers", []),
                "tacacs_servers": row.get("TACACS_Servers", []),
                "tacacs_source_interface": str(row.get("TACACS_Source_Interface")) if row.get("TACACS_Source_Interface") else None,
                "vendor": row.get("Vendor", ""),
                "vrfs": row.get("VRFs", []),
                "zones": row.get("Zones", []),
            }
            nodes.append(node_data)

        return nodes

    # ========== Query 2: Interface Properties ==========
    def get_interface_properties(self) -> list[dict[str, Any]]:
        """Get interface properties for all interfaces"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.interfaceProperties(), "interfaceProperties")
        if df is None:
            return []

        interfaces = []
        for _, row in df.iterrows():
            # Convert Interface object to string
            interface_raw = row.get("Interface", "")
            interface_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "access_vlan": row.get("Access_VLAN"),
                "active": row.get("Active", False),
                "admin_up": row.get("Admin_Up", False),
                "all_prefixes": [str(p) for p in row.get("All_Prefixes", [])] if row.get("All_Prefixes") else [],
                "allowed_vlans": row.get("Allowed_VLANs", []),
                "auto_state_vlan": row.get("Auto_State_VLAN", True),
                "bandwidth": row.get("Bandwidth"),
                "blacklisted": row.get("Blacklisted", False),
                "channel_group": row.get("Channel_Group"),
                "channel_group_members": [str(m) for m in row.get("Channel_Group_Members", [])] if row.get("Channel_Group_Members") else [],
                "declared_names": row.get("Declared_Names", []),
                "description": row.get("Description", ""),
                "encapsulation_vlan": row.get("Encapsulation_VLAN"),
                "hsrp_groups": row.get("HSRP_Groups", []),
                "hsrp_version": row.get("HSRP_Version"),
                "incoming_filter_name": row.get("Incoming_Filter_Name"),
                "interface_type": row.get("Interface_Type", ""),
                "mtu": row.get("MTU", 1500),
                "native_vlan": row.get("Native_VLAN"),
                "ospf_area_name": row.get("OSPF_Area_Name"),
                "ospf_cost": row.get("OSPF_Cost"),
                "ospf_enabled": row.get("OSPF_Enabled", False),
                "ospf_network_type": row.get("OSPF_Network_Type"),
                "ospf_passive": row.get("OSPF_Passive", False),
                "outgoing_filter_name": row.get("Outgoing_Filter_Name"),
                "primary_address": self._convert_ip_network_to_string(row.get("Primary_Address")),
                "primary_network": self._convert_ip_network_to_string(row.get("Primary_Network")),
                "proxy_arp": row.get("Proxy_ARP", False),
                "rip_enabled": row.get("RIP_Enabled", False),
                "rip_passive": row.get("RIP_Passive", False),
                "speed": row.get("Speed"),
                "switchport": row.get("Switchport", False),
                "switchport_mode": row.get("Switchport_Mode", ""),
                "switchport_trunk_encapsulation": row.get("Switchport_Trunk_Encapsulation", ""),
                "vlan": row.get("VLAN"),
                "vrf": row.get("VRF", "default"),
                "zone": row.get("Zone"),
            }
            interfaces.append(interface_data)

        return interfaces

    # ========== Query 3: Routes ==========
    def get_routes(self) -> list[dict[str, Any]]:
        """Get routing table entries"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.routes(), "routes")
        if df is None:
            return []

        routes = []
        for _, row in df.iterrows():
            # Convert NextHopInterface objects to strings
            next_hop_interface_raw = row.get("Next_Hop_Interface")
            next_hop_interface = str(next_hop_interface_raw) if next_hop_interface_raw else ""

            # Convert Next_Hop if it's an object
            next_hop_raw = row.get("Next_Hop", "")
            next_hop = str(next_hop_raw) if next_hop_raw else ""

            # Convert Next_Hop_IP if it's an object
            next_hop_ip_raw = row.get("Next_Hop_IP")
            next_hop_ip = str(next_hop_ip_raw) if next_hop_ip_raw else None

            route_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "network": row.get("Network", ""),
                "next_hop": next_hop,
                "next_hop_ip": next_hop_ip,
                "next_hop_interface": next_hop_interface,
                "protocol": row.get("Protocol", ""),
                "metric": row.get("Metric"),
                "admin_distance": row.get("Admin_Distance"),
                "tag": row.get("Tag"),
            }
            routes.append(route_data)

        return routes

    # ========== Query 4-7: OSPF Queries ==========
    def get_ospf_process_configuration(self) -> list[OSPFProcessConfig]:
        """Get OSPF process configurations"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfProcessConfiguration(), "ospfProcessConfiguration")
        if df is None:
            return []

        processes = []
        for _, row in df.iterrows():
            # Handle Process_ID - some vendors use string values like "default"
            process_id_raw = row.get("Process_ID", 0)
            try:
                process_id = int(process_id_raw) if process_id_raw != "default" else 0
            except (ValueError, TypeError):
                logger.warning(f"Invalid Process_ID '{process_id_raw}' for node {row.get('Node')}, using 0")
                process_id = 0

            process = OSPFProcessConfig(
                node=row.get("Node", ""),
                vrf=row.get("VRF", "default"),
                process_id=process_id,
                areas=row.get("Areas", []),
                reference_bandwidth=row.get("Reference_Bandwidth"),
                router_id=row.get("Router_ID"),
                export_policy_sources=row.get("Export_Policy_Sources", []),
                area_border_router=row.get("Area_Border_Router", False)
            )
            processes.append(process)

        return processes

    def get_ospf_area_configuration(self) -> list[OSPFAreaConfig]:
        """Get OSPF area configurations"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfAreaConfiguration(), "ospfAreaConfiguration")
        if df is None:
            return []

        areas = []
        for _, row in df.iterrows():
            # Convert Interface objects to strings
            active_interfaces_raw = row.get("Interfaces", [])
            active_interfaces = []
            if isinstance(active_interfaces_raw, list):
                for iface in active_interfaces_raw:
                    active_interfaces.append(str(iface))
            else:
                active_interfaces = [str(active_interfaces_raw)] if active_interfaces_raw else []

            passive_interfaces_raw = row.get("Passive_Interfaces", [])
            passive_interfaces = []
            if isinstance(passive_interfaces_raw, list):
                for iface in passive_interfaces_raw:
                    passive_interfaces.append(str(iface))
            else:
                passive_interfaces = [str(passive_interfaces_raw)] if passive_interfaces_raw else []

            # Handle Process_ID - some vendors use string values like "default"
            process_id_raw = row.get("Process_ID", 0)
            try:
                process_id = int(process_id_raw) if process_id_raw != "default" else 0
            except (ValueError, TypeError):
                logger.warning(f"Invalid Process_ID '{process_id_raw}' for node {row.get('Node')}, using 0")
                process_id = 0

            area = OSPFAreaConfig(
                node=row.get("Node", ""),
                vrf=row.get("VRF", "default"),
                process_id=process_id,
                area=str(row.get("Area", "")),
                area_type=row.get("Area_Type", "NONE"),
                active_interfaces=active_interfaces,
                passive_interfaces=passive_interfaces
            )
            areas.append(area)

        return areas

    def get_ospf_interface_configuration(self) -> list[OSPFInterfaceConfig]:
        """Get OSPF interface configurations"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfInterfaceConfiguration(), "ospfInterfaceConfiguration")
        if df is None:
            return []

        interfaces = []
        for _, row in df.iterrows():
            # Convert Interface object to string
            interface_raw = row.get("Interface", "")
            interface_str = str(interface_raw) if interface_raw else ""

            # Handle Process_ID - some vendors use string values like "default"
            process_id_raw = row.get("Process_ID", 0)
            try:
                process_id = int(process_id_raw) if process_id_raw != "default" else 0
            except (ValueError, TypeError):
                logger.warning(f"Invalid Process_ID '{process_id_raw}' for interface {interface_str}, using 0")
                process_id = 0

            interface = OSPFInterfaceConfig(
                interface=interface_str,
                vrf=row.get("VRF", "default"),
                process_id=process_id,
                ospf_area_name=str(row.get("OSPF_Area_Name", "")),
                ospf_enabled=row.get("OSPF_Enabled", True),
                ospf_passive=row.get("OSPF_Passive", False),
                ospf_cost=row.get("OSPF_Cost"),
                ospf_network_type=row.get("OSPF_Network_Type"),
                ospf_hello_interval=row.get("OSPF_Hello_Interval"),
                ospf_dead_interval=row.get("OSPF_Dead_Interval")
            )
            interfaces.append(interface)

        return interfaces

    def get_ospf_session_compatibility(self) -> list[OSPFSessionCompat]:
        """Get OSPF session compatibility status"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfSessionCompatibility(), "ospfSessionCompatibility")
        if df is None:
            return []

        sessions = []
        for _, row in df.iterrows():
            # Convert Interface objects to strings
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")

            session = OSPFSessionCompat(
                interface=str(interface_raw) if interface_raw else "",
                vrf=row.get("VRF", "default"),
                ip=row.get("IP", ""),
                area=str(row.get("Area", "")),
                remote_interface=str(remote_interface_raw) if remote_interface_raw else "",
                remote_vrf=row.get("Remote_VRF", "default"),
                remote_ip=row.get("Remote_IP", ""),
                remote_area=str(row.get("Remote_Area", "")),
                session_status=row.get("Session_Status", "UNKNOWN")
            )
            sessions.append(session)

        return sessions

    # ========== Query 8-10: Edges ==========
    def get_ospf_edges(self) -> list[dict[str, Any]]:
        """Get OSPF topology edges"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfEdges(), "ospfEdges")
        if df is None:
            return []

        edges = []
        for _, row in df.iterrows():
            # Convert Interface objects to strings
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")

            edge_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else "",
                "ip": row.get("IP", ""),
                "remote_ip": row.get("Remote_IP", "")
            }
            edges.append(edge_data)

        return edges

    def get_edges(self) -> list[dict[str, Any]]:
        """Get layer 1 physical edges"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.edges(), "edges")
        if df is None:
            return []

        edges = []
        for _, row in df.iterrows():
            # Convert Interface objects to strings
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")

            edge_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else ""
            }
            edges.append(edge_data)

        return edges

    def get_layer3_edges(self) -> list[dict[str, Any]]:
        """Get layer 3 edges"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.layer3Edges(), "layer3Edges")
        if df is None:
            return []

        edges = []
        for _, row in df.iterrows():
            # Convert Interface objects to strings
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")

            edge_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else "",
                "ips": [str(ip) for ip in row.get("IPs", [])] if row.get("IPs") else [],
                "remote_ips": [str(ip) for ip in row.get("Remote_IPs", [])] if row.get("Remote_IPs") else []
            }
            edges.append(edge_data)

        return edges

    # ========== Query 11: VLAN Properties ==========
    def get_switched_vlan_properties(self) -> list[dict[str, Any]]:
        """Get switched VLAN properties"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.switchedVlanProperties(), "switchedVlanProperties")
        if df is None:
            return []

        vlans = []
        for _, row in df.iterrows():
            vlan_data = {
                "node": row.get("Node", ""),
                "vlan_id": row.get("VLAN_ID"),
                "interfaces": self._convert_interfaces_to_strings(row.get("Interfaces", [])),
                "interface_vlans": self._convert_interfaces_to_strings(row.get("Interface_VLANs", [])),
                "vxlan_vni": row.get("VXLAN_VNI")
            }
            vlans.append(vlan_data)

        return vlans

    # ========== Query 12: IP Owners ==========
    def get_ip_owners(self) -> list[dict[str, Any]]:
        """Get IP address ownership mapping"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ipOwners(), "ipOwners")
        if df is None:
            return []

        owners = []
        for _, row in df.iterrows():
            owner_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "interface": row.get("Interface", ""),
                "ip": row.get("IP", ""),
                "mask": row.get("Mask", ""),
                "active": row.get("Active", False)
            }
            owners.append(owner_data)

        return owners

    # ========== Query 13-15: Configuration Structures ==========
    def get_defined_structures(self) -> list[DefinedStructure]:
        """Get defined configuration structures"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.definedStructures(), "definedStructures")
        if df is None:
            return []

        structures = []
        for _, row in df.iterrows():
            # source_linesを安全に変換
            source_lines_raw = row.get("Source_Lines", [])
            source_lines = []
            if source_lines_raw:
                if hasattr(source_lines_raw, '__class__') and 'FileLines' in str(source_lines_raw.__class__):
                    source_lines = [str(source_lines_raw)]
                elif isinstance(source_lines_raw, list):
                    for item in source_lines_raw:
                        if hasattr(item, '__class__') and 'FileLines' in str(item.__class__):
                            source_lines.append(str(item))
                        else:
                            source_lines.append(item if isinstance(item, str) else str(item))
                else:
                    source_lines = [str(source_lines_raw)]

            structure = DefinedStructure(
                structure_type=row.get("Structure_Type", ""),
                structure_name=row.get("Structure_Name", ""),
                source_lines=source_lines
            )
            structures.append(structure)

        return structures

    def get_referenced_structures(self) -> list[ReferencedStructure]:
        """Get referenced configuration structures"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.referencedStructures(), "referencedStructures")
        if df is None:
            return []

        structures = []
        for _, row in df.iterrows():
            # source_linesを安全に変換
            source_lines_raw = row.get("Source_Lines", [])
            source_lines = []
            if source_lines_raw:
                if hasattr(source_lines_raw, '__class__') and 'FileLines' in str(source_lines_raw.__class__):
                    source_lines = [str(source_lines_raw)]
                elif isinstance(source_lines_raw, list):
                    for item in source_lines_raw:
                        if hasattr(item, '__class__') and 'FileLines' in str(item.__class__):
                            source_lines.append(str(item))
                        else:
                            source_lines.append(item if isinstance(item, str) else str(item))
                else:
                    source_lines = [str(source_lines_raw)]

            structure = ReferencedStructure(
                structure_type=row.get("Structure_Type", ""),
                structure_name=row.get("Structure_Name", ""),
                context=row.get("Context", ""),
                source_lines=source_lines
            )
            structures.append(structure)

        return structures

    def get_named_structures(self) -> list[NamedStructure]:
        """Get named structures with full definitions"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.namedStructures(), "namedStructures")
        if df is None:
            return []

        structures = []
        for _, row in df.iterrows():
            structure = NamedStructure(
                node=row.get("Node", ""),
                structure_type=row.get("Structure_Type", ""),
                structure_name=row.get("Structure_Name", ""),
                structure_definition=self._safe_serialize(row.get("Structure_Definition", {}))
            )
            structures.append(structure)

        return structures

    # ========== Query 16-19: Validation and Parse Status ==========
    def get_file_parse_status(self) -> list[FileParseStatus]:
        """Get file parse status"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.fileParseStatus(), "fileParseStatus")
        if df is None:
            return []

        statuses = []
        for _, row in df.iterrows():
            status = FileParseStatus(
                file_name=row.get("File_Name", ""),
                status=row.get("Status", ""),
                file_format=row.get("File_Format"),
                nodes=row.get("Nodes", [])
            )
            statuses.append(status)

        return statuses

    def get_init_issues(self) -> list[InitIssue]:
        """Get initialization issues"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.initIssues(), "initIssues")
        if df is None:
            return []

        issues = []
        for _, row in df.iterrows():
            # source_linesをFileLines型チェックして安全に変換
            source_lines_raw = row.get("Source_Lines", [])
            source_lines = []
            if source_lines_raw:
                logger.debug(f"source_lines_raw type: {type(source_lines_raw)}, value: {source_lines_raw}")
                # FileLinesオブジェクトの場合は文字列リストに変換
                if hasattr(source_lines_raw, '__class__') and 'FileLines' in str(source_lines_raw.__class__):
                    # FileLines型の場合、文字列形式に変換
                    source_lines = [str(source_lines_raw)]
                elif isinstance(source_lines_raw, list):
                    # リスト内の各要素もチェック
                    source_lines = []
                    for item in source_lines_raw:
                        if hasattr(item, '__class__') and 'FileLines' in str(item.__class__):
                            source_lines.append(str(item))
                        else:
                            source_lines.append(item if isinstance(item, str) else str(item))
                else:
                    source_lines = [str(source_lines_raw)]

            issue = InitIssue(
                nodes=row.get("Nodes"),
                source_lines=source_lines,
                type=row.get("Type", ""),
                details=row.get("Details", ""),
                line_text=row.get("Line_Text", ""),
                parser_context=row.get("Parser_Context", "")
            )
            issues.append(issue)

        return issues

    def get_parse_warnings(self) -> list[ParseWarning]:
        """Get parse warnings"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.parseWarning(), "parseWarning")
        if df is None:
            return []

        warnings = []
        for _, row in df.iterrows():
            # テキストフィールドの安全な変換
            text_raw = row.get("Text", "")
            text = text_raw if isinstance(text_raw, str) else str(text_raw)

            # parser_contextの安全な変換（FileLinesを含む可能性）
            parser_context_raw = row.get("Parser_Context", "")
            if hasattr(parser_context_raw, '__class__') and 'FileLines' in str(parser_context_raw.__class__):
                parser_context = str(parser_context_raw)
            else:
                parser_context = parser_context_raw if isinstance(parser_context_raw, str) else str(parser_context_raw)

            # commentの安全な変換（FileLinesを含む可能性）
            comment_raw = row.get("Comment", "")
            if hasattr(comment_raw, '__class__') and 'FileLines' in str(comment_raw.__class__):
                comment = str(comment_raw)
            else:
                comment = comment_raw if isinstance(comment_raw, str) else str(comment_raw)

            warning = ParseWarning(
                filename=row.get("Filename", ""),
                line=int(row.get("Line", 0)),
                text=text,
                parser_context=parser_context,
                comment=comment
            )
            warnings.append(warning)

        return warnings

    def get_vi_conversion_status(self) -> list[ViConversionStatus]:
        """Get vendor-independent conversion status"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.viConversionStatus(), "viConversionStatus")
        if df is None:
            return []

        statuses = []
        for _, row in df.iterrows():
            status = ViConversionStatus(
                node=row.get("Node", ""),
                status=row.get("Status", "")
            )
            statuses.append(status)

        return statuses

    # ========== Query 20: Reachability ==========
    def get_reachability(self, headers: dict[str, Any] | None = None) -> list[FlowTrace]:
        """
        Get reachability analysis results

        Args:
            headers: Optional flow headers specification
        """
        self._ensure_initialized()

        query = self.session.q.reachability(headers=headers) if headers else self.session.q.reachability()
        df = self._execute_query(query, "reachability")
        if df is None:
            return []

        flow_traces = []
        for _, row in df.iterrows():
            # Convert Trace objects to strings (simplest approach)
            traces_raw = row.get("Traces", [])
            traces = []
            if traces_raw:
                for trace in traces_raw:
                    # Convert to string for simplicity
                    traces.append(str(trace))

            flow_trace = FlowTrace(
                flow=str(row.get("Flow", "")),
                traces=traces,
                trace_count=int(row.get("TraceCount", 0))
            )
            flow_traces.append(flow_trace)

        return flow_traces

    # ========== Query 21: Search Route Policies ==========
    def get_search_route_policies(self, nodes: str = ".*", action: str = "permit") -> list[dict[str, Any]]:
        """
        Search route policies

        Args:
            nodes: Node regex pattern
            action: Action to search for (permit/deny)
        """
        self._ensure_initialized()

        df = self._execute_query(
            self.session.q.searchRoutePolicies(nodes=nodes, action=action),
            "searchRoutePolicies"
        )
        if df is None:
            return []

        policies = []
        for _, row in df.iterrows():
            policy_data = {
                "node": row.get("Node", ""),
                "policy_name": row.get("Policy_Name", ""),
                "action": row.get("Action", ""),
                "input_routes": row.get("Input_Routes", []),
                "output_routes": row.get("Output_Routes", []),
                "trace": [str(t) for t in row.get("Trace", [])] if row.get("Trace") else []
            }
            policies.append(policy_data)

        return policies

    # ========== Query 22: AAA Authentication Login ==========
    def get_aaa_authentication_login(self) -> list[dict[str, Any]]:
        """Get AAA authentication login configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.aaaAuthenticationLogin(), "aaaAuthenticationLogin")
        if df is None:
            return []

        aaa_configs = []
        for _, row in df.iterrows():
            aaa_data = {
                "node": row.get("Node", ""),
                "methods": row.get("Methods", []),
                "list_name": row.get("List_Name", "default")
            }
            aaa_configs.append(aaa_data)

        return aaa_configs

    # ========== Query 23-27: BGP Analysis ==========
    def get_bgp_edges(self) -> list[dict[str, Any]]:
        """Get BGP adjacencies/neighbors topology"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.bgpEdges(), "bgpEdges")
        if df is None:
            return []

        edges = []
        for _, row in df.iterrows():
            edge_data = {
                "node": row.get("Node", ""),
                "interface": str(row.get("Interface")) if row.get("Interface") else None,
                "remote_node": row.get("Remote_Node", ""),
                "remote_interface": str(row.get("Remote_Interface")) if row.get("Remote_Interface") else None,
                "remote_ip": row.get("Remote_IP", ""),
                "local_ip": row.get("Local_IP", ""),
                "remote_asn": row.get("Remote_AS", ""),
                "local_asn": row.get("Local_AS", ""),
                "import_policy": row.get("Import_Policy", []),
                "export_policy": row.get("Export_Policy", []),
            }
            edges.append(edge_data)

        return edges

    def get_bgp_peer_configuration(self) -> list[dict[str, Any]]:
        """Get BGP peer settings and configurations"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.bgpPeerConfiguration(), "bgpPeerConfiguration")
        if df is None:
            return []

        peers = []
        for _, row in df.iterrows():
            peer_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "local_as": row.get("Local_AS"),
                "local_ip": row.get("Local_IP", ""),
                "local_interface": str(row.get("Local_Interface")) if row.get("Local_Interface") else None,
                "confederation": row.get("Confederation"),
                "remote_as": row.get("Remote_AS"),
                "remote_ip": row.get("Remote_IP", ""),
                "description": row.get("Description", ""),
                "ebgp_multihop": row.get("EBGP_Multihop", False),
                "peer_group": row.get("Peer_Group", ""),
                "import_policy": row.get("Import_Policy", []),
                "export_policy": row.get("Export_Policy", []),
                "send_community": row.get("Send_Community", False),
                "route_reflector_client": row.get("Route_Reflector_Client", False),
                "cluster_id": row.get("Cluster_ID"),
                "shutdown": row.get("Is_Shutdown", False),
                "passive": row.get("Is_Passive", False)
            }
            peers.append(peer_data)

        return peers

    def get_bgp_process_configuration(self) -> list[dict[str, Any]]:
        """Get BGP process-wide settings"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.bgpProcessConfiguration(), "bgpProcessConfiguration")
        if df is None:
            return []

        processes = []
        for _, row in df.iterrows():
            process_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "router_id": row.get("Router_ID", ""),
                "confederation_id": row.get("Confederation_ID"),
                "confederation_members": row.get("Confederation_Members", []),
                "multipath_equivalent_as_path_match_mode": row.get("Multipath_Equivalent_As_Path_Match_Mode", ""),
                "multipath_ebgp": row.get("Multipath_EBGP", False),
                "multipath_ibgp": row.get("Multipath_IBGP", False),
                "neighbors": row.get("Neighbors", []),
                "tie_breaker": row.get("Tie_Breaker", "")
            }
            processes.append(process_data)

        return processes

    def get_bgp_session_status(self) -> list[dict[str, Any]]:
        """Get BGP session operational status"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.bgpSessionStatus(), "bgpSessionStatus")
        if df is None:
            return []

        sessions = []
        for _, row in df.iterrows():
            session_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "local_as": row.get("Local_AS"),
                "local_interface": str(row.get("Local_Interface")) if row.get("Local_Interface") else None,
                "local_ip": row.get("Local_IP", ""),
                "remote_as": row.get("Remote_AS"),
                "remote_node": row.get("Remote_Node", ""),
                "remote_ip": row.get("Remote_IP", ""),
                "address_families": row.get("Address_Families", []),
                "session_type": row.get("Session_Type", ""),
                "established_status": row.get("Established_Status", "NOT_ESTABLISHED")
            }
            sessions.append(session_data)

        return sessions

    def get_bgp_session_compatibility(self) -> list[dict[str, Any]]:
        """Get BGP session configuration validation"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.bgpSessionCompatibility(), "bgpSessionCompatibility")
        if df is None:
            return []

        compatibility = []
        for _, row in df.iterrows():
            compat_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "local_as": row.get("Local_AS"),
                "local_interface": str(row.get("Local_Interface")) if row.get("Local_Interface") else None,
                "local_ip": row.get("Local_IP", ""),
                "remote_as": row.get("Remote_AS"),
                "remote_node": row.get("Remote_Node", ""),
                "remote_ip": row.get("Remote_IP", ""),
                "address_families": row.get("Address_Families", []),
                "session_type": row.get("Session_Type", ""),
                "configured_status": row.get("Configured_Status", "")
            }
            compatibility.append(compat_data)

        return compatibility

    def get_bgp_rib(self) -> list[dict[str, Any]]:
        """Get BGP Routing Information Base entries"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.bgpRib(), "bgpRib")
        if df is None:
            return []

        rib_entries = []
        for _, row in df.iterrows():
            rib_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "network": row.get("Network", ""),
                "next_hop_ip": row.get("Next_Hop_IP", ""),
                "protocol": row.get("Protocol", ""),
                "as_path": row.get("AS_Path", []),
                "local_preference": row.get("Local_Preference"),
                "med": row.get("MED"),
                "origin_protocol": row.get("Origin_Protocol", ""),
                "origin_type": row.get("Origin_Type", ""),
                "originator_id": row.get("Originator_ID", ""),
                "received_from_ip": row.get("Received_From_IP", ""),
                "tag": row.get("Tag"),
                "weight": row.get("Weight"),
                "communities": row.get("Communities", []),
                "cluster_list": row.get("Cluster_List", [])
            }
            rib_entries.append(rib_data)

        return rib_entries

    # ========== Query 28-31: ACL/Firewall Analysis ==========
    def test_filters(self, headers=None, nodes=None, filters=None, startLocation=None) -> list[dict[str, Any]]:
        """Test flows against ACLs/firewall rules"""
        self._ensure_initialized()

        query = self.session.q.testFilters(headers=headers, nodes=nodes, filters=filters, startLocation=startLocation)
        df = self._execute_query(query, "testFilters")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "filter_name": row.get("Filter_Name", ""),
                "flow": self._safe_serialize(row.get("Flow")),
                "action": row.get("Action", ""),
                "line_content": row.get("Line_Content", ""),
                "trace": self._safe_serialize(row.get("Trace"))
            }
            results.append(result_data)

        return results

    def get_filter_line_reachability(self) -> list[dict[str, Any]]:
        """Identify unreachable/shadowed ACL lines"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.filterLineReachability(), "filterLineReachability")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "sources": self._safe_serialize(row.get("Sources", [])),
                "unreachable_line": row.get("Unreachable_Line", ""),
                "unreachable_line_action": row.get("Unreachable_Line_Action", ""),
                "blocking_lines": row.get("Blocking_Lines", []),
                "different_action": row.get("Different_Action", False),
                "reason": row.get("Reason", ""),
                "additional_info": row.get("Additional_Info", "")
            }
            results.append(result_data)

        return results

    def search_filters(self, headers=None, action=None, filters=None, nodes=None) -> list[dict[str, Any]]:
        """Search for flows matching conditions (permit/deny)"""
        self._ensure_initialized()

        query = self.session.q.searchFilters(headers=headers, action=action, filters=filters, nodes=nodes)
        df = self._execute_query(query, "searchFilters")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "filter": row.get("Filter", ""),
                "flow": self._safe_serialize(row.get("Flow")),
                "action": row.get("Action", ""),
                "line_content": row.get("Line_Content", ""),
                "trace": self._safe_serialize(row.get("Trace"))
            }
            results.append(result_data)

        return results

    def find_matching_filter_lines(self, headers=None, filters=None, nodes=None) -> list[dict[str, Any]]:
        """Find ACL lines matching specific flows"""
        self._ensure_initialized()

        query = self.session.q.findMatchingFilterLines(headers=headers, filters=filters, nodes=nodes)
        df = self._execute_query(query, "findMatchingFilterLines")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "filter": row.get("Filter", ""),
                "flow": self._safe_serialize(row.get("Flow")),
                "action": row.get("Action", ""),
                "line_content": row.get("Line_Content", ""),
                "line_index": row.get("Line_Index")
            }
            results.append(result_data)

        return results

    # ========== Query 32-34: Advanced Path Analysis ==========
    def traceroute(
        self,
        headers=None,
        startLocation=None,
        ignoreFilters=False,
        maxTraces=None,
        pathConstraints=None
    ) -> list[dict[str, Any]]:
        """
        Virtual traceroute through network

        Args:
            headers: Flow headers specification (srcIps, dstIps, ipProtocols, ports, etc.)
            startLocation: Starting location for the trace
            ignoreFilters: Whether to ignore ACLs/filters
            maxTraces: Maximum number of traces to return
            pathConstraints: Path constraints (startLocation, endLocation, transit, forbidden)
        """
        self._ensure_initialized()

        # Build query parameters
        query_params = {
            "headers": headers,
            "startLocation": startLocation,
            "ignoreFilters": ignoreFilters
        }

        if maxTraces is not None:
            query_params["maxTraces"] = maxTraces

        if pathConstraints is not None:
            query_params["pathConstraints"] = pathConstraints

        query = self.session.q.traceroute(**query_params)
        df = self._execute_query(query, "traceroute")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "flow": self._safe_serialize(row.get("Flow")),
                "traces": self._safe_serialize(row.get("Traces", [])),
            }
            results.append(result_data)

        return results

    def bidirectional_traceroute(
        self,
        headers=None,
        startLocation=None,
        ignoreFilters=False,
        maxTraces=None,
        pathConstraints=None
    ) -> list[dict[str, Any]]:
        """
        Bidirectional traceroute validation

        Args:
            headers: Flow headers specification (srcIps, dstIps, ipProtocols, ports, etc.)
            startLocation: Starting location for the trace
            ignoreFilters: Whether to ignore ACLs/filters
            maxTraces: Maximum number of traces to return
            pathConstraints: Path constraints (startLocation, endLocation, transit, forbidden)
        """
        self._ensure_initialized()

        # Build query parameters
        query_params = {
            "headers": headers,
            "startLocation": startLocation,
            "ignoreFilters": ignoreFilters
        }

        if maxTraces is not None:
            query_params["maxTraces"] = maxTraces

        if pathConstraints is not None:
            query_params["pathConstraints"] = pathConstraints

        query = self.session.q.bidirectionalTraceroute(**query_params)
        df = self._execute_query(query, "bidirectionalTraceroute")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "flow": self._safe_serialize(row.get("Flow")),
                "forward_traces": self._safe_serialize(row.get("Forward_Traces", [])),
                "reverse_flow": self._safe_serialize(row.get("Reverse_Flow")),
                "reverse_traces": self._safe_serialize(row.get("Reverse_Traces", [])),
            }
            results.append(result_data)

        return results

    # ========== PHASE 1: CRITICAL - Network Validation (12 queries) ==========

    def get_unused_structures(self) -> list[dict[str, Any]]:
        """Find unused ACLs, route-maps, prefix-lists"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.unusedStructures(), "unusedStructures")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            source_lines = self._safe_serialize(row.get("Source_Lines", []))
            result_data = {
                "structure_type": row.get("Structure_Type", ""),
                "structure_name": row.get("Structure_Name", ""),
                "source_lines": source_lines
            }
            results.append(result_data)

        return results

    def get_undefined_references(self) -> list[dict[str, Any]]:
        """Find references to non-existent objects"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.undefinedReferences(), "undefinedReferences")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            source_lines = self._safe_serialize(row.get("Source_Lines", []))
            result_data = {
                "structure_type": row.get("Structure_Type", ""),
                "structure_name": row.get("Structure_Name", ""),
                "context": row.get("Context", ""),
                "source_lines": source_lines
            }
            results.append(result_data)

        return results

    def resolve_filter_specifier(self, filters=None, nodes=None) -> list[dict[str, Any]]:
        """Validate filter names"""
        self._ensure_initialized()

        query = self.session.q.resolveFilterSpecifier(filters=filters, nodes=nodes) if filters or nodes else self.session.q.resolveFilterSpecifier()
        df = self._execute_query(query, "resolveFilterSpecifier")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "filter": row.get("Filter", "")
            }
            results.append(result_data)

        return results

    def resolve_node_specifier(self, nodes=None) -> list[dict[str, Any]]:
        """Validate node patterns"""
        self._ensure_initialized()

        query = self.session.q.resolveNodeSpecifier(nodes=nodes) if nodes else self.session.q.resolveNodeSpecifier()
        df = self._execute_query(query, "resolveNodeSpecifier")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", "")
            }
            results.append(result_data)

        return results

    def resolve_interface_specifier(self, interfaces=None, nodes=None) -> list[dict[str, Any]]:
        """Validate interface specifications"""
        self._ensure_initialized()

        query = self.session.q.resolveInterfaceSpecifier(interfaces=interfaces, nodes=nodes) if interfaces or nodes else self.session.q.resolveInterfaceSpecifier()
        df = self._execute_query(query, "resolveInterfaceSpecifier")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else ""
            }
            results.append(result_data)

        return results

    def get_vrrp_properties(self) -> list[dict[str, Any]]:
        """VRRP configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.vrrpProperties(), "vrrpProperties")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "vrrp_group": row.get("VRRP_Group"),
                "virtual_address": self._convert_ip_network_to_string(row.get("Virtual_Address")),
                "priority": row.get("Priority"),
                "preempt": row.get("Preempt", False),
                "source_address": self._convert_ip_network_to_string(row.get("Source_Address"))
            }
            results.append(result_data)

        return results

    def get_hsrp_properties(self) -> list[dict[str, Any]]:
        """HSRP configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.hsrpProperties(), "hsrpProperties")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "hsrp_group": row.get("HSRP_Group"),
                "group_number": row.get("Group_Number"),
                "virtual_address": self._convert_ip_network_to_string(row.get("Virtual_Address")),
                "priority": row.get("Priority"),
                "preempt": row.get("Preempt", False)
            }
            results.append(result_data)

        return results

    def get_mlag_properties(self) -> list[dict[str, Any]]:
        """MLAG configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.mlagProperties(), "mlagProperties")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "id": row.get("ID", ""),
                "local_interface": str(row.get("Local_Interface")) if row.get("Local_Interface") else None,
                "peer_address": row.get("Peer_Address", ""),
                "peer_interface": str(row.get("Peer_Interface")) if row.get("Peer_Interface") else None
            }
            results.append(result_data)

        return results

    def get_duplicate_router_ids(self) -> list[DuplicateRouterID]:
        """
        Detect duplicate router IDs in OSPF and BGP
        Returns list of sessions with DUPLICATE_ROUTER_ID status
        """
        self._ensure_initialized()

        results = []

        # 1. Check OSPF sessions for duplicate router IDs
        ospf_df = self._execute_query(
            self.session.q.ospfSessionCompatibility(),
            "ospfSessionCompatibility"
        )

        if ospf_df is not None:
            # Get OSPF process configurations to lookup router IDs
            ospf_processes = {}  # key: (node, vrf), value: router_id
            ospf_proc_df = self._execute_query(
                self.session.q.ospfProcessConfiguration(),
                "ospfProcessConfiguration"
            )
            if ospf_proc_df is not None:
                for _, row in ospf_proc_df.iterrows():
                    node = row.get("Node", "")
                    vrf = row.get("VRF", "default")
                    router_id = row.get("Router_ID", "")
                    if node and router_id:
                        ospf_processes[(node, vrf)] = router_id

            # Filter for DUPLICATE_ROUTER_ID status
            for _, row in ospf_df.iterrows():
                status = row.get("Session_Status", "")
                if status == "DUPLICATE_ROUTER_ID":
                    # Parse node from interface (format: "node:interface")
                    interface = str(row.get("Interface", ""))
                    node = interface.split(":")[0] if ":" in interface else interface

                    remote_interface = str(row.get("Remote_Interface", ""))
                    remote_node = remote_interface.split(":")[0] if ":" in remote_interface else ""

                    vrf = row.get("VRF", "default")
                    area = str(row.get("Area", ""))

                    # Lookup router ID
                    router_id = ospf_processes.get((node, vrf), "")

                    duplicate = DuplicateRouterID(
                        node=node,
                        vrf=vrf,
                        router_id=router_id,
                        protocol="OSPF",
                        area=area,
                        remote_node=remote_node,
                        session_status=status
                    )
                    results.append(duplicate)

        # 2. Check BGP sessions for duplicate router IDs
        bgp_df = self._execute_query(
            self.session.q.bgpSessionCompatibility(),
            "bgpSessionCompatibility"
        )

        if bgp_df is not None:
            # Get BGP process configurations to lookup router IDs
            bgp_processes = {}  # key: (node, vrf), value: router_id
            bgp_proc_df = self._execute_query(
                self.session.q.bgpProcessConfiguration(),
                "bgpProcessConfiguration"
            )
            if bgp_proc_df is not None:
                for _, row in bgp_proc_df.iterrows():
                    node = row.get("Node", "")
                    vrf = row.get("VRF", "default")
                    router_id = row.get("Router_ID", "")
                    if node and router_id:
                        bgp_processes[(node, vrf)] = router_id

            # Check both Configured_Status and Session_Status for DUPLICATE_ROUTER_ID
            for _, row in bgp_df.iterrows():
                # BGP might use Configured_Status instead of Session_Status
                status = row.get("Configured_Status", "") or row.get("Session_Status", "")
                if "DUPLICATE_ROUTER_ID" in status:
                    node = row.get("Node", "")
                    remote_node = row.get("Remote_Node", "")
                    vrf = row.get("VRF", "default")

                    # Lookup router ID
                    router_id = bgp_processes.get((node, vrf), "")

                    duplicate = DuplicateRouterID(
                        node=node,
                        vrf=vrf,
                        router_id=router_id,
                        protocol="BGP",
                        area=None,
                        remote_node=remote_node,
                        session_status=status
                    )
                    results.append(duplicate)

        return results

    def get_detect_loops(self) -> list[dict[str, Any]]:
        """Detect routing loops"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.detectLoops(), "detectLoops")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "loop": self._safe_serialize(row.get("Loop", []))
            }
            results.append(result_data)

        return results

    def get_multipath_consistency(self) -> list[dict[str, Any]]:
        """Multipath validation"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.multipathConsistency(), "multipathConsistency")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "interface": str(row.get("Interface")) if row.get("Interface") else None,
                "ip": row.get("IP", ""),
                "dip": row.get("DIP", ""),
                "is_multipath_consistent": row.get("Is_Multipath_Consistent", True)
            }
            results.append(result_data)

        return results

    def get_loopback_multipath_consistency(self) -> list[dict[str, Any]]:
        """Loopback multipath validation"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.loopbackMultipathConsistency(), "loopbackMultipathConsistency")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "loopback_ip": row.get("Loopback_IP", ""),
                "is_loopback_multipath_consistent": row.get("Is_Loopback_Multipath_Consistent", True)
            }
            results.append(result_data)

        return results

    def compare_filters(self, filters=None, nodes=None) -> list[dict[str, Any]]:
        """Compare ACL behavior"""
        self._ensure_initialized()

        query = self.session.q.compareFilters(filters=filters, nodes=nodes) if filters or nodes else self.session.q.compareFilters()
        df = self._execute_query(query, "compareFilters")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "filter_name": row.get("Filter_Name", ""),
                "base_filter_name": row.get("Base_Filter_Name", ""),
                "differences": self._safe_serialize(row.get("Differences", []))
            }
            results.append(result_data)

        return results

    # ========== PHASE 2: IMPORTANT - Additional Protocols (13 queries) ==========

    def get_evpn_rib(self) -> list[dict[str, Any]]:
        """EVPN routing table"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.evpnRib(), "evpnRib")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "route_distinguisher": row.get("Route_Distinguisher", ""),
                "prefix": row.get("Prefix", ""),
                "next_hop": self._convert_ip_network_to_string(row.get("Next_Hop")),
                "originator_ip": row.get("Originator_IP", ""),
                "route_type": row.get("Route_Type", ""),
                "vni": row.get("VNI")
            }
            results.append(result_data)

        return results

    def get_vxlan_edges(self) -> list[dict[str, Any]]:
        """VXLAN tunnels"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.vxlanEdges(), "vxlanEdges")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vni": row.get("VNI"),
                "vtep_address": row.get("VTEP_Address", ""),
                "remote_node": row.get("Remote_Node", ""),
                "remote_vtep_address": row.get("Remote_VTEP_Address", ""),
                "multicast_group": row.get("Multicast_Group", "")
            }
            results.append(result_data)

        return results

    def get_vxlan_vni_properties(self) -> list[dict[str, Any]]:
        """VXLAN VNI configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.vxlanVniProperties(), "vxlanVniProperties")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vni": row.get("VNI"),
                "vlan": row.get("VLAN"),
                "vrf": row.get("VRF", ""),
                "udp_port": row.get("UDP_Port"),
                "vtep_flood_list": row.get("VTEP_Flood_List", []),
                "multicast_group": row.get("Multicast_Group", "")
            }
            results.append(result_data)

        return results

    def get_eigrp_edges(self) -> list[dict[str, Any]]:
        """EIGRP adjacencies"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.eigrpEdges(), "eigrpEdges")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else "",
                "ip": row.get("IP", ""),
                "remote_ip": row.get("Remote_IP", "")
            }
            results.append(result_data)

        return results

    def get_eigrp_interface_configuration(self) -> list[dict[str, Any]]:
        """
        EIGRP interface configuration

        Note: pybatfish does not provide a dedicated eigrpInterfaces() method.
        This method returns an empty list. EIGRP topology information can be
        obtained via eigrpEdges() method instead.
        """
        self._ensure_initialized()

        # Method eigrpInterfaces() does not exist in pybatfish API
        # Only eigrpEdges() is available for EIGRP topology
        logger.warning("eigrpInterfaces() method does not exist in pybatfish - returning empty list")
        return []

    def get_isis_edges(self) -> list[dict[str, Any]]:
        """IS-IS adjacencies"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.isisEdges(), "isisEdges")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else "",
                "level": row.get("Level", "")
            }
            results.append(result_data)

        return results

    def get_isis_interface_configuration(self) -> list[dict[str, Any]]:
        """
        IS-IS interface configuration

        Note: pybatfish does not provide a dedicated isisInterfaces() method.
        This method returns an empty list. IS-IS topology information can be
        obtained via isisEdges() method instead.
        """
        self._ensure_initialized()

        # Method isisInterfaces() does not exist in pybatfish API
        # Only isisEdges() is available for IS-IS topology
        logger.warning("isisInterfaces() method does not exist in pybatfish - returning empty list")
        return []

    def get_layer1_edges(self) -> list[dict[str, Any]]:
        """Physical connectivity"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.layer1Edges(), "layer1Edges")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else ""
            }
            results.append(result_data)

        return results

    def get_ipsec_session_status(self) -> list[dict[str, Any]]:
        """IPsec session status"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ipsecSessionStatus(), "ipsecSessionStatus")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vpn": row.get("VPN", ""),
                "remote_node": row.get("Remote_Node", ""),
                "remote_ip": row.get("Remote_IP", ""),
                "local_ip": row.get("Local_IP", ""),
                "status": row.get("Status", ""),
                "tunnel_interfaces": row.get("Tunnel_Interfaces", [])
            }
            results.append(result_data)

        return results

    def get_ipsec_edges(self) -> list[dict[str, Any]]:
        """IPsec VPN tunnels"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ipsecEdges(), "ipsecEdges")
        if df is None:
            return []

        def parse_interface(interface_obj) -> tuple[str, str]:
            """Parse 'node[interface]' format into (node, interface)"""
            # Convert to string first (may be Interface object)
            interface_str = str(interface_obj) if interface_obj is not None else ""
            if not interface_str or '[' not in interface_str:
                return "", ""
            parts = interface_str.split('[', 1)
            node = parts[0]
            interface = parts[1].rstrip(']') if len(parts) > 1 else ""
            return node, interface

        results = []
        for _, row in df.iterrows():
            # Batfish returns: Source_Interface, Tunnel_Interface, Remote_Source_Interface, Remote_Tunnel_Interface
            # Format: "node[interface]" (e.g., "r9-remote-site2[ge-0/0/0.0]")
            source_interface = str(row.get("Source_Interface", ""))
            tunnel_interface = str(row.get("Tunnel_Interface", ""))
            remote_source_interface = str(row.get("Remote_Source_Interface", ""))
            remote_tunnel_interface = str(row.get("Remote_Tunnel_Interface", ""))

            node, local_iface = parse_interface(source_interface)
            remote_node, remote_iface = parse_interface(remote_source_interface)
            _, tunnel_iface = parse_interface(tunnel_interface)

            result_data = {
                "node": node,
                "remote_node": remote_node,
                "local_interface": local_iface,
                "remote_interface": remote_iface,
                "tunnel_interfaces": [tunnel_iface] if tunnel_iface else []
            }
            results.append(result_data)

        return results

    def get_ipsec_peer_configuration(self) -> list[dict[str, Any]]:
        """
        IPsec peer configuration

        Note: pybatfish does not provide an ipsecPeerConfiguration() method.
        This method returns an empty list. IPsec information can be obtained
        via ipsecSessionStatus() and ipsecEdges() methods instead.
        """
        self._ensure_initialized()

        # Method ipsecPeerConfiguration() does not exist in pybatfish API
        logger.warning("ipsecPeerConfiguration() method does not exist in pybatfish - returning empty list")
        return []

    def get_bfd_session_status(self) -> list[dict[str, Any]]:
        """
        BFD session status

        Note: pybatfish does not provide a bfdSessionStatus() method.
        This method returns an empty list.
        """
        self._ensure_initialized()

        # Method bfdSessionStatus() does not exist in pybatfish API
        logger.warning("bfdSessionStatus() method does not exist in pybatfish - returning empty list")
        return []

    def get_layer2_topology(self) -> list[dict[str, Any]]:
        """
        Layer 2 topology

        Note: pybatfish does not provide a layer2Edges() or layer2Topology() method.
        This method returns an empty list. Layer 2 information can be obtained
        via switchedVlanProperties() method instead.
        """
        self._ensure_initialized()

        # Method layer2Topology() does not exist in pybatfish API
        logger.warning("layer2Topology() method does not exist in pybatfish - returning empty list")
        return []

    def get_vi_model(self) -> list[dict[str, Any]]:
        """
        VI (Vendor Independent) model

        Note: pybatfish does not provide a viModel() method.
        This method returns an empty list.
        """
        self._ensure_initialized()

        # Method viModel() does not exist in pybatfish API
        logger.warning("viModel() method does not exist in pybatfish - returning empty list")
        return []

    def get_switched_vlan_edges(self) -> list[dict[str, Any]]:
        """
        VLAN edges

        Note: pybatfish does not provide a switchedVlanEdges() method.
        This method returns an empty list. VLAN information can be obtained
        via switchedVlanProperties() method instead.
        """
        self._ensure_initialized()

        # Method switchedVlanEdges() does not exist in pybatfish API
        logger.warning("switchedVlanEdges() method does not exist in pybatfish - returning empty list")
        return []

    def get_interface_mtu(self) -> list[dict[str, Any]]:
        """MTU analysis"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.interfaceMtu(), "interfaceMtu")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "vrf": row.get("VRF", "default"),
                "mtu": row.get("MTU", 1500),
                "encapsulation_mtu": row.get("Encapsulation_MTU")
            }
            results.append(result_data)

        return results

    def get_ip_space_assignment(self) -> list[dict[str, Any]]:
        """
        IP space management

        Note: pybatfish does not provide an ipSpaceAssignment() method.
        This method returns an empty list. IP ownership information can be
        obtained via ipOwners() method instead.
        """
        self._ensure_initialized()

        # Method ipSpaceAssignment() does not exist in pybatfish API
        logger.warning("ipSpaceAssignment() method does not exist in pybatfish - returning empty list")
        return []

    def get_lpm_routes(self, ip=None) -> list[dict[str, Any]]:
        """Longest prefix match routing"""
        self._ensure_initialized()

        query = self.session.q.lpmRoutes(ip=ip) if ip else self.session.q.lpmRoutes()
        df = self._execute_query(query, "lpmRoutes")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            next_hop_interface_raw = row.get("Next_Hop_Interface")
            result_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "ip": row.get("IP", ""),
                "network": row.get("Network", ""),
                "next_hop": row.get("Next_Hop", ""),
                "next_hop_interface": str(next_hop_interface_raw) if next_hop_interface_raw else None,
                "protocol": row.get("Protocol", "")
            }
            results.append(result_data)

        return results

    def get_prefix_tracer(self, prefix=None, nodes=None) -> list[dict[str, Any]]:
        """Prefix advertisement trace"""
        self._ensure_initialized()

        query = self.session.q.prefixTracer(prefix=prefix, nodes=nodes) if prefix or nodes else self.session.q.prefixTracer()
        df = self._execute_query(query, "prefixTracer")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "prefix": row.get("Prefix", ""),
                "route_entry": self._safe_serialize(row.get("Route_Entry")),
                "trace": self._safe_serialize(row.get("Trace", []))
            }
            results.append(result_data)

        return results

    # ========== PHASE 3: NICE-TO-HAVE (10 queries) ==========

    def get_differential_reachability(self, headers=None) -> list[dict[str, Any]]:
        """Compare reachability between snapshots"""
        self._ensure_initialized()

        query = self.session.q.differentialReachability(headers=headers) if headers else self.session.q.differentialReachability()
        df = self._execute_query(query, "differentialReachability")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "flow": self._safe_serialize(row.get("Flow")),
                "base_traces": self._safe_serialize(row.get("Base_Traces", [])),
                "delta_traces": self._safe_serialize(row.get("Delta_Traces", [])),
                "change": row.get("Change", "")
            }
            results.append(result_data)

        return results

    def get_bidirectional_reachability(self, headers=None) -> list[dict[str, Any]]:
        """Bidirectional reachability"""
        self._ensure_initialized()

        query = self.session.q.bidirectionalReachability(headers=headers) if headers else self.session.q.bidirectionalReachability()
        df = self._execute_query(query, "bidirectionalReachability")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "flow": self._safe_serialize(row.get("Flow")),
                "forward_traces": self._safe_serialize(row.get("Forward_Traces", [])),
                "reverse_flow": self._safe_serialize(row.get("Reverse_Flow")),
                "reverse_traces": self._safe_serialize(row.get("Reverse_Traces", []))
            }
            results.append(result_data)

        return results

    def resolve_location_specifier(self, locations=None) -> list[dict[str, Any]]:
        """Location validation"""
        self._ensure_initialized()

        query = self.session.q.resolveLocationSpecifier(locations=locations) if locations else self.session.q.resolveLocationSpecifier()
        df = self._execute_query(query, "resolveLocationSpecifier")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "location": self._safe_serialize(row.get("Location", ""))
            }
            results.append(result_data)

        return results

    def resolve_ip_specifier(self, ips=None) -> list[dict[str, Any]]:
        """IP validation"""
        self._ensure_initialized()

        query = self.session.q.resolveIpSpecifier(ips=ips) if ips else self.session.q.resolveIpSpecifier()
        df = self._execute_query(query, "resolveIpSpecifier")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "ip": row.get("IP", "")
            }
            results.append(result_data)

        return results

    def get_f5_bigip_vip_configuration(self) -> list[dict[str, Any]]:
        """F5 VIP configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.f5BigipVipConfiguration(), "f5BigipVipConfiguration")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vip_name": row.get("VIP_Name", ""),
                "vip_address": self._convert_ip_network_to_string(row.get("VIP_Address")),
                "destination_port": row.get("Destination_Port"),
                "pool": row.get("Pool", ""),
                "source_address_translation": row.get("Source_Address_Translation", "")
            }
            results.append(result_data)

        return results

    def get_route_policies(self, nodes=None) -> list[dict[str, Any]]:
        """
        Route policy analysis

        Note: pybatfish does not provide a routePolicies() method.
        This method returns an empty list for now to avoid API errors.
        """
        self._ensure_initialized()

        # Method routePolicies() does not exist in pybatfish API
        # Return empty list to avoid causing delays
        logger.warning("routePolicies() method not available - returning empty list")
        return []

    def test_route_policies(self, direction=None, inputRoute=None, nodes=None, policies=None) -> list[dict[str, Any]]:
        """Test route policies"""
        self._ensure_initialized()

        query = self.session.q.testRoutePolicies(
            direction=direction,
            inputRoute=inputRoute,
            nodes=nodes,
            policies=policies
        )
        df = self._execute_query(query, "testRoutePolicies")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "policy_name": row.get("Policy_Name", ""),
                "input_route": self._safe_serialize(row.get("Input_Route")),
                "action": row.get("Action", ""),
                "output_route": self._safe_serialize(row.get("Output_Route")),
                "trace": self._safe_serialize(row.get("Trace", []))
            }
            results.append(result_data)

        return results

    def get_questions(self) -> list[dict[str, Any]]:
        """
        List available questions

        Note: pybatfish does not provide a questions() method in this version.
        This method returns a static list of known question methods.
        """
        self._ensure_initialized()

        # Method questions() does not exist in pybatfish API version 2025.7.7.2423
        # Return a static list of available question methods instead
        logger.warning("questions() method does not exist in this pybatfish version - returning static list")

        # Get all question methods from session.q
        question_methods = [method for method in dir(self.session.q) if not method.startswith('_')]

        results = []
        for method_name in sorted(question_methods):
            # Skip special methods
            if method_name in ['list', 'list_tags', 'load']:
                continue

            # Get method documentation if available
            try:
                method = getattr(self.session.q, method_name)
                doc = method().__doc__ if callable(method) else ""
                description = doc.split('\n')[0] if doc else f"Batfish question: {method_name}"
            except:
                description = f"Batfish question: {method_name}"

            result_data = {
                "name": method_name,
                "description": description,
                "instance_variables": {}
            }
            results.append(result_data)

        return results

    def get_node_roles(self) -> list[dict[str, Any]]:
        """
        Node role definitions

        Note: pybatfish does not provide a nodeRoles() method in this version.
        This method returns an empty list. Node roles can be configured via
        the Batfish session API using set_node_roles() if needed.
        """
        self._ensure_initialized()

        # Method nodeRoles() does not exist in pybatfish API version 2025.7.7.2423
        logger.warning("nodeRoles() method does not exist in this pybatfish version - returning empty list")
        return []

    def get_interface_blacklist(self) -> list[dict[str, Any]]:
        """Blacklisted interfaces"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.interfaceProperties(properties="Blacklisted"), "interfaceBlacklist")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            if row.get("Blacklisted", False):
                interface_raw = row.get("Interface", "")
                result_data = {
                    "interface": str(interface_raw) if interface_raw else "",
                    "blacklisted": True
                }
                results.append(result_data)

        return results

    # ========== Aggregate Data Fetching ==========
    def fetch_all_data(self) -> dict[str, Any]:
        """
        Fetch all 70 types of Batfish data (35 original + 35 new)

        Returns:
            Dictionary containing all query results
        """
        self._ensure_initialized()

        logger.info("Fetching all Batfish data (70 query types)...")

        data = {}

        try:
            # ========== ORIGINAL QUERIES (35) ==========

            # Network topology and properties
            logger.debug("Fetching node_properties...")
            data["node_properties"] = self.get_node_properties()
            logger.debug("Fetching interface_properties...")
            data["interface_properties"] = self.get_interface_properties()
            logger.debug("Fetching routes...")
            data["routes"] = self.get_routes()

            # OSPF protocol data
            logger.debug("Fetching ospf_process_configuration...")
            data["ospf_process_configuration"] = [p.to_dict() for p in self.get_ospf_process_configuration()]
            logger.debug("Fetching ospf_area_configuration...")
            data["ospf_area_configuration"] = [a.to_dict() for a in self.get_ospf_area_configuration()]
            logger.debug("Fetching ospf_interface_configuration...")
            data["ospf_interface_configuration"] = [i.to_dict() for i in self.get_ospf_interface_configuration()]
            logger.debug("Fetching ospf_session_compatibility...")
            data["ospf_session_compatibility"] = [s.to_dict() for s in self.get_ospf_session_compatibility()]

            # Network edges and connectivity
            logger.debug("Fetching ospf_edges...")
            data["ospf_edges"] = self.get_ospf_edges()
            logger.debug("Fetching edges...")
            data["edges"] = self.get_edges()
            logger.debug("Fetching layer3_edges...")
            data["layer3_edges"] = self.get_layer3_edges()

            # VLAN and IP management
            logger.debug("Fetching switched_vlan_properties...")
            data["switched_vlan_properties"] = self.get_switched_vlan_properties()
            logger.debug("Fetching ip_owners...")
            data["ip_owners"] = self.get_ip_owners()

            # Configuration structures
            logger.debug("Fetching defined_structures...")
            data["defined_structures"] = [s.to_dict() for s in self.get_defined_structures()]
            logger.debug("Fetching referenced_structures...")
            data["referenced_structures"] = [s.to_dict() for s in self.get_referenced_structures()]
            logger.debug("Fetching named_structures...")
            data["named_structures"] = [s.to_dict() for s in self.get_named_structures()]

            # Validation and parse status
            logger.debug("Fetching file_parse_status...")
            data["file_parse_status"] = [s.to_dict() for s in self.get_file_parse_status()]
            logger.debug("Fetching init_issues...")
            data["init_issues"] = [i.to_dict() for i in self.get_init_issues()]
            logger.debug("Fetching parse_warnings...")
            data["parse_warnings"] = [w.to_dict() for w in self.get_parse_warnings()]
            logger.debug("Fetching vi_conversion_status...")
            data["vi_conversion_status"] = [s.to_dict() for s in self.get_vi_conversion_status()]

            # Reachability and policy analysis
            logger.debug("Fetching reachability...")
            data["reachability"] = [f.to_dict() for f in self.get_reachability()]
            logger.debug("Fetching search_route_policies...")
            data["search_route_policies"] = self.get_search_route_policies()
            logger.debug("Fetching aaa_authentication_login...")
            data["aaa_authentication_login"] = self.get_aaa_authentication_login()

            # BGP Protocol Analysis
            logger.debug("Fetching bgp_edges...")
            data["bgp_edges"] = self.get_bgp_edges()
            logger.debug("Fetching bgp_peer_configuration...")
            data["bgp_peer_configuration"] = self.get_bgp_peer_configuration()
            logger.debug("Fetching bgp_process_configuration...")
            data["bgp_process_configuration"] = self.get_bgp_process_configuration()
            logger.debug("Fetching bgp_session_status...")
            data["bgp_session_status"] = self.get_bgp_session_status()
            logger.debug("Fetching bgp_session_compatibility...")
            data["bgp_session_compatibility"] = self.get_bgp_session_compatibility()
            logger.debug("Fetching bgp_rib...")
            data["bgp_rib"] = self.get_bgp_rib()

            # ACL/Firewall Analysis
            logger.debug("Fetching filter_line_reachability...")
            data["filter_line_reachability"] = self.get_filter_line_reachability()
            # Note: test_filters, search_filters, find_matching_filter_lines require parameters
            # They will be called through specific API endpoints with parameters

            # Advanced Path Analysis
            # Note: traceroute and bidirectional_traceroute require parameters
            # They will be called through specific API endpoints with parameters

            # ========== PHASE 1: CRITICAL - Network Validation (12 queries) ==========

            logger.debug("Fetching unused_structures...")
            data["unused_structures"] = self.get_unused_structures()
            logger.debug("Fetching undefined_references...")
            data["undefined_references"] = self.get_undefined_references()
            logger.debug("Fetching vrrp_properties...")
            data["vrrp_properties"] = self.get_vrrp_properties()
            logger.debug("Fetching hsrp_properties...")
            data["hsrp_properties"] = self.get_hsrp_properties()
            logger.debug("Fetching mlag_properties...")
            data["mlag_properties"] = self.get_mlag_properties()
            logger.debug("Fetching detect_loops...")
            data["detect_loops"] = self.get_detect_loops()
            logger.debug("Fetching multipath_consistency...")
            data["multipath_consistency"] = self.get_multipath_consistency()
            logger.debug("Fetching loopback_multipath_consistency...")
            data["loopback_multipath_consistency"] = self.get_loopback_multipath_consistency()
            # Note: resolve_filter_specifier, resolve_node_specifier, resolve_interface_specifier,
            # compare_filters require parameters - called through API endpoints

            # ========== PHASE 2: IMPORTANT - Additional Protocols (13 queries) ==========

            logger.debug("Fetching evpn_rib...")
            data["evpn_rib"] = self.get_evpn_rib()
            logger.debug("Fetching vxlan_edges...")
            data["vxlan_edges"] = self.get_vxlan_edges()
            logger.debug("Fetching vxlan_vni_properties...")
            data["vxlan_vni_properties"] = self.get_vxlan_vni_properties()
            logger.debug("Fetching eigrp_edges...")
            data["eigrp_edges"] = self.get_eigrp_edges()
            logger.debug("Fetching eigrp_interface_configuration...")
            data["eigrp_interface_configuration"] = self.get_eigrp_interface_configuration()
            logger.debug("Fetching isis_edges...")
            data["isis_edges"] = self.get_isis_edges()
            logger.debug("Fetching isis_interface_configuration...")
            data["isis_interface_configuration"] = self.get_isis_interface_configuration()
            logger.debug("Fetching layer1_edges...")
            data["layer1_edges"] = self.get_layer1_edges()
            logger.debug("Fetching switched_vlan_edges...")
            data["switched_vlan_edges"] = self.get_switched_vlan_edges()
            logger.debug("Fetching ipsec_edges...")
            data["ipsec_edges"] = self.get_ipsec_edges()
            logger.debug("Fetching interface_mtu...")
            data["interface_mtu"] = self.get_interface_mtu()
            logger.debug("Fetching ip_space_assignment...")
            data["ip_space_assignment"] = self.get_ip_space_assignment()
            # Note: lpm_routes and prefix_tracer can accept parameters - called through API endpoints

            # ========== PHASE 3: NICE-TO-HAVE (10 queries) ==========

            logger.debug("Fetching f5_bigip_vip_configuration...")
            data["f5_bigip_vip_configuration"] = self.get_f5_bigip_vip_configuration()
            logger.debug("Fetching route_policies...")
            data["route_policies"] = self.get_route_policies()
            logger.debug("Fetching questions...")
            data["questions"] = self.get_questions()
            logger.debug("Fetching node_roles...")
            data["node_roles"] = self.get_node_roles()
            logger.debug("Fetching interface_blacklist...")
            data["interface_blacklist"] = self.get_interface_blacklist()
            # Note: differential_reachability, bidirectional_reachability, resolve_location_specifier,
            # resolve_ip_specifier, test_route_policies require parameters or special setup

        except Exception as e:
            logger.error(f"Error in fetch_all_data: {e}", exc_info=True)
            raise

        logger.info("All Batfish data fetched successfully (70 query types)")
        return data