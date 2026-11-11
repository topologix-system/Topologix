import inspect
import json
import unittest

import numpy as np
import pandas as pd
from pybatfish.datamodel.flow import Flow, Trace
from pybatfish.datamodel.primitives import FileLines, Interface, ListWrapper

from services.batfish_service import BatfishService


RESOLVE_FILTER_SPECIFIER_COLUMNS = ["Node", "Filter_Name"]
SEARCH_FILTERS_COLUMNS = ["Node", "Filter_Name", "Flow", "Action", "Line_Content", "Trace"]
FIND_MATCHING_FILTER_LINES_COLUMNS = ["Node", "Filter", "Line", "Line_Index", "Action"]
RESOLVE_IP_SPECIFIER_COLUMNS = ["IP_Space"]
UNDEFINED_REFERENCES_COLUMNS = ["File_Name", "Struct_Type", "Ref_Name", "Context", "Lines"]
FHRP_PROPERTIES_COLUMNS = [
    "Interface",
    "Group_Id",
    "Virtual_Addresses",
    "Source_Address",
    "Priority",
    "Preempt",
    "Active",
]
MLAG_PROPERTIES_COLUMNS = ["Node", "MLAG_ID", "Peer_Address", "Local_Interface", "Source_Interface"]
BGP_EDGES_COLUMNS = [
    "Node",
    "IP",
    "Interface",
    "AS_Number",
    "Remote_Node",
    "Remote_IP",
    "Remote_Interface",
    "Remote_AS_Number",
]
OSPF_SESSION_COMPATIBILITY_COLUMNS = [
    "Interface",
    "VRF",
    "IP",
    "Area",
    "Remote_Interface",
    "Remote_VRF",
    "Remote_IP",
    "Remote_Area",
    "Session_Status",
]
OSPF_PROCESS_CONFIGURATION_COLUMNS = [
    "Node",
    "VRF",
    "Process_ID",
    "Areas",
    "Reference_Bandwidth",
    "Router_ID",
    "Export_Policy_Sources",
    "Area_Border_Router",
]
IPSEC_SESSION_STATUS_COLUMNS = [
    "Node",
    "Node_Interface",
    "Node_IP",
    "Remote_Node",
    "Remote_Node_Interface",
    "Remote_Node_IP",
    "Tunnel_Interfaces",
    "Status",
]
EVPN_RIB_COLUMNS = [
    "Node",
    "VRF",
    "Network",
    "Status",
    "Route_Distinguisher",
    "Next_Hop",
    "Next_Hop_IP",
    "Next_Hop_Interface",
    "Protocol",
    "AS_Path",
    "Metric",
    "Local_Pref",
    "Communities",
    "Origin_Protocol",
    "Origin_Type",
    "Originator_Id",
    "Received_Path_Id",
    "Cluster_List",
    "Tunnel_Encapsulation_Attribute",
    "Weight",
    "Tag",
]
VXLAN_VNI_PROPERTIES_COLUMNS = [
    "Node",
    "VRF",
    "VNI",
    "Local_VTEP_IP",
    "Multicast_Group",
    "VLAN",
    "VTEP_Flood_List",
    "VXLAN_Port",
]
FLOW_TRACES_COLUMNS = ["Flow", "Traces", "TraceCount"]
INTERFACE_PROPERTIES_COLUMNS = [
    "Interface",
    "Access_VLAN",
    "Active",
    "Admin_Up",
    "All_Prefixes",
    "Allowed_VLANs",
    "Auto_State_VLAN",
    "Bandwidth",
    "Blacklisted",
    "Channel_Group",
    "Channel_Group_Members",
    "DHCP_Relay_Addresses",
    "Declared_Names",
    "Description",
    "Encapsulation_VLAN",
    "HSRP_Groups",
    "HSRP_Version",
    "Inactive_Reason",
    "Incoming_Filter_Name",
    "MLAG_ID",
    "MTU",
    "Native_VLAN",
    "Outgoing_Filter_Name",
    "PBR_Policy_Name",
    "Primary_Address",
    "Primary_Network",
    "Proxy_ARP",
    "Rip_Enabled",
    "Rip_Passive",
    "Spanning_Tree_Portfast",
    "Speed",
    "Switchport",
    "Switchport_Mode",
    "Switchport_Trunk_Encapsulation",
    "VRF",
    "VRRP_Groups",
    "Zone_Name",
]
OSPF_INTERFACE_CONFIGURATION_COLUMNS = [
    "Interface",
    "VRF",
    "Process_ID",
    "OSPF_Area_Name",
    "OSPF_Enabled",
    "OSPF_Passive",
    "OSPF_Cost",
    "OSPF_Network_Type",
    "OSPF_Hello_Interval",
    "OSPF_Dead_Interval",
]
BIDIRECTIONAL_REACHABILITY_COLUMNS = [
    "Forward_Flow",
    "Forward_Traces",
    "New_Sessions",
    "Reverse_Flow",
    "Reverse_Traces",
]
F5_BIGIP_VIP_CONFIGURATION_COLUMNS = ["Node", "VIP_Name", "VIP_Endpoint", "Servers", "Description"]
NAMED_STRUCTURES_COLUMNS = ["Node", "Structure_Type", "Structure_Name", "Structure_Definition"]


def _frame(columns, rows):
    return pd.DataFrame(
        [{column: row.get(column) for column in columns} for row in rows],
        columns=columns,
        dtype=object,
    )


def _flow(src_ip, dst_ip, ingress_node, ingress_vrf="default", ingress_interface=None):
    return Flow.from_dict({
        "dscp": 0,
        "dstIp": dst_ip,
        "dstPort": None,
        "ecn": 0,
        "fragmentOffset": 0,
        "icmpCode": 0,
        "icmpVar": 8,
        "ingressInterface": ingress_interface,
        "ingressNode": ingress_node,
        "ingressVrf": ingress_vrf,
        "ipProtocol": "ICMP",
        "packetLength": 512,
        "srcIp": src_ip,
        "srcPort": None,
        "tcpFlagsAck": 0,
        "tcpFlagsCwr": 0,
        "tcpFlagsEce": 0,
        "tcpFlagsFin": 0,
        "tcpFlagsPsh": 0,
        "tcpFlagsRst": 0,
        "tcpFlagsSyn": 0,
        "tcpFlagsUrg": 0,
    })


def _traces(*dispositions_and_networks):
    return ListWrapper([
        Trace.from_dict({
            "disposition": disposition,
            "hops": [{
                "node": {"name": "lp-r1"},
                "steps": [{
                    "type": "Routing",
                    "action": "FORWARDED",
                    "detail": {
                        "outputInterface": "GigabitEthernet0/0",
                        "arpIp": "10.2.12.2",
                        "routes": [{
                            "network": network,
                            "protocol": "static",
                            "nextHop": {"type": "ip", "ip": "10.2.12.2"},
                            "admin": 1,
                            "metric": 0,
                        }],
                    },
                }],
            }],
        })
        for disposition, network in dispositions_and_networks
    ])


class _QuestionApi:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def question(**parameters):
            self.calls.append((name, parameters))
            return name
        return question


class _Session:
    def __init__(self):
        self.q = _QuestionApi()


class BatfishAnswerColumnContractTest(unittest.TestCase):
    def setUp(self):
        self.service = BatfishService()
        self.service._initialized = True
        self.service._session = _Session()
        self.frames = {}
        self.service._execute_query = lambda query, query_name, **kwargs: self.frames.get(query_name)
        self.service._execute_query_factory = (
            lambda query_factory, query_name, **kwargs: self.frames.get(query_name)
        )

    @property
    def question_calls(self):
        return self.service._session.q.calls

    def test_resolve_filter_specifier_reads_filter_name(self):
        self.frames["resolveFilterSpecifier"] = _frame(RESOLVE_FILTER_SPECIFIER_COLUMNS, [
            {"Node": "core-rtr1", "Filter_Name": "BLOCK-DC-ICMP"},
            {"Node": "core-rtr1", "Filter_Name": "FILTER-EXTERNAL"},
        ])

        results = self.service.resolve_filter_specifier(filters=".*", nodes="core-rtr1")

        self.assertEqual(results, [
            {"node": "core-rtr1", "filter": "BLOCK-DC-ICMP"},
            {"node": "core-rtr1", "filter": "FILTER-EXTERNAL"},
        ])

    def test_search_filters_reads_filter_name(self):
        self.frames["searchFilters"] = _frame(SEARCH_FILTERS_COLUMNS, [{
            "Node": "core-rtr1",
            "Filter_Name": "FILTER-EXTERNAL",
            "Flow": _flow("203.0.113.0", "10.255.0.1", "core-rtr1"),
            "Action": "DENY",
            "Line_Content": "deny   icmp 203.0.113.0 0.0.0.3 any",
            "Trace": None,
        }])

        result = self.service.search_filters(action="deny", filters="FILTER-EXTERNAL", nodes="core-rtr1")[0]

        self.assertEqual(set(result), {"node", "filter", "flow", "action", "line_content", "trace"})
        self.assertEqual(result["filter"], "FILTER-EXTERNAL")
        self.assertEqual(result["line_content"], "deny   icmp 203.0.113.0 0.0.0.3 any")

    def test_find_matching_filter_lines_reads_line_and_keeps_index_zero(self):
        self.frames["findMatchingFilterLines"] = _frame(FIND_MATCHING_FILTER_LINES_COLUMNS, [{
            "Node": "core-rtr1",
            "Filter": "FILTER-EXTERNAL",
            "Line": "deny   icmp 203.0.113.0 0.0.0.3 any",
            "Line_Index": 0,
            "Action": "DENY",
        }])

        result = self.service.find_matching_filter_lines(filters="FILTER-EXTERNAL", nodes="core-rtr1")[0]

        self.assertEqual(set(result), {"node", "filter", "flow", "action", "line_content", "line_index"})
        self.assertEqual(result["filter"], "FILTER-EXTERNAL")
        self.assertEqual(result["line_content"], "deny   icmp 203.0.113.0 0.0.0.3 any")
        self.assertEqual(result["line_index"], 0)

    def test_resolve_ip_specifier_reads_ip_space(self):
        self.frames["resolveIpSpecifier"] = _frame(RESOLVE_IP_SPECIFIER_COLUMNS, [
            {"IP_Space": "PrefixIpSpace{prefix=10.0.0.0/30}"},
        ])

        self.assertEqual(
            self.service.resolve_ip_specifier(ips="10.0.0.0/30"),
            [{"ip": "PrefixIpSpace{prefix=10.0.0.0/30}"}],
        )

    def test_undefined_references_reads_reference_name_type_and_lines(self):
        self.frames["undefinedReferences"] = _frame(UNDEFINED_REFERENCES_COLUMNS, [{
            "File_Name": "configs/fg-fw1.txt",
            "Struct_Type": "service custom or service group",
            "Ref_Name": "ALL",
            "Context": "firewall policy service",
            "Lines": FileLines(filename="configs/fg-fw1.txt", lines=[92, 114]),
        }])

        self.assertEqual(self.service.get_undefined_references(), [{
            "structure_type": "service custom or service group",
            "structure_name": "ALL",
            "context": "firewall policy service",
            "source_lines": {"filename": "configs/fg-fw1.txt", "lines": [92, 114]},
        }])

    @staticmethod
    def _fhrp_row(interface, group_id, virtual_addresses=("192.168.10.1",)):
        return {
            "Interface": Interface(hostname=interface[0], interface=interface[1]),
            "Group_Id": group_id,
            "Virtual_Addresses": ListWrapper(list(virtual_addresses)),
            "Source_Address": "192.168.10.2/24",
            "Priority": 110,
            "Preempt": True,
            "Active": True,
        }

    def test_hsrp_reads_group_id_and_virtual_addresses(self):
        self.frames["hsrpProperties"] = _frame(FHRP_PROPERTIES_COLUMNS, [
            self._fhrp_row(("ha-r1", "GigabitEthernet0/1"), 10),
            self._fhrp_row(("ha-r1", "GigabitEthernet0/2"), 0, ("192.168.20.1", "192.168.20.9")),
        ])

        results = self.service.get_hsrp_properties()

        self.assertEqual(set(results[0]), {
            "interface", "hsrp_group", "group_number", "virtual_address", "priority", "preempt",
        })
        self.assertEqual(results[0]["interface"], "ha-r1[GigabitEthernet0/1]")
        self.assertEqual(results[0]["hsrp_group"], 10)
        self.assertEqual(results[0]["group_number"], 10)
        self.assertEqual(results[0]["virtual_address"], "192.168.10.1")
        self.assertEqual(results[1]["hsrp_group"], 0)
        self.assertEqual(results[1]["group_number"], 0)
        self.assertEqual(results[1]["virtual_address"], "192.168.20.1, 192.168.20.9")

    def test_hsrp_normalizes_numpy_and_missing_group_ids(self):
        self.frames["hsrpProperties"] = _frame(FHRP_PROPERTIES_COLUMNS, [
            self._fhrp_row(("ha-r1", "GigabitEthernet0/1"), np.int64(10)),
            self._fhrp_row(("ha-r1", "GigabitEthernet0/2"), np.nan, ()),
            self._fhrp_row(("ha-r1", "GigabitEthernet0/3"), pd.NA),
        ])

        results = self.service.get_hsrp_properties()

        self.assertEqual(results[0]["hsrp_group"], 10)
        self.assertIs(type(results[0]["hsrp_group"]), int)
        self.assertIs(type(results[0]["group_number"]), int)
        self.assertIsNone(results[1]["hsrp_group"])
        self.assertIsNone(results[1]["group_number"])
        self.assertIsNone(results[1]["virtual_address"])
        self.assertIsNone(results[2]["hsrp_group"])

    def test_vrrp_reads_group_id_and_virtual_addresses(self):
        self.frames["vrrpProperties"] = _frame(FHRP_PROPERTIES_COLUMNS, [
            self._fhrp_row(("ha-r1", "GigabitEthernet0/2"), np.int64(20), ("192.168.20.1",)),
            self._fhrp_row(("ha-r2", "GigabitEthernet0/2"), 0),
            self._fhrp_row(("ha-r3", "GigabitEthernet0/2"), np.nan, ()),
        ])

        results = self.service.get_vrrp_properties()

        self.assertEqual(set(results[0]), {
            "interface", "vrrp_group", "virtual_address", "priority", "preempt", "source_address",
        })
        self.assertEqual(results[0]["vrrp_group"], 20)
        self.assertIs(type(results[0]["vrrp_group"]), int)
        self.assertEqual(results[0]["virtual_address"], "192.168.20.1")
        self.assertEqual(results[1]["vrrp_group"], 0)
        self.assertIsNone(results[2]["vrrp_group"])
        self.assertIsNone(results[2]["virtual_address"])

    def test_mlag_reads_mlag_id(self):
        self.frames["mlagProperties"] = _frame(MLAG_PROPERTIES_COLUMNS, [{
            "Node": "ha-sw1",
            "MLAG_ID": "FNCOV-MLAG",
            "Peer_Address": "10.0.94.2",
            "Local_Interface": Interface(hostname="ha-sw1", interface="Port-Channel10"),
            "Source_Interface": Interface(hostname="ha-sw1", interface="Vlan4094"),
        }])

        result = self.service.get_mlag_properties()[0]

        self.assertEqual(set(result), {"node", "id", "local_interface", "peer_address", "peer_interface"})
        self.assertEqual(result["id"], "FNCOV-MLAG")
        self.assertEqual(result["local_interface"], "ha-sw1[Port-Channel10]")

    def test_duplicate_router_ids_parse_bracketed_interface_names(self):
        def session_row(local, remote):
            return {
                "Interface": Interface(hostname=local[0], interface=local[1]),
                "VRF": "default",
                "IP": "10.1.13.1",
                "Area": 0,
                "Remote_Interface": Interface(hostname=remote[0], interface=remote[1]),
                "Remote_VRF": "default",
                "Remote_IP": "10.1.13.2",
                "Remote_Area": 0,
                "Session_Status": "DUPLICATE_ROUTER_ID",
            }

        def process_row(node):
            return {"Node": node, "VRF": "default", "Process_ID": "1", "Router_ID": "10.9.9.9"}

        self.frames["ospfSessionCompatibility"] = _frame(OSPF_SESSION_COMPATIBILITY_COLUMNS, [
            session_row(("ha-r1", "GigabitEthernet0/3"), ("ha-r3", "GigabitEthernet0/0")),
            session_row(("ha-r3", "GigabitEthernet0/0"), ("ha-r1", "GigabitEthernet0/3")),
        ])
        self.frames["ospfProcessConfiguration"] = _frame(OSPF_PROCESS_CONFIGURATION_COLUMNS, [
            process_row("ha-r1"),
            process_row("ha-r3"),
        ])

        results = [duplicate.to_dict() for duplicate in self.service.get_duplicate_router_ids()]

        self.assertEqual(results, [
            {"node": "ha-r1", "vrf": "default", "router_id": "10.9.9.9", "protocol": "OSPF",
             "area": "0", "remote_node": "ha-r3", "session_status": "DUPLICATE_ROUTER_ID"},
            {"node": "ha-r3", "vrf": "default", "router_id": "10.9.9.9", "protocol": "OSPF",
             "area": "0", "remote_node": "ha-r1", "session_status": "DUPLICATE_ROUTER_ID"},
        ])

    def test_ipsec_session_status_reads_node_ips(self):
        self.frames["ipsecSessionStatus"] = _frame(IPSEC_SESSION_STATUS_COLUMNS, [{
            "Node": "ha-r1",
            "Node_Interface": Interface(hostname="ha-r1", interface="GigabitEthernet0/4"),
            "Node_IP": "203.0.113.1",
            "Remote_Node": "ha-r4",
            "Remote_Node_Interface": Interface(hostname="ha-r4", interface="GigabitEthernet0/0"),
            "Remote_Node_IP": "203.0.113.2",
            "Tunnel_Interfaces": "Tunnel0 -> Tunnel0",
            "Status": "IPSEC_SESSION_ESTABLISHED",
        }])

        result = self.service.get_ipsec_session_status()[0]

        self.assertEqual(set(result), {
            "node", "vpn", "remote_node", "remote_ip", "local_ip", "status", "tunnel_interfaces",
        })
        self.assertEqual(result["local_ip"], "203.0.113.1")
        self.assertEqual(result["remote_ip"], "203.0.113.2")

    def test_bgp_edges_read_ip_and_as_number_columns(self):
        self.frames["bgpEdges"] = _frame(BGP_EDGES_COLUMNS, [{
            "Node": "core-rtr1",
            "IP": "10.255.0.1",
            "Interface": None,
            "AS_Number": "65000",
            "Remote_Node": "dist-sw2",
            "Remote_IP": "10.255.0.4",
            "Remote_Interface": None,
            "Remote_AS_Number": "65001",
        }])

        result = self.service.get_bgp_edges()[0]

        self.assertEqual(result, {
            "node": "core-rtr1",
            "interface": None,
            "remote_node": "dist-sw2",
            "remote_interface": None,
            "remote_ip": "10.255.0.4",
            "local_ip": "10.255.0.1",
            "remote_asn": "65001",
            "local_asn": "65000",
        })

    def test_bgp_edges_missing_values_are_null_not_empty_strings(self):
        self.frames["bgpEdges"] = _frame(BGP_EDGES_COLUMNS, [{
            "Node": "r1",
            "IP": None,
            "AS_Number": np.nan,
            "Remote_Node": "r2",
            "Remote_IP": "192.0.2.2",
            "Remote_AS_Number": None,
        }])

        result = self.service.get_bgp_edges()[0]

        self.assertIsNone(result["local_ip"])
        self.assertIsNone(result["local_asn"])
        self.assertIsNone(result["remote_asn"])

    def test_evpn_rib_reads_network_and_originator_id(self):
        row = {column: None for column in EVPN_RIB_COLUMNS}
        row.update({
            "Node": "evpn-leaf1",
            "VRF": "default",
            "Network": "172.20.2.1/32",
            "Route_Distinguisher": "10.255.10.2:50001",
            "Protocol": "bgp",
            "Originator_Id": "10.255.10.2",
        })
        self.frames["evpnRib"] = _frame(EVPN_RIB_COLUMNS, [row])

        result = self.service.get_evpn_rib()[0]

        self.assertEqual(set(result), {
            "node", "vrf", "route_distinguisher", "prefix", "next_hop", "originator_ip", "route_type", "vni",
        })
        self.assertEqual(result["prefix"], "172.20.2.1/32")
        self.assertEqual(result["originator_ip"], "10.255.10.2")
        self.assertEqual(result["route_distinguisher"], "10.255.10.2:50001")

    def test_interface_properties_derive_vlan_from_access_or_encapsulation_vlan(self):
        def row(interface, mode, access_vlan=None, encapsulation_vlan=None, native_vlan=None):
            return {
                "Interface": Interface(hostname="sw1", interface=interface),
                "Access_VLAN": access_vlan,
                "Active": True,
                "Encapsulation_VLAN": encapsulation_vlan,
                "Native_VLAN": native_vlan,
                "Switchport": mode != "NONE",
                "Switchport_Mode": mode,
            }

        self.frames["interfaceProperties"] = _frame(INTERFACE_PROPERTIES_COLUMNS, [
            row("GigabitEthernet0/1", "ACCESS", access_vlan=10),
            row("GigabitEthernet0/2", "TRUNK", native_vlan=99),
            row("GigabitEthernet0/3.200", "NONE", encapsulation_vlan=np.int64(200)),
            row("GigabitEthernet0/4", "NONE"),
            row("GigabitEthernet0/5", "ACCESS", access_vlan=np.nan),
        ])

        results = self.service.get_interface_properties()

        self.assertEqual(
            [(result["interface"], result["vlan"]) for result in results],
            [
                ("GigabitEthernet0/1", 10),
                ("GigabitEthernet0/2", None),
                ("GigabitEthernet0/3.200", 200),
                ("GigabitEthernet0/4", None),
                ("GigabitEthernet0/5", None),
            ],
        )
        self.assertIs(type(results[2]["vlan"]), int)
        self.assertEqual(results[0]["access_vlan"], 10)
        self.assertEqual(results[1]["native_vlan"], 99)

    def test_interface_properties_read_rip_and_zone_name_columns(self):
        def row(interface, rip_enabled, rip_passive, zone_name):
            return {
                "Interface": Interface(hostname="pa-fw1", interface=interface),
                "Active": True,
                "Rip_Enabled": rip_enabled,
                "Rip_Passive": rip_passive,
                "Zone_Name": zone_name,
            }

        self.frames["interfaceProperties"] = _frame(INTERFACE_PROPERTIES_COLUMNS, [
            row("ethernet1/1", True, False, "UNTRUST"),
            row("ethernet1/2", np.bool_(True), np.bool_(True), "TRUST"),
            row("ethernet1/3", False, None, None),
        ])

        results = self.service.get_interface_properties()

        self.assertEqual(
            [(result["rip_enabled"], result["rip_passive"], result["zone"]) for result in results],
            [(True, False, "UNTRUST"), (True, True, "TRUST"), (False, False, None)],
        )
        self.assertIs(type(results[1]["rip_enabled"]), bool)
        self.assertIs(type(results[1]["rip_passive"]), bool)
        json.dumps(results)

    @staticmethod
    def _ospf_interface_row(interface, area, cost, network_type, passive):
        return {
            "Interface": Interface(hostname=interface[0], interface=interface[1]),
            "VRF": "default",
            "Process_ID": "1",
            "OSPF_Area_Name": area,
            "OSPF_Enabled": np.bool_(True),
            "OSPF_Passive": passive,
            "OSPF_Cost": cost,
            "OSPF_Network_Type": network_type,
            "OSPF_Hello_Interval": 10,
            "OSPF_Dead_Interval": 40,
        }

    def _two_router_interfaces(self):
        self.frames["interfaceProperties"] = _frame(INTERFACE_PROPERTIES_COLUMNS, [
            {"Interface": Interface(hostname="core-rtr1", interface="GigabitEthernet0/0"), "Active": True},
            {"Interface": Interface(hostname="core-rtr1", interface="GigabitEthernet0/1"), "Active": True},
        ])

    def _ospf_question_calls(self):
        return [call for call in self.question_calls if call[0] == "ospfInterfaceConfiguration"]

    def test_interface_properties_join_ospf_interface_configuration(self):
        self._two_router_interfaces()
        self.frames["ospfInterfaceConfiguration"] = _frame(OSPF_INTERFACE_CONFIGURATION_COLUMNS, [
            self._ospf_interface_row(
                ("core-rtr1", "GigabitEthernet0/0"), np.int64(0), np.int64(10), "POINT_TO_POINT", np.bool_(False),
            ),
            self._ospf_interface_row(("core-rtr9", "GigabitEthernet0/1"), 1, 1, "BROADCAST", True),
        ])

        results = self.service.get_interface_properties()

        ospf_keys = ["ospf_area_name", "ospf_cost", "ospf_enabled", "ospf_network_type", "ospf_passive"]
        self.assertEqual(self._ospf_question_calls(), [("ospfInterfaceConfiguration", {})])
        self.assertEqual(
            {key: results[0][key] for key in ospf_keys},
            {
                "ospf_area_name": "0",
                "ospf_cost": 10,
                "ospf_enabled": True,
                "ospf_network_type": "POINT_TO_POINT",
                "ospf_passive": False,
            },
        )
        self.assertIs(type(results[0]["ospf_cost"]), int)
        self.assertIs(type(results[0]["ospf_enabled"]), bool)
        self.assertIs(type(results[0]["ospf_passive"]), bool)
        self.assertEqual(
            {key: results[1][key] for key in ospf_keys},
            {
                "ospf_area_name": None,
                "ospf_cost": None,
                "ospf_enabled": False,
                "ospf_network_type": None,
                "ospf_passive": False,
            },
        )
        json.dumps(results)

    def test_interface_properties_keep_ospf_defaults_when_ospf_query_fails(self):
        self._two_router_interfaces()

        results = self.service.get_interface_properties()

        self.assertEqual(self._ospf_question_calls(), [("ospfInterfaceConfiguration", {})])
        self.assertEqual(
            [result["interface"] for result in results],
            ["GigabitEthernet0/0", "GigabitEthernet0/1"],
        )
        for result in results:
            self.assertIsNone(result["ospf_area_name"])
            self.assertIsNone(result["ospf_cost"])
            self.assertIs(result["ospf_enabled"], False)
            self.assertIsNone(result["ospf_network_type"])
            self.assertIs(result["ospf_passive"], False)

    def test_interface_properties_skip_ospf_query_without_interfaces(self):
        self.assertEqual(self.service.get_interface_properties(), [])
        self.assertEqual(self._ospf_question_calls(), [])

    def test_snapshot_interface_properties_skip_ospf_query(self):
        self._two_router_interfaces()
        self.service.current_snapshot_name = "active-x"
        self.service._session.snapshot = "active-x"
        self.service._load_snapshot = lambda snapshot_dir, snapshot_name: None

        for snapshot_name in ("active-x", "comp-b"):
            with self.subTest(snapshot=snapshot_name):
                results = self.service.get_snapshot_interface_properties("unused", snapshot_name)

                self.assertEqual(
                    [result["interface"] for result in results],
                    ["GigabitEthernet0/0", "GigabitEthernet0/1"],
                )
        self.assertEqual(self._ospf_question_calls(), [])
        self.assertEqual(
            [call for call in self.question_calls if call[0] == "interfaceProperties"],
            [("interfaceProperties", {}), ("interfaceProperties", {})],
        )
        self.assertEqual(self.service._session.snapshot, "active-x")

    def test_aggregate_fetch_reuses_the_ospf_interface_answer(self):
        self._two_router_interfaces()
        self.frames["ospfInterfaceConfiguration"] = _frame(OSPF_INTERFACE_CONFIGURATION_COLUMNS, [
            self._ospf_interface_row(("core-rtr1", "GigabitEthernet0/1"), 0, 10, "POINT_TO_POINT", False),
        ])

        data = self.service.fetch_all_data()

        self.assertEqual(self._ospf_question_calls(), [("ospfInterfaceConfiguration", {})])
        self.assertEqual(
            [interface["interface"] for interface in data["ospf_interface_configuration"]],
            ["core-rtr1[GigabitEthernet0/1]"],
        )
        self.assertEqual(
            [(result["interface"], result["ospf_enabled"]) for result in data["interface_properties"]],
            [("GigabitEthernet0/0", False), ("GigabitEthernet0/1", True)],
        )

    def test_vxlan_vni_properties_reads_vxlan_port(self):
        def row(node, port):
            return {
                "Node": node,
                "VRF": "default",
                "VNI": 10010,
                "Local_VTEP_IP": "10.254.10.1",
                "Multicast_Group": None,
                "VLAN": 10,
                "VTEP_Flood_List": ListWrapper(["10.254.10.2"]),
                "VXLAN_Port": port,
            }

        self.frames["vxlanVniProperties"] = _frame(VXLAN_VNI_PROPERTIES_COLUMNS, [
            row("evpn-leaf1", 4789),
            row("evpn-leaf2", np.int64(4789)),
            row("evpn-leaf3", 0),
            row("evpn-leaf4", np.nan),
            row("evpn-leaf5", pd.NA),
        ])

        results = self.service.get_vxlan_vni_properties()

        self.assertEqual(set(results[0]), {
            "node", "vni", "vlan", "vrf", "udp_port", "vtep_flood_list", "multicast_group",
        })
        self.assertEqual([result["udp_port"] for result in results], [4789, 4789, 0, None, None])
        self.assertIs(type(results[1]["udp_port"]), int)

    def test_detect_loops_reads_flow_and_traces(self):
        self.frames["detectLoops"] = _frame(FLOW_TRACES_COLUMNS, [{
            "Flow": _flow("10.2.12.1", "10.77.0.0", "lp-r1"),
            "Traces": _traces(("LOOP", "10.77.0.0/24")),
            "TraceCount": 1,
        }])

        result = self.service.get_detect_loops()[0]

        self.assertEqual(set(result), {"node", "vrf", "loop"})
        self.assertEqual(result["node"], "lp-r1")
        self.assertEqual(result["vrf"], "default")
        self.assertIsInstance(result["loop"], list)
        self.assertEqual(result["loop"][0]["disposition"], "LOOP")
        self.assertIn("10.77.0.0/24", json.dumps(result["loop"]))

    def test_multipath_consistency_reports_each_flow_as_inconsistent(self):
        self.frames["multipathConsistency"] = _frame(FLOW_TRACES_COLUMNS, [
            {
                "Flow": _flow("10.2.12.1", "10.24.4.0", "lp-r1"),
                "Traces": _traces(("EXITS_NETWORK", "10.24.4.0/24"), ("DENIED_OUT", "10.24.4.0/24")),
                "TraceCount": 2,
            },
            {
                "Flow": _flow("10.21.1.2", "10.24.4.0", "lp-r1", None, "GigabitEthernet0/2"),
                "Traces": _traces(("EXITS_NETWORK", "10.24.4.0/24"), ("DENIED_OUT", "10.24.4.0/24")),
                "TraceCount": np.int64(2),
            },
        ])

        results = self.service.get_multipath_consistency()

        self.assertEqual(set(results[0]), {"node", "vrf", "interface", "ip", "dip", "is_multipath_consistent"})
        self.assertEqual(results[0], {
            "node": "lp-r1",
            "vrf": "default",
            "interface": None,
            "ip": "10.2.12.1",
            "dip": "10.24.4.0",
            "is_multipath_consistent": False,
        })
        self.assertEqual(results[1]["interface"], "GigabitEthernet0/2")
        self.assertEqual(results[1]["vrf"], "default")
        self.assertIs(results[1]["is_multipath_consistent"], False)

    def test_loopback_multipath_consistency_reports_each_flow_as_inconsistent(self):
        self.frames["loopbackMultipathConsistency"] = _frame(FLOW_TRACES_COLUMNS, [{
            "Flow": _flow("10.255.21.1", "10.255.24.4", "lp-r1"),
            "Traces": _traces(("ACCEPTED", "10.255.24.4/32"), ("DENIED_OUT", "10.255.24.4/32")),
            "TraceCount": 2,
        }])

        self.assertEqual(self.service.get_loopback_multipath_consistency(), [{
            "node": "lp-r1",
            "vrf": "default",
            "loopback_ip": "10.255.24.4",
            "is_loopback_multipath_consistent": False,
        }])

    def test_bidirectional_reachability_reads_forward_flow(self):
        self.frames["bidirectionalReachability"] = _frame(BIDIRECTIONAL_REACHABILITY_COLUMNS, [{
            "Forward_Flow": _flow("10.31.0.10", "10.255.32.2", "d-r1", None, "GigabitEthernet0/2"),
            "Forward_Traces": _traces(("ACCEPTED", "10.255.32.2/32")),
            "New_Sessions": ListWrapper([]),
            "Reverse_Flow": _flow("10.255.32.2", "10.31.0.10", "d-r2"),
            "Reverse_Traces": _traces(("DELIVERED_TO_SUBNET", "10.31.0.0/24")),
        }])

        result = self.service.get_bidirectional_reachability(headers={"srcIps": "10.31.0.10"})[0]

        self.assertEqual(set(result), {"flow", "forward_traces", "reverse_flow", "reverse_traces"})
        self.assertEqual(result["flow"]["srcIp"], "10.31.0.10")
        self.assertEqual(result["flow"]["ingressNode"], "d-r1")
        self.assertEqual(result["reverse_flow"]["srcIp"], "10.255.32.2")

    def test_f5_vip_reads_address_and_port_from_endpoint(self):
        def row(name, endpoint):
            return {
                "Node": "lb-f5",
                "VIP_Name": name,
                "VIP_Endpoint": endpoint,
                "Servers": ListWrapper(["10.51.0.12:80", "10.51.0.11:80"]),
                "Description": "",
            }

        self.frames["f5BigipVipConfiguration"] = _frame(F5_BIGIP_VIP_CONFIGURATION_COLUMNS, [
            row("/Common/vs_web", "10.50.0.100:80 TCP"),
            row("/Common/vs_any", "10.50.0.101:0 UDP"),
            row("/Common/vs_none", None),
        ])

        results = self.service.get_f5_bigip_vip_configuration()

        self.assertEqual(set(results[0]), {
            "node", "vip_name", "vip_address", "destination_port", "pool", "source_address_translation",
        })
        self.assertEqual(results[0]["vip_address"], "10.50.0.100")
        self.assertEqual(results[0]["destination_port"], 80)
        self.assertEqual(results[1]["vip_address"], "10.50.0.101")
        self.assertEqual(results[1]["destination_port"], 0)
        self.assertIsNone(results[2]["vip_address"])
        self.assertIsNone(results[2]["destination_port"])

    def test_snmp_communities_are_enumerated_from_vrf_structures(self):
        def vrf_row(node, snmp_server):
            definition = {"name": "default"}
            if snmp_server is not ...:
                definition["snmpServer"] = snmp_server
            return {
                "Node": node,
                "Structure_Type": "VRF",
                "Structure_Name": "default",
                "Structure_Definition": definition,
            }

        community = {
            "name": "FNCOV-RO",
            "accessList": "FNCOV-SNMP-ACL",
            "clientIps": {"class": "org.batfish.datamodel.IpWildcardIpSpace", "ipWildcard": "10.99.0.0/24"},
            "ro": True,
            "rw": False,
        }
        unrestricted = {"name": "public", "ro": True, "rw": False}
        single_character = {"name": "x", "accessList": "", "ro": False, "rw": True}
        self.frames["namedStructures"] = _frame(NAMED_STRUCTURES_COLUMNS, [
            vrf_row("ha-r1", None),
            vrf_row("dc-leaf1", {}),
            vrf_row("ha-j1", ...),
            vrf_row("ha-sw1", {"communities": {"FNCOV-RO": community}, "vrf": "default"}),
            vrf_row("ha-sw2", {"communities": {"public": unrestricted, "x": single_character}, "vrf": "default"}),
        ])

        results = self.service.get_snmp_community_clients()

        self.assertEqual(self.question_calls, [("namedStructures", {"structureTypes": "VRF"})])
        self.assertEqual(results, [
            {"node": "ha-sw1", "community": "F***", "client_ips": ["FNCOV-SNMP-ACL"]},
            {"node": "ha-sw2", "community": "p***", "client_ips": []},
            {"node": "ha-sw2", "community": "***", "client_ips": []},
        ])
        self.assertNotIn("FNCOV-RO", json.dumps(results))
        self.assertNotIn("public", json.dumps(results))

    def test_snmp_communities_empty_answer(self):
        self.assertEqual(self.service.get_snmp_community_clients(), [])

    def test_aggregate_fetch_reuses_the_named_structures_answer(self):
        community = {"name": "FNCOV-RO", "accessList": "FNCOV-SNMP-ACL", "ro": True, "rw": False}
        self.frames["namedStructures"] = _frame(NAMED_STRUCTURES_COLUMNS, [
            {
                "Node": "ha-sw1",
                "Structure_Type": "VRF",
                "Structure_Name": "default",
                "Structure_Definition": {"name": "default", "snmpServer": {"communities": {"FNCOV-RO": community}}},
            },
            {
                "Node": "ha-sw1",
                "Structure_Type": "Routing_Policy",
                "Structure_Name": "RM-OUT",
                "Structure_Definition": {"name": "RM-OUT", "snmpServer": {"communities": {"LEAK": community}}},
            },
        ])

        data = self.service.fetch_all_data()

        named_structure_calls = [call for call in self.question_calls if call[0] == "namedStructures"]
        self.assertEqual(named_structure_calls, [("namedStructures", {})])
        self.assertEqual(len(data["named_structures"]), 2)
        self.assertEqual(
            data["snmp_community_clients"],
            [{"node": "ha-sw1", "community": "F***", "client_ips": ["FNCOV-SNMP-ACL"]}],
        )

    def test_aggregate_fetch_without_named_structures_has_no_snmp_communities(self):
        data = self.service.fetch_all_data()

        named_structure_calls = [call for call in self.question_calls if call[0] == "namedStructures"]
        self.assertEqual(named_structure_calls, [("namedStructures", {})])
        self.assertEqual(data["snmp_community_clients"], [])

    def test_wrong_column_names_are_not_reintroduced(self):
        wrong_names = {
            BatfishService.resolve_filter_specifier: ['"Filter"'],
            BatfishService.search_filters: ['"Filter"'],
            BatfishService.find_matching_filter_lines: ['"Line_Content"'],
            BatfishService.resolve_ip_specifier: ['"IP"'],
            BatfishService.get_undefined_references: ['"Structure_Type"', '"Structure_Name"', '"Source_Lines"'],
            BatfishService.get_hsrp_properties: ['"HSRP_Group"', '"Group_Number"', '"Virtual_Address"'],
            BatfishService.get_vrrp_properties: ['"VRRP_Group"', '"Virtual_Address"'],
            BatfishService.get_mlag_properties: ['"ID"'],
            BatfishService.get_ipsec_session_status: ['"Local_IP"', '"Remote_IP"'],
            BatfishService.get_evpn_rib: ['"Prefix"', '"Originator_IP"'],
            BatfishService.get_vxlan_vni_properties: ['"UDP_Port"'],
            BatfishService.get_detect_loops: ['"Node"', '"VRF"', '"Loop"'],
            BatfishService.get_multipath_consistency: ['"Node"', '"IP"', '"DIP"', '"Is_Multipath_Consistent"'],
            BatfishService.get_loopback_multipath_consistency: [
                '"Node"', '"Loopback_IP"', '"Is_Loopback_Multipath_Consistent"',
            ],
            BatfishService.get_bidirectional_reachability: ['"Flow"'],
            BatfishService.get_f5_bigip_vip_configuration: ['"VIP_Address"', '"Destination_Port"'],
            BatfishService.get_snmp_community_clients: ["snmpCommunityClients", '"Client_IPs"'],
            BatfishService.get_bgp_edges: [
                '"Local_IP"', '"Local_AS"', '"Remote_AS"', '"Import_Policy"', '"Export_Policy"',
            ],
            BatfishService.get_interface_properties: [
                '"RIP_Enabled"', '"RIP_Passive"', '"Zone"', '"OSPF_Area_Name"', '"OSPF_Cost"',
                '"OSPF_Enabled"', '"OSPF_Network_Type"', '"OSPF_Passive"',
            ],
        }

        for method, names in wrong_names.items():
            source = inspect.getsource(method)
            for wrong_name in names:
                with self.subTest(method=method.__name__, column=wrong_name):
                    self.assertNotIn(wrong_name, source)


if __name__ == "__main__":
    unittest.main()
