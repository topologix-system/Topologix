"""
Configuration validation and parsing data models (dataclasses)
- FileParseStatus: Configuration file parse status and format
- InitIssue: Initialization issues detected by Batfish
- ParseWarning: Parse warnings from Batfish parser
- ViConversionStatus: Vendor-independent format conversion status
- DuplicateRouterID: Duplicate OSPF router ID detection
- Maps to Batfish fileParseStatus and initIssues queries
- Used for configuration validation and troubleshooting
"""
from dataclasses import dataclass, field, asdict


@dataclass
class FileParseStatus:
    """File parse status"""
    file_name: str
    status: str
    file_format: str | None = None
    nodes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InitIssue:
    """Initialization issue"""
    nodes: list[str] | None = None
    source_lines: list[str] = field(default_factory=list)
    type: str = ""
    details: str = ""
    line_text: str = ""
    parser_context: str = ""

    def to_dict(self) -> dict:
        # source_linesを手動で安全に変換
        result = {
            "nodes": self.nodes,
            "source_lines": self.source_lines if isinstance(self.source_lines, list) else [],
            "type": self.type,
            "details": self.details,
            "line_text": self.line_text,
            "parser_context": self.parser_context
        }
        return result


@dataclass
class ParseWarning:
    """Parse warning"""
    filename: str
    line: int
    text: str
    parser_context: str = ""
    comment: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ViConversionStatus:
    """VI conversion status"""
    node: str
    status: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DuplicateRouterID:
    """Duplicate router ID detected in OSPF or BGP"""
    node: str
    vrf: str
    router_id: str
    protocol: str  # "OSPF" or "BGP"
    area: str | None = None  # For OSPF
    remote_node: str | None = None
    session_status: str = "DUPLICATE_ROUTER_ID"

    def to_dict(self) -> dict:
        return asdict(self)