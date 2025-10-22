"""
Configuration structure data models (dataclasses)
- DefinedStructure: Structures defined in network configurations
- ReferencedStructure: Structures referenced but not defined
- NamedStructure: Named structure with full definition
- Maps to Batfish definedStructures and referencedStructures queries
- Includes source lines for traceability to original configs
- Used for configuration analysis and validation
"""
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class DefinedStructure:
    """Defined structure in configuration"""
    structure_type: str
    structure_name: str
    source_lines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = {
            "structure_type": self.structure_type,
            "structure_name": self.structure_name,
            "source_lines": self.source_lines if isinstance(self.source_lines, list) else []
        }
        return result


@dataclass
class ReferencedStructure:
    """Referenced structure in configuration"""
    structure_type: str
    structure_name: str
    context: str
    source_lines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = {
            "structure_type": self.structure_type,
            "structure_name": self.structure_name,
            "context": self.context,
            "source_lines": self.source_lines if isinstance(self.source_lines, list) else []
        }
        return result


@dataclass
class NamedStructure:
    """Named structure with full definition"""
    node: str
    structure_type: str
    structure_name: str
    structure_definition: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)