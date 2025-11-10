"""
Reachability and flow analysis data models (dataclasses)
- FlowTrace: Flow trace information with traces list
- ReachabilityTrace: Detailed path trace from source to destination
- Includes flow definition, hops, status, and disposition
- Maps to Batfish reachability and traceroute query results
- Safe serialization of Batfish FileLines objects
"""
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class FlowTrace:
    """Flow trace information"""
    flow: str
    traces: list[Any] = field(default_factory=list)
    trace_count: int = 0

    def to_dict(self) -> dict:
        # Safely convert traces
        safe_traces = []
        for trace in self.traces:
            if hasattr(trace, '__class__') and 'FileLines' in str(trace.__class__):
                safe_traces.append(str(trace))
            else:
                safe_traces.append(trace)

        return {
            "flow": self.flow,
            "traces": safe_traces,
            "trace_count": self.trace_count
        }


@dataclass
class ReachabilityTrace:
    """Reachability trace with detailed path"""
    source_node: str
    destination_node: str
    flow: str
    hops: list[dict[str, Any]] = field(default_factory=list)
    status: str = "UNKNOWN"
    disposition: str = ""

    def to_dict(self) -> dict:
        return asdict(self)