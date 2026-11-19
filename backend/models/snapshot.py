"""Network configuration snapshot data models (dataclasses)"""
from dataclasses import dataclass


@dataclass
class Snapshot:
    """Network configuration snapshot"""
    name: str
    path: str
    file_count: int
    created_at: str
    size_bytes: int


@dataclass
class SnapshotFile:
    """Configuration file in a snapshot"""
    name: str
    size_bytes: int
    modified_at: str