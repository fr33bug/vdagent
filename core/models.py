from dataclasses import dataclass
from enum import Enum
from typing import Optional


class BinaryFormat(Enum):
    """Supported binary formats."""
    ELF = "elf"
    PE = "pe"  # .exe, .dll
    MACHO = "macho"
    UNKNOWN = "unknown"


@dataclass
class FunctionInfo:
    """Information about a decompiled function."""
    name: str
    address: str
    pseudocode: str
    size: int
    complexity: Optional[float] = None


@dataclass
class VulnerabilityFinding:
    """Vulnerability finding from analysis."""
    function_name: str
    address: str
    vulnerability_type: str
    confidence: float  # 0.0 to 1.0
    description: str
    pseudocode_snippet: str
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None