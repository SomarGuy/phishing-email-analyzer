from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    """One raw detection from an analysis step. Weight, severity and ATT&CK come from the configuration."""
    id: str
    detail: str
    evidence: List[str] = field(default_factory=list)
