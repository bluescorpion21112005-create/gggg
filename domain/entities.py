"""Domain entities that represent core business objects."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AnalysisResult:
    id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict = field(default_factory=dict)