"""Value objects used across the domain."""
from dataclasses import dataclass


@dataclass(frozen=True)
class RiskScore:
    value: float  # 0.0 to 10.0

    def __post_init__(self):
        if not (0.0 <= self.value <= 10.0):
            raise ValueError("Risk score must be between 0.0 and 10.0")