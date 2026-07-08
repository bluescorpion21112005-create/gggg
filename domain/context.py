"""Kontekst – agentlar o‘rtasida uzatiladigan ma’lumotlar."""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class AnalysisContext:
    # IOC tahlil natijalari
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    ioc_result: Optional[Dict[str, Any]] = None

    # Log tahlil natijalari
    log_file_path: Optional[str] = None
    log_entries: Optional[List[Dict[str, Any]]] = None
    log_threats: Optional[Dict[str, int]] = None

    # Threat Hunting natijalari
    hunting_query: Optional[str] = None
    hunting_result: Optional[str] = None

    # Yakuniy hisobot
    report_path: Optional[str] = None

    # Qo‘shimcha xabar yoki xatoliklar
    messages: List[str] = field(default_factory=list)
    error: Optional[str] = None