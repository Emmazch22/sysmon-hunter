from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_SCORE = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 5,
    Severity.HIGH: 8,
    Severity.CRITICAL: 10,
}


class Event(BaseModel):
    """Evento Sysmon normalizado, agnostico del transporte."""

    event_id: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    host: str = "unknown"
    user: Optional[str] = None

    # identidad de proceso (clave para el correlador de la fase 2)
    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    process_id: Optional[int] = None

    image: Optional[str] = None
    parent_image: Optional[str] = None
    command_line: Optional[str] = None
    parent_command_line: Optional[str] = None

    # campos crudos: cualquier cosa que Sysmon mande y no hayamos mapeado
    raw: dict[str, Any] = Field(default_factory=dict)

    def get(self, field: str) -> Any:
        """Acceso unificado: primero campos normalizados, luego raw."""
        if hasattr(self, field):
            return getattr(self, field)
        return self.raw.get(field)


class Detection(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    attack: list[str] = Field(default_factory=list)
    event: Event
    matched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def score(self) -> int:
        return SEVERITY_SCORE[self.severity]


class Rule(BaseModel):
    id: str
    title: str
    event_id: int
    severity: Severity = Severity.MEDIUM
    attack: list[str] = Field(default_factory=list)
    description: str = ""
    detection: dict[str, Any]
    condition: str = "all"  # all | any
    enabled: bool = True