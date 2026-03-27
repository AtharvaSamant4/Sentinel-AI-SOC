from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: Literal["TCP", "UDP", "HTTP", "SSH"]
    event_type: Literal["login", "request", "connection"]
    username: Optional[str] = None
    status: Literal["success", "failure"]
    bytes_transferred: int = Field(ge=0)
    country: str
    is_attack: bool

    def as_dict(self) -> dict:
        return self.model_dump()
