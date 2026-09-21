from pydantic import BaseModel
from typing import Optional
from enum import Enum
from datetime import datetime


class Severity(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"


class Ticket(BaseModel):
    ticket_id: str
    title: str
    severity: Severity
    cve_id: str
    host: str
    owner: str
    epss_score: float
    identity_exposure_score: float
    unified_risk_score: float
    attack_path: Optional[list[str]] = None
    hops_to_domain_admin: Optional[int] = None
    recommended_actions: list[str]
    status: str = "Open"
    created_at: str