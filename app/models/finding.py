from pydantic import BaseModel
from typing import Optional


class UnifiedFinding(BaseModel):
    cve_id: str
    host: str
    owner: str
    epss_score: float
    identity_exposure_score: float
    graph_proximity_score: float
    betweenness_centrality: float
    unified_risk_score: float
    hops_to_domain_admin: Optional[int] = None
    attack_path: Optional[list[str]] = None