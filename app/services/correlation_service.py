from app.models.vulnerability import Vulnerability
from app.models.identity import Identity
from app.models.finding import UnifiedFinding
from app.services.epss_service import EPSSService
from app.services.identity_service import IdentityService
from app.services.graph_service import GraphRiskService


class CorrelationService:
    """
    Fuses vulnerability exploitability (EPSS) with identity risk
    (rule-based + graph-based) into a single Unified Risk Score.
    """

    def __init__(self):
        self.epss_service = EPSSService()
        self.identity_service = IdentityService()
        self.graph_service = GraphRiskService()

    async def correlate(
        self,
        vulnerabilities: list[Vulnerability],
        identities: list[Identity]
    ) -> list[UnifiedFinding]:

        identity_by_host = {i.owned_asset_ip: i for i in identities}
        graph_results = self.graph_service.analyze(identities)
        graph_by_username = {r["username"]: r for r in graph_results}

        findings = []
        for vuln in vulnerabilities:
            identity = identity_by_host.get(vuln.host)
            epss_score = await self.epss_service.get_score(vuln.cve_id)

            if identity:
                rule_based_score = self.identity_service.calculate_score(identity)
                graph_info = graph_by_username.get(identity.username, {})
                graph_proximity = graph_info.get("graph_proximity_score", 0.0)
                centrality = graph_info.get("betweenness_centrality", 0.0)

                identity_score = round(
                    (graph_proximity * 0.6) + (rule_based_score * 0.3) + (centrality * 0.1), 3
                )
                owner = identity.username
                hops = graph_info.get("hops_to_domain_admin")
                path = graph_info.get("attack_path")
            else:
                identity_score = 0.0
                graph_proximity = 0.0
                centrality = 0.0
                owner = "unknown"
                hops = None
                path = None

            unified_score = round((epss_score * 0.5) + (identity_score * 0.5), 3)

            findings.append(UnifiedFinding(
                cve_id=vuln.cve_id,
                host=vuln.host,
                owner=owner,
                epss_score=epss_score,
                identity_exposure_score=identity_score,
                graph_proximity_score=graph_proximity,
                betweenness_centrality=centrality,
                unified_risk_score=unified_score,
                hops_to_domain_admin=hops,
                attack_path=path
            ))

        findings.sort(key=lambda f: f.unified_risk_score, reverse=True)
        return findings