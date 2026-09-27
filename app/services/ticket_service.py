from datetime import datetime
from app.models.finding import UnifiedFinding
from app.models.ticket import Ticket, Severity
from app.core.config import settings
from uuid import uuid4

class TicketService:
    """
    Generates structured incident tickets for findings above
    the configured risk threshold, with attack path evidence
    and recommended remediation actions.
    """

    def _get_severity(self, score: float) -> Severity:
        if score >= settings.risk_threshold_critical:
            return Severity.critical
        elif score >= settings.risk_threshold_high:
            return Severity.high
        return Severity.medium

    def _recommend_actions(self, finding: UnifiedFinding) -> list[str]:
        actions = []
        if finding.hops_to_domain_admin is not None and finding.hops_to_domain_admin <= 2:
            actions.append("Enforce MFA immediately on this account")
        if finding.hops_to_domain_admin is not None and finding.hops_to_domain_admin >= 3:
            actions.append("Review lateral movement path; rotate credentials for all accounts in the chain")
        actions.append(f"Patch {finding.cve_id} on host {finding.host}")
        return actions

    def generate_tickets(self, findings: list[UnifiedFinding]) -> list[Ticket]:
        tickets = []
        for i, finding in enumerate(findings):
            if finding.unified_risk_score < settings.risk_threshold_high:
                continue

            severity = self._get_severity(finding.unified_risk_score)
            ticket = Ticket(
                ticket_id=f"XENTRA-{datetime.now().strftime('%Y%m%d%H%M%S')}-{i+1}-{uuid4().hex[:6]}",
                title=f"{severity.value} Risk: {finding.cve_id} on account '{finding.owner}'",
                severity=severity,
                cve_id=finding.cve_id,
                host=finding.host,
                owner=finding.owner,
                epss_score=finding.epss_score,
                identity_exposure_score=finding.identity_exposure_score,
                unified_risk_score=finding.unified_risk_score,
                attack_path=finding.attack_path,
                hops_to_domain_admin=finding.hops_to_domain_admin,
                recommended_actions=self._recommend_actions(finding),
                created_at=datetime.now().isoformat()
            )
            tickets.append(ticket)
        return tickets