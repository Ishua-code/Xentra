import logging

import httpx

from app.core.config import settings
from app.models.ticket import Ticket

logger = logging.getLogger(__name__)


class TheHiveClient:
    """
    Pushes generated tickets to TheHive as cases.

    When settings.thehive_enabled is False (default), push_case() logs
    the would-be case locally instead of making a real HTTP call. Flipping
    the flag to True (once a TheHive instance is available) makes this
    POST to the real TheHive API without changing any calling code.
    """

    def __init__(self):
        self.enabled = settings.thehive_enabled
        self.base_url = settings.thehive_api_url
        self.api_key = settings.thehive_api_key
        self.timeout = settings.thehive_request_timeout

    async def push_case(self, ticket: Ticket) -> dict:
        payload = {
            "title": ticket.title,
            "description": f"CVE {ticket.cve_id} on host {ticket.host}, owner {ticket.owner}",
            "severity": self._map_severity(ticket.severity),
            "tags": ["xentra", ticket.cve_id, ticket.owner],
            "sourceRef": ticket.ticket_id,
        }

        if not self.enabled:
            logger.info("TheHive disabled — mock case created: %s", payload)
            return {"status": "mocked", "case": payload}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/case",
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            response.raise_for_status()
            return response.json()

    @staticmethod
    def _map_severity(severity) -> int:
        mapping = {"Critical": 4, "High": 3, "Medium": 2}
        value = severity.value if hasattr(severity, "value") else severity
        return mapping.get(value, 1)