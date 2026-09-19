import httpx
from app.core.config import settings


class EPSSService:
    """
    Fetches real-world exploit probability scores from the
    FIRST.org Exploit Prediction Scoring System (EPSS) API.
    """

    def __init__(self):
        self.base_url = settings.epss_api_url
        self.timeout = settings.epss_request_timeout

    async def get_score(self, cve_id: str) -> float:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(self.base_url, params={"cve": cve_id})
            response.raise_for_status()
            data = response.json()
            if data.get("data"):
                return float(data["data"][0]["epss"])
            return 0.0

    async def get_scores_bulk(self, cve_ids: list[str]) -> dict[str, float]:
        results = {}
        for cve_id in cve_ids:
            results[cve_id] = await self.get_score(cve_id)
        return results