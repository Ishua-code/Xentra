import pytest
import respx
from httpx import Response

from app.services.thehive_service import TheHiveClient
from app.models.ticket import Ticket, Severity


def make_ticket(**overrides):
    defaults = dict(
        ticket_id="XENTRA-TEST-1",
        title="High Risk: CVE-2021-44228 on account 'admin_john'",
        severity=Severity.high,
        cve_id="CVE-2021-44228",
        host="192.168.1.10",
        owner="admin_john",
        epss_score=0.97,
        identity_exposure_score=0.54,
        unified_risk_score=0.77,
        recommended_actions=["Rotate credentials", "Enable MFA"],
        created_at="2026-09-25T00:00:00",
    )
    defaults.update(overrides)
    return Ticket(**defaults)


@pytest.mark.asyncio
async def test_push_case_mocked_when_disabled():
    client = TheHiveClient()
    client.enabled = False

    result = await client.push_case(make_ticket())

    assert result["status"] == "mocked"
    assert result["case"]["sourceRef"] == "XENTRA-TEST-1"


@pytest.mark.asyncio
@respx.mock
async def test_push_case_calls_api_when_enabled():
    client = TheHiveClient()
    client.enabled = True
    client.base_url = "http://fake-thehive:9000/api/v1"
    client.api_key = "test-key"

    route = respx.post("http://fake-thehive:9000/api/v1/case").mock(
        return_value=Response(200, json={"id": "case-123"})
    )

    result = await client.push_case(make_ticket())

    assert route.called
    assert result["id"] == "case-123"


def test_map_severity():
    assert TheHiveClient._map_severity(Severity.critical) == 4
    assert TheHiveClient._map_severity(Severity.high) == 3
    assert TheHiveClient._map_severity(Severity.medium) == 2