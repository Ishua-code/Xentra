import pytest
import respx
from httpx import Response
from app.services.epss_service import EPSSService


@pytest.mark.asyncio
@respx.mock
async def test_get_score_returns_correct_value():
    respx.get("https://api.first.org/data/v1/epss").mock(
        return_value=Response(200, json={"data": [{"epss": "0.975"}]})
    )
    service = EPSSService()
    score = await service.get_score("CVE-TEST-0001")
    assert score == 0.975


@pytest.mark.asyncio
@respx.mock
async def test_get_score_returns_zero_when_no_data():
    respx.get("https://api.first.org/data/v1/epss").mock(
        return_value=Response(200, json={"data": []})
    )
    service = EPSSService()
    score = await service.get_score("CVE-UNKNOWN")
    assert score == 0.0