import asyncio

import pytest
from fastapi.testclient import TestClient

from app.db.repository import TicketRepository
from app.main import app
from app.models.ticket import Ticket


def make_ticket(ticket_id="XENTRA-1", severity="High", owner="alice", status="Open"):
    return Ticket(
        ticket_id=ticket_id,
        title="High Risk: CVE-2024-0001 on account 'alice'",
        severity=severity,
        cve_id="CVE-2024-0001",
        host="srv-01",
        owner=owner,
        epss_score=0.8,
        identity_exposure_score=0.7,
        unified_risk_score=0.75,
        attack_path=None,
        hops_to_domain_admin=2,
        recommended_actions=["Patch CVE-2024-0001 on host srv-01"],
        status=status,
        created_at="2026-09-24T12:00:00",
    )


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seed(session_factory):
    def _seed(*tickets):
        async def run():
            async with session_factory() as session:
                await TicketRepository(session).save_many(tickets)
        asyncio.run(run())
    return _seed


def test_list_and_filter(client, seed):
    seed(make_ticket("T1"), make_ticket("T2", severity="Critical", owner="bob"))
    assert len(client.get("/api/v1/tickets").json()) == 2
    critical = client.get("/api/v1/tickets", params={"severity": "Critical"}).json()
    assert [t["ticket_id"] for t in critical] == ["T2"]
    assert len(client.get("/api/v1/tickets", params={"owner": "alice"}).json()) == 1


def test_get_ticket_and_404(client, seed):
    seed(make_ticket("T1"))
    resp = client.get("/api/v1/tickets/T1")
    assert resp.status_code == 200
    assert resp.json()["attack_path"] == []
    assert client.get("/api/v1/tickets/NOPE").status_code == 404


def test_update_status(client, seed):
    seed(make_ticket("T1"))
    resp = client.patch("/api/v1/tickets/T1/status", json={"status": "Resolved"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "Resolved"
    assert client.get("/api/v1/tickets/T1").json()["status"] == "Resolved"


def test_update_status_invalid_and_missing(client, seed):
    seed(make_ticket("T1"))
    assert client.patch("/api/v1/tickets/T1/status", json={"status": "Bogus"}).status_code == 422
    assert client.patch("/api/v1/tickets/NOPE/status", json={"status": "Closed"}).status_code == 404