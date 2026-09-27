import respx
from httpx import Response
from fastapi.testclient import TestClient

from app.main import app
from app.services.identity_service import IdentityService
from app.services.graph_service import GraphRiskService
from app.models.identity import Identity, PrivilegeLevel

client = TestClient(app)


def make_identity(username, privilege, mfa, last_login, ip):
    return Identity(
        username=username,
        privilege_level=privilege,
        mfa_enabled=mfa,
        last_login_days_ago=last_login,
        owned_asset_ip=ip,
    )


@respx.mock
def test_correlate_fuses_epss_and_identity_risk():
    respx.get("https://api.first.org/data/v1/epss").mock(
        return_value=Response(200, json={"data": [{"epss": "0.97"}]})
    )

    identity = make_identity(
        "admin_john", PrivilegeLevel.domain_admin, False, 2, "192.168.1.10"
    )

    payload = {
        "vulnerabilities": [
            {"cve_id": "CVE-2021-44228", "host": "192.168.1.10", "cvss_score": 10.0}
        ],
        "identities": [identity.model_dump(mode="json")],
    }

    response = client.post("/api/v1/correlate", json=payload)
    assert response.status_code == 200

    findings = response.json()["findings"]
    assert len(findings) == 1
    finding = findings[0]

    graph_service = GraphRiskService()
    identity_service = IdentityService()
    graph_result = graph_service.analyze([identity])[0]
    rule_based_score = identity_service.calculate_score(identity)

    expected_identity_score = round(
        (graph_result["graph_proximity_score"] * 0.6)
        + (rule_based_score * 0.3)
        + (graph_result["betweenness_centrality"] * 0.1),
        3,
    )
    expected_unified_score = round((0.97 * 0.5) + (expected_identity_score * 0.5), 3)

    assert finding["owner"] == "admin_john"
    assert finding["epss_score"] == 0.97
    assert finding["identity_exposure_score"] == expected_identity_score
    assert finding["unified_risk_score"] == expected_unified_score
    assert finding["hops_to_domain_admin"] == graph_result["hops_to_domain_admin"]
    tickets = response.json()["tickets"]
    assert len(tickets) == 1
    assert tickets[0]["cve_id"] == "CVE-2021-44228"


@respx.mock
def test_correlate_unmatched_host_falls_back_to_unknown_owner():
    respx.get("https://api.first.org/data/v1/epss").mock(
        return_value=Response(200, json={"data": [{"epss": "0.5"}]})
    )

    identity = make_identity("safe_user", PrivilegeLevel.standard, True, 1, "10.0.0.5")

    payload = {
        "vulnerabilities": [
            {"cve_id": "CVE-2024-0001", "host": "10.0.0.99", "cvss_score": 7.0}
        ],
        "identities": [identity.model_dump(mode="json")],
    }

    response = client.post("/api/v1/correlate", json=payload)
    assert response.status_code == 200

    finding = response.json()["findings"][0]
    assert finding["owner"] == "unknown"
    assert finding["identity_exposure_score"] == 0.0
    assert finding["hops_to_domain_admin"] is None
    assert finding["unified_risk_score"] == 0.25


@respx.mock
def test_correlate_sorts_findings_by_unified_risk_score_descending():
    respx.get("https://api.first.org/data/v1/epss").mock(
        return_value=Response(200, json={"data": [{"epss": "0.5"}]})
    )

    admin = make_identity("admin_john", PrivilegeLevel.domain_admin, False, 2, "10.0.0.1")
    standard = make_identity("safe_user", PrivilegeLevel.standard, True, 1, "10.0.0.5")

    payload = {
        "vulnerabilities": [
            {"cve_id": "CVE-A", "host": "10.0.0.5", "cvss_score": 5.0},
            {"cve_id": "CVE-B", "host": "10.0.0.1", "cvss_score": 5.0},
        ],
        "identities": [admin.model_dump(mode="json"), standard.model_dump(mode="json")],
    }

    response = client.post("/api/v1/correlate", json=payload)
    findings = response.json()["findings"]

    assert len(findings) == 2
    assert findings[0]["unified_risk_score"] >= findings[1]["unified_risk_score"]
    assert findings[0]["owner"] == "admin_john"
    tickets = response.json()["tickets"]
    assert len(tickets) == 1
    assert tickets[0]["cve_id"] == "CVE-B"

@respx.mock
def test_correlate_persists_ticket_to_database():
    respx.get("https://api.first.org/data/v1/epss").mock(
        return_value=Response(200, json={"data": [{"epss": "0.97"}]})
    )

    identity = make_identity(
        "admin_persist", PrivilegeLevel.domain_admin, False, 2, "192.168.1.50"
    )
    payload = {
        "vulnerabilities": [
            {"cve_id": "CVE-2021-44228", "host": "192.168.1.50", "cvss_score": 10.0}
        ],
        "identities": [identity.model_dump(mode="json")],
    }

    response = client.post("/api/v1/correlate", json=payload)
    assert response.status_code == 200
    returned = response.json()["tickets"]
    assert len(returned) == 1
    ticket_id = returned[0]["ticket_id"]

    # Fetched via a fresh request/session, so it must have been committed
    fetched = client.get(f"/api/v1/tickets/{ticket_id}")
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["cve_id"] == "CVE-2021-44228"
    assert body["owner"] == "admin_persist"
    assert body["host"] == "192.168.1.50"

    listed = client.get("/api/v1/tickets", params={"owner": "admin_persist"})
    assert listed.status_code == 200
    assert ticket_id in [t["ticket_id"] for t in listed.json()]