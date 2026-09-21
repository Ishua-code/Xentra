from app.services.graph_service import GraphRiskService
from app.models.identity import Identity, PrivilegeLevel


def test_domain_admin_has_two_hops():
    service = GraphRiskService()
    identities = [
        Identity(username="admin", privilege_level=PrivilegeLevel.domain_admin,
                  mfa_enabled=False, last_login_days_ago=1, owned_asset_ip="10.0.0.1")
    ]
    results = service.analyze(identities)
    assert results[0]["hops_to_domain_admin"] == 2


def test_isolated_standard_user_is_unreachable():
    service = GraphRiskService()
    identities = [
        Identity(username="safe_user", privilege_level=PrivilegeLevel.standard,
                  mfa_enabled=True, last_login_days_ago=1, owned_asset_ip="10.0.0.5")
    ]
    results = service.analyze(identities)
    assert results[0]["hops_to_domain_admin"] is None


def test_weak_user_pivots_through_admin():
    service = GraphRiskService()
    identities = [
        Identity(username="admin", privilege_level=PrivilegeLevel.domain_admin,
                  mfa_enabled=False, last_login_days_ago=1, owned_asset_ip="10.0.0.1"),
        Identity(username="weak_user", privilege_level=PrivilegeLevel.standard,
                  mfa_enabled=False, last_login_days_ago=1, owned_asset_ip="10.0.0.1")
    ]
    results = service.analyze(identities)
    weak_result = next(r for r in results if r["username"] == "weak_user")
    assert weak_result["hops_to_domain_admin"] == 3