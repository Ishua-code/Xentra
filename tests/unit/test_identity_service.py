from app.services.identity_service import IdentityService
from app.models.identity import Identity, PrivilegeLevel


def make_identity(privilege, mfa, last_login):
    return Identity(
        username="test_user",
        privilege_level=privilege,
        mfa_enabled=mfa,
        last_login_days_ago=last_login,
        owned_asset_ip="10.0.0.1"
    )


def test_domain_admin_no_mfa_is_high_risk():
    service = IdentityService()
    identity = make_identity(PrivilegeLevel.domain_admin, False, 5)
    score = service.calculate_score(identity)
    assert score >= 0.8


def test_standard_user_with_mfa_is_low_risk():
    service = IdentityService()
    identity = make_identity(PrivilegeLevel.standard, True, 5)
    score = service.calculate_score(identity)
    assert score <= 0.2


def test_stale_account_increases_score():
    service = IdentityService()
    fresh = service.calculate_score(make_identity(PrivilegeLevel.standard, True, 5))
    stale = service.calculate_score(make_identity(PrivilegeLevel.standard, True, 90))
    assert stale > fresh


def test_score_never_exceeds_one():
    service = IdentityService()
    identity = make_identity(PrivilegeLevel.domain_admin, False, 999)
    score = service.calculate_score(identity)
    assert score <= 1.0