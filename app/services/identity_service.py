from app.models.identity import Identity, PrivilegeLevel
from app.core.config import settings


class IdentityService:
    """
    Calculates a rule-based identity exposure score based on
    privilege level, MFA status, and account activity.
    """

    def calculate_score(self, identity: Identity) -> float:
        score = 0.0

        if identity.privilege_level == PrivilegeLevel.domain_admin:
            score += 0.4
        elif identity.privilege_level == PrivilegeLevel.service_account:
            score += 0.3
        else:
            score += 0.1

        if not identity.mfa_enabled:
            score += 0.4

        if identity.last_login_days_ago > 30:
            score += 0.2

        return round(min(score, 1.0), 3)