from pydantic import BaseModel
from enum import Enum


class PrivilegeLevel(str, Enum):
    domain_admin = "domain_admin"
    service_account = "service_account"
    standard = "standard"


class Identity(BaseModel):
    username: str
    privilege_level: PrivilegeLevel
    mfa_enabled: bool
    last_login_days_ago: int
    owned_asset_ip: str