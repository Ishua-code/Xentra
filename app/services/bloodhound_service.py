import json
from pathlib import Path

from app.core.config import settings
from app.models.identity import Identity, PrivilegeLevel


class BloodHoundClient:
    """
    Imports BloodHound Active Directory attack-path data.

    When settings.bloodhound_enabled is False (default), this client reads
    a local sample export instead of talking to a live BloodHound instance.
    Flipping the flag to True (once BloodHound CE is available) would make
    this pull from a real export file path or the BloodHound API without
    changing any calling code.
    """

    def __init__(self):
        self.enabled = settings.bloodhound_enabled
        self.export_path = settings.bloodhound_mock_export_path

    def import_export(self, file_path: str | None = None) -> list[Identity]:
        path = Path(file_path or self.export_path)

        if not path.exists():
            raise FileNotFoundError(f"BloodHound export not found: {path}")

        with open(path, "r") as f:
            data = json.load(f)

        identities = []
        for node in data.get("nodes", []):
            if node.get("type") != "User":
                continue
            identities.append(
                Identity(
                    username=node["username"],
                    privilege_level=PrivilegeLevel(node["privilege_level"]),
                    mfa_enabled=node.get("mfa_enabled", False),
                    last_login_days_ago=node.get("last_login_days_ago", 0),
                    owned_asset_ip=node.get("owned_asset_ip", ""),
                )
            )
        return identities

    def get_edges(self, file_path: str | None = None) -> list[dict]:
        path = Path(file_path or self.export_path)
        with open(path, "r") as f:
            data = json.load(f)
        return data.get("edges", [])