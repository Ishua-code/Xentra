import json

import pytest

from app.services.bloodhound_service import BloodHoundClient
from app.models.identity import PrivilegeLevel


@pytest.fixture
def sample_export(tmp_path):
    data = {
        "nodes": [
            {"username": "admin_john", "type": "User", "privilege_level": "domain_admin", "owned_asset_ip": "192.168.1.10"},
            {"username": "not_a_user", "type": "Computer", "privilege_level": "standard", "owned_asset_ip": "192.168.1.99"},
        ],
        "edges": [
            {"source": "admin_john", "target": "not_a_user", "relationship": "AdminTo"},
        ],
    }
    file_path = tmp_path / "export.json"
    file_path.write_text(json.dumps(data))
    return str(file_path)


def test_import_export_parses_user_nodes_only(sample_export):
    client = BloodHoundClient()
    identities = client.import_export(sample_export)

    assert len(identities) == 1
    assert identities[0].username == "admin_john"
    assert identities[0].privilege_level == PrivilegeLevel.domain_admin


def test_get_edges_returns_relationships(sample_export):
    client = BloodHoundClient()
    edges = client.get_edges(sample_export)

    assert len(edges) == 1
    assert edges[0]["relationship"] == "AdminTo"


def test_import_export_missing_file_raises():
    client = BloodHoundClient()
    with pytest.raises(FileNotFoundError):
        client.import_export("nonexistent/path.json")