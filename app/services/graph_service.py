import networkx as nx
from app.models.identity import Identity, PrivilegeLevel


class GraphRiskService:
    """
    Builds an attack graph from identity data and computes
    graph-theoretic risk metrics: shortest path to Domain Admin
    and betweenness centrality (structural chokepoint risk).
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph(self, identities: list[Identity]):
        self.graph = nx.DiGraph()
        self.graph.add_node("DOMAIN_ADMIN")

        host_to_privileged = {}
        for identity in identities:
            if identity.privilege_level in (PrivilegeLevel.domain_admin, PrivilegeLevel.service_account):
                host_to_privileged.setdefault(identity.owned_asset_ip, []).append(identity.username)

        for identity in identities:
            if identity.privilege_level in (PrivilegeLevel.domain_admin, PrivilegeLevel.service_account):
                self.graph.add_edge(identity.username, identity.owned_asset_ip)
                self.graph.add_edge(identity.owned_asset_ip, "DOMAIN_ADMIN")

        for identity in identities:
            if (identity.privilege_level == PrivilegeLevel.standard
                    and not identity.mfa_enabled
                    and identity.owned_asset_ip in host_to_privileged):
                for privileged_user in host_to_privileged[identity.owned_asset_ip]:
                    self.graph.add_edge(identity.username, privileged_user)

    def get_attack_path(self, username: str):
        try:
            path = nx.shortest_path(self.graph, source=username, target="DOMAIN_ADMIN")
            return {"path": path, "hops": len(path) - 1}
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return {"path": None, "hops": None}

    def get_centrality(self, username: str) -> float:
        centrality = nx.betweenness_centrality(self.graph)
        return round(centrality.get(username, 0.0), 3)

    def analyze(self, identities: list[Identity]):
        self.build_graph(identities)
        results = []
        for identity in identities:
            path_info = self.get_attack_path(identity.username)
            centrality = self.get_centrality(identity.username)
            proximity_score = round(1 / path_info["hops"], 3) if path_info["hops"] else 0.0

            results.append({
                "username": identity.username,
                "hops_to_domain_admin": path_info["hops"],
                "attack_path": path_info["path"],
                "graph_proximity_score": proximity_score,
                "betweenness_centrality": centrality
            })
        return results