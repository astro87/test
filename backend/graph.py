import networkx as nx
from typing import List, Dict, Any, Set

class DependencyGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build(self, components: List[Dict[str, Any]], dependencies: List[Dict[str, Any]]):
        """
        Builds the dependency graph from components and dependencies.
        """
        # Add nodes
        for comp in components:
            # Use bom-ref or purl as node ID, fallback to name-version
            node_id = comp.get('bom-ref') or comp.get('purl') or f"{comp.get('name')}@{comp.get('version')}"
            self.graph.add_node(node_id, **comp)

        # Add edges
        for dep in dependencies:
            parent = dep.get('ref')
            if not parent:
                continue
            
            for child in dep.get('dependsOn', []):
                self.graph.add_edge(parent, child)

    def calculate_depth(self, root_node: str) -> Dict[str, int]:
        """
        Calculates the depth of each dependency from the root node.
        """
        try:
            return nx.shortest_path_length(self.graph, source=root_node)
        except nx.NetworkXNoPath:
            return {root_node: 0}
        except nx.NodeNotFound:
            return {}

    def get_critical_path(self) -> List[str]:
        """
        Identifies critical path components (e.g., most connected, or deepest).
        For now, we return nodes with high degree centrality (hubs).
        """
        if self.graph.number_of_nodes() == 0:
            return []
        centrality = nx.degree_centrality(self.graph)
        # Return top 10% or top 5 nodes
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return [node for node, score in sorted_nodes[:5]]

    def get_transitive_dependencies(self, node_id: str) -> Set[str]:
        """
        Returns all transitive dependencies for a given node.
        """
        try:
            return nx.descendants(self.graph, node_id)
        except nx.NetworkXError:
            return set()
