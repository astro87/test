import unittest
from backend.graph import DependencyGraph

class TestDependencyGraph(unittest.TestCase):
    def test_build_and_metrics(self):
        graph = DependencyGraph()
        
        components = [
            {"bom-ref": "root", "name": "root-app", "version": "1.0"},
            {"bom-ref": "lib-a", "name": "lib-a", "version": "1.0"},
            {"bom-ref": "lib-b", "name": "lib-b", "version": "1.0"},
            {"bom-ref": "lib-c", "name": "lib-c", "version": "1.0"}
        ]
        
        dependencies = [
            {"ref": "root", "dependsOn": ["lib-a"]},
            {"ref": "lib-a", "dependsOn": ["lib-b"]},
            {"ref": "lib-b", "dependsOn": ["lib-c"]}
        ]
        
        graph.build(components, dependencies)
        
        # Test Depth
        depths = graph.calculate_depth("root")
        self.assertEqual(depths["root"], 0)
        self.assertEqual(depths["lib-a"], 1)
        self.assertEqual(depths["lib-c"], 3)
        
        # Test Transitive
        transitive = graph.get_transitive_dependencies("root")
        self.assertEqual(len(transitive), 3)
        self.assertIn("lib-c", transitive)
        
        # Test Critical Path (Centrality)
        # lib-a and lib-b have degree 2 (1 in, 1 out), root and lib-c have 1.
        critical = graph.get_critical_path()
        self.assertIn("lib-a", critical)

if __name__ == '__main__':
    unittest.main()
