import unittest
from backend.reasoning import ReasoningEngine

class TestReasoningEngine(unittest.TestCase):
    def test_reasoning_rules(self):
        engine = ReasoningEngine()
        
        # Component with ML score 8.0, Depth 1 (Near root)
        comp1 = {
            "bom-ref": "c1",
            "ml_risk_score": 8.0,
            "ml_features": [8.0, 1, 0.0, 0],
            "vulnerabilities": [{"severity": "HIGH"}]
        }
        
        # Component with Critical Vuln but low ML score (maybe due to depth)
        comp2 = {
            "bom-ref": "c2",
            "ml_risk_score": 4.0,
            "ml_features": [4.0, 5, 0.0, 0],
            "vulnerabilities": [{"severity": "CRITICAL"}]
        }
        
        results = engine.analyze([comp1, comp2], None)
        
        # Check c1: 8.0 * 1.2 = 9.6 due to Depth < 2 rule
        self.assertEqual(results[0]['final_risk_score'], 9.6)
        self.assertIn("High risk component near root", results[0]['risk_reasons'][0])
        
        # Check c2: Boosted to at least 9.0 due to Critical Rule
        self.assertTrue(results[1]['final_risk_score'] >= 9.0)
        self.assertIn("Contains CRITICAL vulnerability", results[1]['risk_reasons'][0])

if __name__ == '__main__':
    unittest.main()
