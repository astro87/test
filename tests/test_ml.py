import unittest
from backend.ml import RiskModel

class TestRiskModel(unittest.TestCase):
    def test_risk_prediction(self):
        model = RiskModel()
        
        # Test Case 1: High severity, deep dependency
        # Features: [Base=9.0, Depth=3, Exploit=1.0, Transitive=0]
        # New Weights: [1.0, 0.1, 5.0, 0.05]
        # Score = 9.0*1.0 + 3*0.1 + 1.0*5.0 + 0 = 9 + 0.3 + 5 = 14.3
        features = [9.0, 3, 1.0, 0]
        score = model.predict_risk(features)
        self.assertAlmostEqual(score, 14.3)
        
        # Test Case 2: No vulns
        features = [0.0, 1, 0.0, 0]
        score = model.predict_risk(features)
        self.assertEqual(score, 0.1) # Just depth penalty
        
    def test_batch_predict(self):
        model = RiskModel()
        components = [
            {"bom-ref": "c1", "vulnerabilities": [{"cvss": 5.0}]},
            {"bom-ref": "c2"} # No vulns
        ]
        depths = {"c1": 2, "c2": 1}
        
        results = model.batch_predict(components, depths)
        
        # c1 Exploit Maturity: Base=5.0 -> Maturity=1.0
        # Score = 5.0*1 + 2*0.1 + 1.0*5 + 0 = 5 + 0.2 + 5 = 10.2
        self.assertEqual(results[0]['ml_risk_score'], 10.2)
        
        # c2: 0 + 1*0.1 + 0 + 0 = 0.1
        self.assertEqual(results[1]['ml_risk_score'], 0.1)

if __name__ == '__main__':
    unittest.main()
