from typing import Dict, Any, List
import numpy as np

# In a real scenario, we would use:
# from sklearn.ensemble import RandomForestClassifier
# import joblib

class RiskModel:
    """
    Lightweight ML model for risk amplification.
    Uses pre-defined weights or a loaded sklearn model.
    """
    def __init__(self):
        # Mocking a trained model for "Startup/Research" feel
        # Features: [base_score, depth, exploit_maturity_score, dependency_count]
        # We manually define weights to simulate an interpretable linear model or decision tree logic
        self.weights = np.array([1.0, 0.1, 5.0, 0.05])
        self.bias = 0.0

    def predict_risk(self, features: List[float]) -> float:
        """
        Predicts risk score (0-100) based on feature vector.
        """
        score = np.dot(np.array(features), self.weights) + self.bias
        return min(100.0, max(0.0, score))

    def batch_predict(self, components: List[Dict[str, Any]], depths: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Augments components with ML-derived risk scores.
        """
        for comp in components:
            vulns = comp.get('vulnerabilities', [])
            
            # --- ML Scoring Phase ---
            # 1. Base Score
            # Use max CVSS score from vulnerabilities
            base_score = max([v.get('cvss', 0) for v in vulns]) if vulns else 0.0
            
            # 2. Depth
            node_id = comp.get('bom-ref') or comp.get('purl')
            depth = depths.get(node_id, 0)
            
            # 3. Exploit Maturity (Mocked)
            exploit_maturity = 0.0
            if base_score >= 9.0: exploit_maturity = 3.0
            elif base_score >= 7.0: exploit_maturity = 2.0
            elif base_score > 0: exploit_maturity = 1.0
            
            transitive_count = 0 
            
            features = [base_score, depth, exploit_maturity, transitive_count]
            ml_score = self.predict_risk(features)
            
            comp['ml_risk_score'] = round(ml_score, 2)
            comp['ml_features'] = features
            
        return components
