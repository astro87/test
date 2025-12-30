from typing import Dict, Any, List
try:
    import spacy
except ImportError:
    spacy = None

class NLPProcessor:
    """
    NLP module for extracting context, reasoning about severity, and generating explanations.
    Uses SpaCy for text analysis and a neuro-symbolic approach for severity inference.
    """
    def __init__(self):
        self.nlp = None
        if spacy:
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                print("Warning: SpaCy model 'en_core_web_sm' not found. NLP features will be limited.")
        else:
             print("Warning: SpaCy not installed. NLP features disabled.")

        # Neuro-symbolic keywords map for severity inference
        self.severity_map = {
            "CRITICAL": ["remote code execution", "rce", "arbitrary code", "jndi lookup"],
            "HIGH": ["privilege escalation", "sql injection", "authentication bypass", "xss"],
            "MEDIUM": ["denial of service", "dos", "information disclosure"],
            "LOW": ["small memory leak", "local access"]
        }

    def analyze_description(self, description: str) -> Dict[str, Any]:
        """
        Analyzes a vulnerability description to extract attack vector and infer severity.
        """
        if not description:
            return {"attack_type": "Unknown", "inferred_severity": "UNKNOWN", "explanation": "No description available."}
        
        doc = self.nlp(description.lower()) if self.nlp else None
        text_lower = description.lower()
        
        # 1. Inference: Determine Attack Type and Severity
        inferred_severity = "UNKNOWN"
        attack_type = "Generic Vulnerability"
        
        # Check Critical triggers
        for keyword in self.severity_map["CRITICAL"]:
            if keyword in text_lower:
                inferred_severity = "CRITICAL"
                attack_type = "Remote Code Execution (RCE)"
                break
        
        # Check High triggers
        if inferred_severity == "UNKNOWN":
            for keyword in self.severity_map["HIGH"]:
                if keyword in text_lower:
                    inferred_severity = "HIGH"
                    attack_type = "Privilege Escalation / Auth Bypass"
                    break
                    
        # Check Medium triggers
        if inferred_severity == "UNKNOWN":
            for keyword in self.severity_map["MEDIUM"]:
                if keyword in text_lower:
                    inferred_severity = "MEDIUM"
                    attack_type = "Denial of Service (DoS)"
                    break

        # 2. Explanation Generation (NLP-based)
        # Use SpaCy to identify the main verb/action if possible for dynamic explanation
        action = "exploit"
        if doc:
            # Simple heuristic: find the first verb that is not a stop word
            for token in doc:
                if token.pos_ == "VERB" and not token.is_stop:
                    action = token.lemma_
                    break
                    
        explanation = f"This vulnerability involves {attack_type.lower()} which allows attackers to {action} the system."
        if inferred_severity == "CRITICAL":
            explanation += " This is highly dangerous and requires immediate patching."
            
        return {
            "attack_type": attack_type,
            "inferred_severity": inferred_severity,
            "explanation": explanation
        }

class ReasoningEngine:
    """
    Neuro-Symbolic Engine.
    Combines ML scores with expert rules for final decision and explainability.
    """
    def __init__(self):
        self.nlp_engine = NLPProcessor()
    
    def analyze(self, components: List[Dict[str, Any]], graph: Any) -> List[Dict[str, Any]]:
        """
        Applies rules to modify risk scores and generate explanations.
        """
        for comp in components:
            reasons = []
            
            # Start with ML score or 0
            final_score = comp.get('ml_risk_score', 0.0)
            
            # --- NLP Analysis Phase (Post-Processing) ---
            vulns = comp.get('vulnerabilities', [])
            nlp_data = {}
            if vulns:
                desc = vulns[0].get("description", "")
                nlp_data = self.nlp_engine.analyze_description(desc)
                comp['nlp_analysis'] = nlp_data # Store for frontend if needed
            else:
                 nlp_data = {
                     "attack_type": "None",
                     "inferred_severity": "SAFE",
                     "explanation": "No vulnerabilities detected."
                 }
            
            # --- Rule 1: Critical Path Exposure ---
            node_id = comp.get('bom-ref') or comp.get('purl')
            depth = comp.get('ml_features', [0, 0])[1] # Index 1 is depth
            
            if depth < 2 and final_score > 5.0:
                final_score *= 1.2 # Amplify risk by 20%
                reasons.append(f"High risk component near root (Depth {depth}). Impact is immediate.")

            # --- Rule 2: Neuro-Symbolic Severity Reasoning ---
            # Combine Rule-Based Severity with NLP-Inferred Severity
            vulns = comp.get('vulnerabilities', [])
            max_severity = "SAFE"
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0, "UNKNOWN": 0}
            
            # 2a. Check Structred Data
            if vulns:
                max_severity_val = 0
                for v in vulns:
                    s = v.get('severity', 'UNKNOWN').upper()
                    if severity_order.get(s, 0) > max_severity_val:
                        max_severity_val = severity_order.get(s, 0)
                        max_severity = s
            
            # 2b. Check NLP Inference (Override if NLP detects higher severity context)
            nlp_severity = nlp_data.get("inferred_severity", "UNKNOWN")
            if severity_order.get(nlp_severity, 0) > severity_order.get(max_severity, 0):
                max_severity = nlp_severity
                reasons.append(f"NLP Analysis detected '{nlp_severity}' context in advisory text.")

            # Fix: Ensure score reflects severity if CRITICAL/HIGH
            if max_severity == "CRITICAL":
                reasons.append("Contains CRITICAL vulnerability. Immediate remediation required.")
                final_score = max(final_score, 90.0)
            elif max_severity == "HIGH":
                final_score = max(final_score, 70.0) 
            
            # --- Rule 3: Public Exploit Availability ---
            exploit_maturity = comp.get('ml_features', [0, 0, 0])[2]
            if exploit_maturity > 0:
                 reasons.append("Exploit code is publicly available.")
            
            # --- NLP Explanation Injection ---
            if nlp_data.get("explanation"):
                reasons.append(f"[AI Insight] {nlp_data['explanation']}")

            # Cap Score
            final_score = min(100.0, final_score)
            
            # --- Final Labeling ---
            # Correct Rule: Logic says Vulnerability Severity drives the Label, not just Score
            if max_severity in ["CRITICAL", "HIGH"]:
                final_label = max_severity
            else:
                # Fallback to score-based mapping
                if final_score >= 90: final_label = "CRITICAL"
                elif final_score >= 70: final_label = "HIGH"
                elif final_score >= 40: final_label = "MEDIUM"
                elif final_score > 0: final_label = "LOW"
                else: final_label = "SAFE"
            
            comp['final_risk_score'] = round(final_score, 2)
            comp['risk_severity'] = final_label
            comp['risk_reasons'] = reasons
            
        return components

    def generate_system_summary(self, components: List[Dict[str, Any]]) -> str:
        """
        Generates high-level risk summary for the entire system.
        """
        summary = []
        critical_count = sum(1 for c in components if c.get('final_risk_score', 0) >= 90)
        high_count = sum(1 for c in components if 70 <= c.get('final_risk_score', 0) < 90)
        
        if critical_count > 0:
            summary.append(f"CRITICAL RISK: System contains {critical_count} critical components. Immediate action required.")
        elif high_count > 0:
            summary.append(f"HIGH RISK: System has {high_count} high-severity issues.")
        else:
            summary.append("System is relatively secure. No critical/high risks detected.")
            
        # Cluster analysis (mock)
        vulnerable_ecosystems = set()
        for c in components:
            if c.get('final_risk_score', 0) > 40:
                purl = c.get('purl', '')
                if 'npm' in purl: vulnerable_ecosystems.add('NPM')
                if 'pypi' in purl: vulnerable_ecosystems.add('PyPI')
        
        if vulnerable_ecosystems:
            summary.append(f"Risk concentration detected in: {', '.join(vulnerable_ecosystems)} ecosystems.")
            
        return " ".join(summary)
