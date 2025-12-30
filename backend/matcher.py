from typing import List, Dict, Any, Optional
from packaging.version import parse as parse_version
from packaging.specifiers import SpecifierSet
from backend.vuln_db import VulnDB

# --- KNOWLEDGE ENGINE ---
# Ground-truth vulnerability rules.
# In a future iteration, this can be hydrated from the DB or a live feed.
KNOWN_VULNERABILITIES = {
    "log4j-core": {
        "affected": "<2.17.1", # Covers Log4Shell and subsequent patches
        "severity": "CRITICAL",
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "description": "Remote Code Execution (RCE) in Log4j 2.x"
    },
    "jackson-databind": {
        "affected": "<2.13.0",
        "severity": "HIGH",
        "cve": "CVE-2020-36518", 
        "cvss": 7.5,
        "description": "Denial of Service (DoS) via deeply nested objects"
    },
    "commons-collections": {
        "affected": "<=3.2.1",
        "severity": "CRITICAL", 
        "cve": "CVE-2015-7501",
        "cvss": 9.8,
        "description": "Deserialization remote code execution"
    },
    "spring-web": {
         "affected": "<5.3.18",
         "severity": "CRITICAL",
         "cve": "CVE-2022-22965",
         "cvss": 9.8,
         "description": "Spring4Shell RCE"
    },
    "fastapi": {
        "affected": "<0.65.2",
        "severity": "MEDIUM", 
        "cve": "CVE-2021-32677",
        "cvss": 5.4,
        "description": "Incorrect Authorization"
    }
}

class VulnMatcher:
    def __init__(self, db_path="data/vuln.db"):
        # We keep the DB reference for future hybrid usage, 
        # but for now we rely on the deterministic Knowledge Engine.
        self.db = VulnDB(db_path)

    def match_components(self, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Matches components against the Rule-Based Vulnerability Knowledge Engine.
        Determinstic, fast, and explainable.
        """
        if not isinstance(components, list):
             raise TypeError(f"Matcher requires a concrete list, got {type(components)}")
             
        results = []
        for comp in components:
            name = comp.get('name', '').lower() # Normalize name
            version = comp.get('version')
            
            if not name or not version:
                continue
                
            # check if we have a rule for this package
            rule = KNOWN_VULNERABILITIES.get(name)
            if rule:
                if self._is_vulnerable(version, rule['affected']):
                    # MATCH FOUND
                    comp['vulnerabilities'] = [{
                        "id": rule['cve'],
                        "severity": rule['severity'],
                        "cvss": rule['cvss'],
                        "description": rule.get('description', 'Known Vulnerability')
                    }]
                    comp['risk_score'] = rule['cvss']
                    # Tag it for the frontend/reasoning engine
                    comp['match_type'] = 'rule_engine'
                    results.append(comp)
            
            # (Optional) Fallback to DB check could go here
                    
        return results

    def _is_vulnerable(self, version_str: str, specifier_str: str) -> bool:
        """
        Checks if a version string matches a specifier (e.g. '2.14.0' match '<2.15.0').
        """
        try:
            # Clean version string (remove 'v' prefix if present)
            if version_str.startswith('v'):
                version_str = version_str[1:]
                
            version = parse_version(version_str)
            spec = SpecifierSet(specifier_str)
            return version in spec
        except Exception as e:
            # If version parsing fails, assume safe to avoid false positives in strict mode
            # Or log warning
            return False
