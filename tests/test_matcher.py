import unittest
from backend.matcher import VulnMatcher
from backend.vuln_db import VulnDB

class TestVulnMatcher(unittest.TestCase):
    def setUp(self):
        # Ensure DB is populated
        self.db = VulnDB("data/test_vuln.db")
        self.db.populate_mock_data()
        self.matcher = VulnMatcher("data/test_vuln.db")

    def test_match(self):
        components = [
            {"name": "library-b", "version": "2.1.0"}, # Vulnerable ( < 2.2.0)
            {"name": "library-b", "version": "2.3.0"}, # Safe
            {"name": "log4j", "version": "2.14.0"},    # Vulnerable
            {"name": "safe-lib", "version": "1.0.0"}    # Safe
        ]
        
        results = self.matcher.match_components(components)
        
        # Check library-b 2.1.0
        vuln_lib_b = next((c for c in results if c['name'] == 'library-b' and c['version'] == '2.1.0'), None)
        self.assertIsNotNone(vuln_lib_b)
        self.assertEqual(vuln_lib_b['vulnerabilities'][0]['id'], "CVE-2023-1234")
        
        # Check library-b 2.3.0 should not be in results (or have no vulns)
        safe_lib_b = next((c for c in results if c['name'] == 'library-b' and c['version'] == '2.3.0'), None)
        self.assertIsNone(safe_lib_b) # Our matcher only returns components with matches or modifies them? 
        # The code returns "results.append(comp)" only if vulns found.
        
        # Check log4j
        vuln_log4j = next((c for c in results if c['name'] == 'log4j'), None)
        self.assertIsNotNone(vuln_log4j)
        self.assertEqual(vuln_log4j['risk_score'], 10.0)

if __name__ == '__main__':
    unittest.main()
