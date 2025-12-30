import sqlite3
import os
from typing import List, Dict, Tuple

class VulnDB:
    def __init__(self, db_path="data/vuln.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        # Create table optimized for PURL matching
        # Simple schema: package name, version range, CVE ID, severity, cvss
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT,
                version_start TEXT,
                version_end TEXT,
                cve_id TEXT,
                severity TEXT,
                cvss_score REAL,
                description TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_pkg_name ON vulnerabilities(package_name)')
        conn.commit()
        conn.close()

    def insert_vuln(self, package_name: str, version_start: str, version_end: str, cve_id: str, severity: str, cvss: float):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO vulnerabilities (package_name, version_start, version_end, cve_id, severity, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (package_name, version_start, version_end, cve_id, severity, cvss))
        conn.commit()
        conn.close()

    def get_vulns_for_package(self, package_name: str) -> List[Tuple]:
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM vulnerabilities WHERE package_name = ?', (package_name,))
        rows = cursor.fetchall()
        conn.close()
        return rows

    def populate_mock_data(self):
        """Populates the DB with some sample data for testing."""
        # Clean first
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM vulnerabilities')
        conn.commit()
        conn.close()

        # Sample 1: library-b < 2.2.0 is vulnerable
        self.insert_vuln("library-b", "0.0.0", "2.2.0", "CVE-2023-1234", "HIGH", 8.5)
        # Sample 2: log4j < 2.15.0
        self.insert_vuln("log4j", "2.0.0", "2.15.0", "CVE-2021-44228", "CRITICAL", 10.0)

if __name__ == "__main__":
    db = VulnDB()
    db.populate_mock_data()
    print("Database populated with mock data.")
    print(db.get_vulns_for_package("library-b"))
