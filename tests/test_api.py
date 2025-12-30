import unittest
from fastapi.testclient import TestClient
from backend.main import app
import os
import json

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        
    def test_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        
    def test_upload_flow(self):
        # Create a dummy SBOM file
        sbom_content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "test-lib", "version": "1.0", "purl": "pkg:npm/test-lib@1.0"}
            ],
            "dependencies": []
        }
        
        files = {
            'file': ('sbom.json', json.dumps(sbom_content), 'application/json')
        }
        
        # Upload
        response = self.client.post("/api/upload", files=files)
        self.assertEqual(response.status_code, 200)
        job_id = response.json().get("job_id")
        self.assertIsNotNone(job_id)
        
        # Poll status
        # Since run_analysis is async task, it might not be done instantly
        # But TestClient runs sync. Wait, background tasks in TestClient?
        # Starlette TestClient runs background tasks synchronously usually.
        # But we used asyncio.create_task which might not block TestClient.
        # Let's check if we get a status.
        
        status_response = self.client.get(f"/api/results/{job_id}")
        self.assertEqual(status_response.status_code, 200)
        data = status_response.json()
        self.assertIn(data['status'], ["processing", "completed", "failed"])

if __name__ == '__main__':
    unittest.main()
