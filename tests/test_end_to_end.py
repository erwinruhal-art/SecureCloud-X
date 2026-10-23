"""
End-to-End System Integration Test
Simulates full browser-client interactions through Flask TestClient:
  1. Login as admin
  2. Upload file through the 8-stage cryptographic pipeline
  3. Verify file download and byte-for-byte decryption
  4. Simulate cloud fragment tampering and verify tamper detection & blocking
  5. Test ML threat detection simulation endpoints
  6. Execute live performance benchmark API
"""

import unittest
import io
import json
from app import app
from database.database import init_db
from init_db import seed_database


class TestEndToEndSystem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        seed_database()
        cls.client = app.test_client()

    def test_full_pipeline_flow(self):
        # 1. Login
        login_res = self.client.post("/login", data={
            "username": "admin",
            "password": "admin123"
        }, follow_redirects=True)
        self.assertEqual(login_res.status_code, 200)
        self.assertIn(b"System Status", login_res.data)

        # 2. Upload file
        sample_content = b"SecureCloud-X End-to-End Academic Demonstration File 2026."
        upload_data = {
            "file": (io.BytesIO(sample_content), "demo_project_report.pdf")
        }
        upload_res = self.client.post("/upload", data=upload_data, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(upload_res.status_code, 200)
        self.assertIn(b"Pipeline Execution Verified", upload_res.data)
        self.assertIn(b"STAGE 1", upload_res.data)
        self.assertIn(b"STAGE 6", upload_res.data)

        # Extract file_id from page response
        response_text = upload_res.data.decode("utf-8")
        import re
        match = re.search(r"FILE-[A-F0-9]+", response_text)
        self.assertIsNotNone(match)
        file_id = match.group(0)

        # 3. Download and verify original plaintext matches exactly
        download_res = self.client.get(f"/download/{file_id}")
        self.assertEqual(download_res.status_code, 200)
        self.assertEqual(download_res.data, sample_content)

        # 4. Standalone integrity check endpoint
        verify_res = self.client.get(f"/verify-integrity/{file_id}")
        self.assertEqual(verify_res.status_code, 200)
        v_data = json.loads(verify_res.data.decode("utf-8"))
        self.assertTrue(v_data["is_valid"])

        # 5. Simulate Tampering on Cloud A
        tamper_res = self.client.post("/api/security/simulate-tamper", json={"file_id": file_id})
        self.assertEqual(tamper_res.status_code, 200)
        t_data = json.loads(tamper_res.data.decode("utf-8"))
        self.assertFalse(t_data["is_valid"])
        self.assertIn("TAMPERING DETECTED", t_data["status"])

        # 6. Attempt download after tampering -> MUST BE BLOCKED
        blocked_download_res = self.client.get(f"/download/{file_id}", follow_redirects=True)
        self.assertEqual(blocked_download_res.status_code, 200)
        self.assertIn(b"Tampering detected", blocked_download_res.data)

        # 7. Test ML threat simulation endpoints
        ml_norm = self.client.post("/api/security/simulate-ml", json={"type": "normal"})
        self.assertEqual(ml_norm.status_code, 200)
        norm_data = json.loads(ml_norm.data.decode("utf-8"))["result"]
        self.assertEqual(norm_data["prediction"], "NORMAL")
        self.assertIn(norm_data["decision"], ["ALLOW", "WARN"])

        ml_susp = self.client.post("/api/security/simulate-ml", json={"type": "suspicious"})
        self.assertEqual(ml_susp.status_code, 200)
        susp_data = json.loads(ml_susp.data.decode("utf-8"))["result"]
        self.assertEqual(susp_data["prediction"], "ANOMALY")
        self.assertEqual(susp_data["decision"], "BLOCK")

        # 8. Test Performance Benchmark Suite API
        bench_res = self.client.post("/api/performance/run-benchmark")
        self.assertEqual(bench_res.status_code, 200)
        bench_data = json.loads(bench_res.data.decode("utf-8"))
        self.assertTrue(bench_data["success"])
        self.assertEqual(len(bench_data["benchmarks"]), 5)  # 10KB, 100KB, 1MB, 5MB, 10MB
        self.assertEqual(len(bench_data["rng_comparison"]), 3)


if __name__ == "__main__":
    unittest.main()
