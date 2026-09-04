import os
import shutil
import unittest
import tempfile
from recover.carver_engine import StreamCarver
from eraser.eraser_engine import SecureEraser

class TestForensicNexus(unittest.TestCase):
    def setUp(self):
        self.carver = StreamCarver()
        self.eraser = SecureEraser()
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "sample.raw")
        
        with open(self.test_file, "wb") as f:
            # PNG signature + fake data + IEND
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x00IEND\xaeB`\x82")
            f.write(b"\x00" * 1024)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_carver_execution_and_metrics(self):
        res = self.carver.carve_target(job_id="TEST-001", target_path=self.test_file, output_base_dir=self.test_dir)
        self.assertIn("carving_exhaustion_confidence_pct", res["entropy_analysis"])
        self.assertEqual(res["deleted_files_recovered"], 1)

    def test_eraser_execution_and_signature(self):
        res = self.eraser.sanitize(target_path=self.test_file, method="NIST_CLEAR", job_id="TEST-ERASE-001")
        self.assertTrue(res.verified)
        self.assertEqual(res.job_id, "TEST-ERASE-001")

if __name__ == "__main__":
    unittest.main()
