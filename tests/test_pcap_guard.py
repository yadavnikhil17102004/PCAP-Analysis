import tempfile
import unittest
from pathlib import Path

from utils.pcap_guard import MAX_SAFE_SIZE_MB, check_pcap_size


class DummyUploadedFile:
    def __init__(self, size, name="sample.pcap"):
        self.size = size
        self.name = name


class TestPcapGuard(unittest.TestCase):
    def test_guard_rejects_oversized_uploaded_file(self):
        oversized = DummyUploadedFile((MAX_SAFE_SIZE_MB + 1) * 1024 * 1024)
        is_safe, size_mb, message = check_pcap_size(oversized)
        self.assertFalse(is_safe)
        self.assertGreater(size_mb, MAX_SAFE_SIZE_MB)
        self.assertIn("exceeds", message)

    def test_guard_allows_under_limit_uploaded_file(self):
        under = DummyUploadedFile((MAX_SAFE_SIZE_MB - 1) * 1024 * 1024)
        is_safe, size_mb, message = check_pcap_size(under)
        self.assertTrue(is_safe)
        self.assertLess(size_mb, MAX_SAFE_SIZE_MB)
        self.assertIn("within", message)

    def test_guard_uses_path_size_when_given_file_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "small.pcap"
            path.write_bytes(b"x" * (2 * 1024 * 1024))
            is_safe, size_mb, _ = check_pcap_size(path)
            self.assertTrue(is_safe)
            self.assertAlmostEqual(size_mb, 2.0, places=2)


if __name__ == "__main__":
    unittest.main()
