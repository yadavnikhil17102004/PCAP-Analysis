from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT / "archive" / "pipeline"
for candidate in (str(ROOT), str(PIPELINE)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)


@pytest.fixture(scope="session")
def sample_pcap_path() -> Path:
    path = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"
    if not path.exists():
        raise FileNotFoundError(path)
    return path
