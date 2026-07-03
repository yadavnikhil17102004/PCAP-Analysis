from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# Local benchmark on synthetic PCAPs showed ~1000MB peak RSS at ~156MB capture size.
# Keep a wide buffer for concurrent Streamlit Cloud sessions and scapy's rdpcap() overhead.
MAX_SAFE_SIZE_MB = 100


def _size_bytes(file_path_or_buffer: Any) -> int:
    if hasattr(file_path_or_buffer, "size") and isinstance(file_path_or_buffer.size, (int, float)):
        return int(file_path_or_buffer.size)

    if isinstance(file_path_or_buffer, (str, os.PathLike, Path)):
        return Path(file_path_or_buffer).expanduser().resolve().stat().st_size

    if isinstance(file_path_or_buffer, (bytes, bytearray, memoryview)):
        return len(file_path_or_buffer)

    if hasattr(file_path_or_buffer, "getbuffer"):
        return len(file_path_or_buffer.getbuffer())

    if hasattr(file_path_or_buffer, "fileno"):
        return os.fstat(file_path_or_buffer.fileno()).st_size

    if hasattr(file_path_or_buffer, "seek") and hasattr(file_path_or_buffer, "tell"):
        current = file_path_or_buffer.tell()
        file_path_or_buffer.seek(0, os.SEEK_END)
        size = file_path_or_buffer.tell()
        file_path_or_buffer.seek(current, os.SEEK_SET)
        return int(size)

    raise TypeError(f"Unsupported PCAP input type: {type(file_path_or_buffer)!r}")


def check_pcap_size(file_path_or_buffer: Any, max_mb: int = MAX_SAFE_SIZE_MB):
    """
    Returns (is_safe: bool, size_mb: float, message: str).
    Check size BEFORE calling rdpcap(). For Streamlit UploadedFile objects,
    use .size attribute (bytes) rather than os.path.getsize to avoid requiring
    a disk write first.
    """
    size_bytes = _size_bytes(file_path_or_buffer)
    size_mb = size_bytes / (1024 * 1024)
    is_safe = size_mb <= max_mb

    if is_safe:
        message = f"File is {size_mb:.1f}MB and within the {max_mb}MB safe limit for this deployment."
    else:
        message = (
            f"File is {size_mb:.1f}MB, exceeds the {max_mb}MB safe limit for this deployment. "
            "Large-file support requires self-hosted deployment — contact admin."
        )

    return is_safe, round(size_mb, 2), message
