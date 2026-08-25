from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile

FIXTURE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FIXTURE))

from src.extractor import extract_archive


def archive_bytes(payload: bytes) -> io.BytesIO:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo("../escaped-marker.txt")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    stream.seek(0)
    return stream


def main() -> None:
    payload = (Path(__file__).with_name("escaped-marker.txt")).read_bytes()
    error: str | None = None
    with tempfile.TemporaryDirectory(prefix="copilot-security-tarfile-") as root:
        root_path = Path(root)
        destination = root_path / "destination"
        destination.mkdir()
        escaped = root_path / "escaped-marker.txt"
        try:
            extract_archive(archive_bytes(payload), destination)
        except (OSError, tarfile.TarError) as caught:
            error = type(caught).__name__
        disclosed = escaped.is_file() and escaped.read_bytes() == payload
    print(
        json.dumps(
            {
                "disclosed": disclosed,
                "error": error,
                "python": ".".join(map(str, sys.version_info[:3])),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
