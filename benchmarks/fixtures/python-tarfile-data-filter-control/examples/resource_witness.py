from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile

FIXTURE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FIXTURE))

from src.extractor import (
    MAX_ARCHIVE_MEMBERS,
    MAX_EXPANDED_BYTES,
    MAX_MEMBER_BYTES,
    extract_archive,
)


def archive_bytes(entries: list[tuple[tarfile.TarInfo, bytes]]) -> io.BytesIO:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for member, payload in entries:
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    stream.seek(0)
    return stream


def regular(name: str, payload: bytes = b"bounded") -> tuple[tarfile.TarInfo, bytes]:
    return tarfile.TarInfo(name), payload


def rejected(entries: list[tuple[tarfile.TarInfo, bytes]]) -> bool:
    with tempfile.TemporaryDirectory(prefix="copilot-security-tar-limit-") as root:
        try:
            extract_archive(archive_bytes(entries), Path(root) / "destination")
        except (ValueError, OSError, tarfile.TarError):
            return True
    return False


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="copilot-security-tar-valid-") as root:
        destination = Path(root) / "destination"
        extract_archive(
            archive_bytes([regular("bounded.txt")]),
            destination,
        )
        valid_round_trip = (destination / "bounded.txt").read_bytes() == b"bounded"

    too_many = [
        regular(f"member-{index}.txt", b"")
        for index in range(MAX_ARCHIVE_MEMBERS + 1)
    ]
    oversized_member = [regular("large.bin", b"x" * (MAX_MEMBER_BYTES + 1))]
    expanded_total = [
        regular("first.bin", b"x" * MAX_MEMBER_BYTES),
        regular("second.bin", b"x" * MAX_MEMBER_BYTES),
        regular("last.bin", b"x"),
    ]
    link = tarfile.TarInfo("link")
    link.type = tarfile.SYMTYPE
    link.linkname = "bounded.txt"
    duplicate = [regular("same.txt"), regular("SAME.TXT")]

    print(
        json.dumps(
            {
                "duplicate_rejected": rejected(duplicate),
                "expanded_limit": MAX_EXPANDED_BYTES,
                "expanded_total_rejected": rejected(expanded_total),
                "link_rejected": rejected([(link, b"")]),
                "member_limit": MAX_ARCHIVE_MEMBERS,
                "member_size_limit": MAX_MEMBER_BYTES,
                "oversized_member_rejected": rejected(oversized_member),
                "too_many_rejected": rejected(too_many),
                "valid_round_trip": valid_round_trip,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
