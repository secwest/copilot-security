from __future__ import annotations

import tarfile


def extract_archive(stream, destination) -> None:
    with tarfile.open(fileobj=stream, mode="r:*") as archive:
        archive.extractall(path=destination)
