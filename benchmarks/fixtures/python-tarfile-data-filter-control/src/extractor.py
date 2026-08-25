from __future__ import annotations

import tarfile

MAX_ARCHIVE_MEMBERS = 32
MAX_EXPANDED_BYTES = 2_097_152
MAX_MEMBER_BYTES = 1_048_576


def validated_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    names: set[str] = set()
    expanded_bytes = 0
    for member in archive:
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive member limit exceeded")
        if not (member.isfile() or member.isdir()):
            raise ValueError("archive links and special files are not accepted")
        if member.size < 0 or member.size > MAX_MEMBER_BYTES:
            raise ValueError("archive member size limit exceeded")
        expanded_bytes += member.size
        if expanded_bytes > MAX_EXPANDED_BYTES:
            raise ValueError("archive expanded-byte limit exceeded")
        normalized_name = member.name.replace("\\", "/").casefold()
        if normalized_name in names:
            raise ValueError("duplicate archive member")
        names.add(normalized_name)
        members.append(member)
    return members


def extract_archive(stream, destination) -> None:
    with tarfile.open(fileobj=stream, mode="r:*") as archive:
        archive.extractall(
            path=destination,
            members=validated_members(archive),
            filter="data",
        )
