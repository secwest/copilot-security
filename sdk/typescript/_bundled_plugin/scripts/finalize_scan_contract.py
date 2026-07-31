#!/usr/bin/env python3
"""Validate and seal additive Copilot Security scan-contract artifacts."""

from __future__ import annotations

import argparse
import copy
import csv
import errno
import hashlib
import importlib.util
import io
import json
import math
import os
import re
import secrets
import stat
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, TextIO
from urllib.parse import quote, urlsplit

SCHEMA_VERSION = "1.0"
PRODUCER_NAME = "copilot-security-plugin"
FINGERPRINT_ALGORITHM = "copilot-security/v1"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
CONFIDENCES = {"high", "medium", "low"}
TARGET_KINDS = {"git_revision", "git_worktree", "git_diff", "directory_snapshot"}
TARGET_COORDINATE_FIELDS = {
    "revision",
    "baseRevision",
    "headRevision",
    "snapshotDigest",
}
TARGET_REQUIRED_COORDINATE_FIELDS = {
    "git_revision": {"revision"},
    "git_worktree": {"snapshotDigest"},
    "git_diff": {"snapshotDigest"},
    "directory_snapshot": {"snapshotDigest"},
}
SCOPE_FIELDS = {
    "includePaths",
    "excludePaths",
    "summary",
    "artifactsReviewed",
    "runtimeStatus",
    "validationMode",
    "context",
    "limitations",
}
DISPOSITIONS = {"reported", "no_issue_found", "rejected", "not_applicable", "needs_follow_up"}
SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)
GITHUB_HASH_BLOCK_SIZE = 100
GITHUB_HASH_MOD = 37
GITHUB_HASH_MASK = (1 << 64) - 1
GITHUB_HASH_EOF = 65535
GITHUB_HASH_MAX_LINES = 100_000
SOURCE_READ_CHUNK_SIZE = 64 * 1024
SOURCE_READ_MAX_BYTES = 10 * 1024 * 1024
IN_SCOPE_INVENTORY_MAX_BYTES = 8 * 1024 * 1024
CONTRACT_DOCUMENT_MAX_BYTES = {
    "scan-manifest.json": 16 * 1024 * 1024,
    "findings.json": 128 * 1024 * 1024,
    "coverage.json": 32 * 1024 * 1024,
}
SCHEMA_DOCUMENT_MAX_BYTES = 4 * 1024 * 1024
JSON_DOCUMENT_READ_CHUNK_SIZE = 64 * 1024
MAX_JSON_DEPTH = 256
MAX_JSON_INTEGER = (1 << 53) - 1
MAX_DRAFT_JSON_QUOTE_REPAIRS = 64
MAX_SCHEMA_NODES = 8192
MAX_SCHEMA_COLLECTION_ENTRIES = 4096
MAX_SCHEMA_APPLICATOR_EDGES = 128
SAFE_SCHEMA_PATTERNS = {
    r"^(?![^:/?#]+://[^/?#]*@)[^?#]+$",
    r"^copilot-security-snapshot/v1:sha256:[a-f0-9]{64}$",
    r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))(?!.*\\).+$",
    r"^[a-f0-9]{64}$",
    r"^(?!.*(?:^|/)\.\.(?:/|$))(?!.*\\)artifacts/.+$",
    r"^csf_[a-f0-9]{24}$",
    r"^occ_[a-f0-9]{24}$",
    r"^[a-z0-9][a-z0-9._/-]*$",
    r"^copilot-security/v1:sha256:[a-f0-9]{64}$",
    r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$",
}
EXPORT_PATHS = {
    "csv": "exports/findings.csv",
    "json": "exports/findings.json",
    "sarif": "exports/results.sarif",
}


class ContractError(ValueError):
    """Raised when a completed scan does not satisfy the additive contract."""


def _reject_non_finite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is not supported")


def _loads_json(value: str | bytes) -> Any:
    return json.loads(value, parse_constant=_reject_non_finite_json)


def _repair_unescaped_json_string_quotes(value: str) -> str | None:
    """Escape bounded interior quotes while leaving JSON structure untouched."""

    output: list[str] = []
    in_string = False
    escaped = False
    repairs = 0
    for index, character in enumerate(value):
        if not in_string:
            output.append(character)
            if character == '"':
                in_string = True
            continue
        if escaped:
            output.append(character)
            escaped = False
            continue
        if character == "\\":
            output.append(character)
            escaped = True
            continue
        if character != '"':
            output.append(character)
            continue

        lookahead = index + 1
        while lookahead < len(value) and value[lookahead].isspace():
            lookahead += 1
        if lookahead == len(value) or value[lookahead] in ",:]}":
            output.append(character)
            in_string = False
            continue

        repairs += 1
        if repairs > MAX_DRAFT_JSON_QUOTE_REPAIRS:
            return None
        output.append('\\"')

    if in_string or repairs == 0:
        return None
    return "".join(output)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            raw = _read_bounded_json_document(handle, str(path), SCHEMA_DOCUMENT_MAX_BYTES)
        payload = _loads_json(raw.decode("utf-8"))
        _require_safe_json_value(payload, str(path))
    except FileNotFoundError as exc:
        raise ContractError(f"missing required contract artifact: {path}") from exc
    except ContractError:
        raise
    except ValueError as exc:
        raise ContractError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContractError(f"{path}: expected a JSON object")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(payload))


def _generate_report_projection(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
) -> bytes:
    script = Path(__file__).resolve().parent / "report_projection.py"
    spec = importlib.util.spec_from_file_location("copilot_security_report_projection", script)
    if spec is None or spec.loader is None:
        raise ContractError(f"could not load report projection helper: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.generate_report_markdown(manifest, findings, coverage)
    except (OSError, ValueError) as exc:
        raise ContractError(f"report projection failed: {exc}") from exc


def _validate_report_output_paths(scan_dir: Path) -> None:
    _validate_scan_local_output_path(scan_dir, scan_dir / "report.md", "report.md")


def _json_bytes(payload: Any) -> bytes:
    try:
        encoded = json.dumps(payload, allow_nan=False, indent=2, sort_keys=True)
    except ValueError as exc:
        raise ContractError(f"cannot encode canonical JSON: {exc}") from exc
    return (encoded + "\n").encode("utf-8")


def _contract_json_bytes(relative_path: str, payload: Any) -> bytes:
    _require_safe_json_value(payload, relative_path)
    encoded = _json_bytes(payload)
    maximum = CONTRACT_DOCUMENT_MAX_BYTES.get(relative_path)
    if maximum is not None and len(encoded) > maximum:
        raise ContractError(f"{relative_path}: JSON document exceeds the {maximum}-byte limit")
    return encoded


def _read_bounded_json_document(handle: BinaryIO, context: str, maximum: int) -> bytes:
    if os.fstat(handle.fileno()).st_size > maximum:
        raise ContractError(f"{context}: JSON document exceeds the {maximum}-byte limit")
    chunks: list[bytes] = []
    length = 0
    while length <= maximum:
        chunk = handle.read(min(JSON_DOCUMENT_READ_CHUNK_SIZE, maximum + 1 - length))
        if not chunk:
            break
        length += len(chunk)
        if length > maximum:
            raise ContractError(f"{context}: JSON document exceeds the {maximum}-byte limit")
        chunks.append(chunk)
    result = b"".join(chunks)
    _require_json_nesting(result, context)
    return result


def _require_json_nesting(value: bytes, context: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == ord("\\"):
                escaped = True
            elif character == ord('"'):
                in_string = False
            continue
        if character == ord('"'):
            in_string = True
        elif character in (ord("{"), ord("[")):
            depth += 1
            if depth > MAX_JSON_DEPTH + 1:
                raise ContractError(
                    f"{context}: JSON document exceeds the {MAX_JSON_DEPTH}-level nesting limit"
                )
        elif character in (ord("}"), ord("]")):
            depth -= 1


def _require_safe_json_value(value: Any, context: str, *, validate_strings: bool = True) -> None:
    def visit(item: Any, location: str, depth: int) -> None:
        if depth > MAX_JSON_DEPTH:
            raise ContractError(
                f"{location}: JSON document exceeds the {MAX_JSON_DEPTH}-level nesting limit"
            )
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ContractError(f"{location}: expected string JSON property names")
                if validate_strings:
                    _require_safe_json_string(key, location)
                visit(child, f"{location}.<property>", depth + 1)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, f"{location}[{index}]", depth + 1)
        elif isinstance(item, str) and validate_strings:
            _require_safe_json_string(item, location)
        elif isinstance(item, int) and not isinstance(item, bool):
            if abs(item) > MAX_JSON_INTEGER:
                raise ContractError(
                    f"{location}: unsafe integer-valued JSON numbers are not supported"
                )
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ContractError(f"{location}: non-finite JSON numbers are not supported")
            if item.is_integer() and abs(item) > MAX_JSON_INTEGER:
                raise ContractError(
                    f"{location}: unsafe integer-valued JSON numbers are not supported"
                )

    visit(value, context, 0)


def _require_safe_json_string(value: str, context: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{context}: expected well-formed Unicode JSON strings") from exc


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_dict(payload: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ContractError(f"{context}.{key}: expected an object")
    return value


def _require_list(payload: dict[str, Any], key: str, context: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ContractError(f"{context}.{key}: expected an array")
    return value


def _require_str(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{context}.{key}: expected a non-empty string")
    return value


def _require_safe_relative_path(value: str, context: str, *, allow_dot: bool = False) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{context}: expected a safe repository-relative POSIX path") from exc
    path = PurePosixPath(value)
    normalized = path.as_posix()
    if (
        not value
        or (normalized == "." and not allow_dot)
        or "\\" in value
        or "\0" in value
        or path.is_absolute()
        or ".." in path.parts
    ):
        raise ContractError(f"{context}: expected a safe repository-relative POSIX path")
    return normalized


def _require_scan_directory(scan_dir: Path) -> Path:
    scan_dir = scan_dir.absolute()
    try:
        metadata = scan_dir.lstat()
    except OSError as exc:
        raise ContractError("scan directory: expected an existing non-symlink directory") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ContractError("scan directory: expected an existing non-symlink directory")
    try:
        resolved = scan_dir.resolve(strict=True)
    except OSError as exc:
        raise ContractError("scan directory: expected an existing non-symlink directory") from exc
    if os.path.normcase(resolved) != os.path.normcase(scan_dir):
        raise ContractError("scan directory: expected a canonical non-symlink directory")
    return resolved


def _validate_scan_local_output_path(scan_dir: Path, path: Path, relative_path: str) -> None:
    try:
        resolved_parent = path.parent.resolve(strict=True)
        resolved_parent.relative_to(scan_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ContractError(f"{relative_path}: expected a path inside the scan directory") from exc
    if (
        os.path.normcase(resolved_parent) != os.path.normcase(path.parent)
        or path.is_symlink()
    ):
        raise ContractError(
            f"{relative_path}: expected a non-symlink path inside the scan directory"
        )
    if path.exists() and not path.is_file():
        raise ContractError(f"{relative_path}: expected a regular file")


def _descriptor_relative_reads_available() -> bool:
    return os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")


def _is_windows() -> bool:
    return os.name == "nt"


def _descriptor_relative_writes_available() -> bool:
    # os.replace accepts src_dir_fd/dst_dir_fd wherever descriptor-relative
    # os.rename is supported, but Python lists only os.rename in supports_dir_fd.
    required_operations = (os.mkdir, os.open, os.rename, os.stat, os.unlink)
    return hasattr(os, "O_NOFOLLOW") and all(
        operation in os.supports_dir_fd for operation in required_operations
    )


_WINDOWS_SCAN_LOCAL_FILES: Any | None = None


def _windows_scan_local_files() -> Any:
    """Load the Win32 backend only on runtimes that need it."""

    global _WINDOWS_SCAN_LOCAL_FILES
    if _WINDOWS_SCAN_LOCAL_FILES is None:
        script = Path(__file__).resolve().with_name("windows_scan_local_files.py")
        spec = importlib.util.spec_from_file_location("copilot_security_windows_scan_files", script)
        if spec is None or spec.loader is None:
            raise ContractError(f"could not load Windows scan-local file helper: {script}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _WINDOWS_SCAN_LOCAL_FILES = module
    return _WINDOWS_SCAN_LOCAL_FILES


def _open_verified_scan_directory(scan_dir: Path) -> int:
    scan_dir = scan_dir.absolute()
    try:
        expected = scan_dir.lstat()
        canonical = _require_scan_directory(scan_dir)
        descriptor = os.open(
            canonical,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ContractError("scan directory: expected an existing non-symlink directory") from exc
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
        os.close(descriptor)
        raise ContractError("scan directory: changed while it was being opened")
    return descriptor


def _open_scan_local_directory(root_fd: int, parts: tuple[str, ...], *, create: bool) -> int:
    descriptor = os.dup(root_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            next_descriptor = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_scan_local_file_descriptor(scan_dir: Path, relative_path: str, context: str) -> int:
    scan_dir = _require_scan_directory(scan_dir)
    relative_path = _require_safe_relative_path(relative_path, context)
    if not _descriptor_relative_reads_available():
        if not _is_windows():
            raise ContractError("scan-local input requires descriptor-relative file operations")
        try:
            return _windows_scan_local_files().open_read_fd(scan_dir, relative_path, context)
        except OSError as exc:
            raise ContractError(str(exc)) from exc
    root_fd: int | None = None
    parent_fd: int | None = None
    descriptor: int | None = None
    try:
        root_fd = _open_verified_scan_directory(scan_dir)
        parts = PurePosixPath(relative_path).parts
        try:
            parent_fd = _open_scan_local_directory(root_fd, parts[:-1], create=False)
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                try:
                    link_target = Path(os.readlink(parts[-1], dir_fd=parent_fd))
                    if not link_target.is_absolute():
                        link_target = scan_dir.joinpath(*parts[:-1], link_target)
                    link_target.resolve(strict=False).relative_to(scan_dir)
                except (OSError, RuntimeError, ValueError):
                    raise ContractError(
                        f"{context}: expected a file inside the scan directory"
                    ) from exc
                raise ContractError(f"{context}: expected a regular non-symlink file") from exc
            raise ContractError(f"{context}: expected a file inside the scan directory") from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"{context}: expected a regular non-symlink file")
        result = descriptor
        descriptor = None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_fd is not None:
            os.close(parent_fd)
        if root_fd is not None:
            os.close(root_fd)


def _require_scan_local_file(scan_dir: Path, relative_path: str, context: str) -> None:
    descriptor = open_scan_local_file_descriptor(scan_dir, relative_path, context)
    os.close(descriptor)


def _require_derived_writeup_files(scan_dir: Path, findings: dict[str, Any]) -> None:
    for index, finding in enumerate(findings.get("findings", [])):
        if not isinstance(finding, dict):
            continue
        writeup = finding.get("writeup")
        if not isinstance(writeup, dict):
            continue
        report_path = writeup.get("reportPath")
        if isinstance(report_path, str):
            _require_scan_local_file(
                scan_dir,
                report_path,
                f"findings[{index}].writeup.reportPath",
            )


def _require_hardening_portfolio_file(scan_dir: Path, scan: dict[str, Any]) -> None:
    hardening = scan.get("hardening")
    if not isinstance(hardening, dict):
        return
    portfolio_path = hardening.get("portfolioPath")
    if isinstance(portfolio_path, str):
        _require_scan_local_file(
            scan_dir,
            portfolio_path,
            "manifest.scan.hardening.portfolioPath",
        )


def _read_scan_local_json_bytes(
    scan_dir: Path,
    relative_path: str,
    context: str,
    *,
    require_object: bool = True,
    draft_recovery_warnings: list[str] | None = None,
) -> tuple[Any, bytes]:
    descriptor = open_scan_local_file_descriptor(scan_dir, relative_path, context)
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            maximum = CONTRACT_DOCUMENT_MAX_BYTES.get(relative_path)
            raw = (
                handle.read()
                if maximum is None
                else _read_bounded_json_document(handle, context, maximum)
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError(f"{context}: invalid JSON: {exc}") from exc
        try:
            payload = _loads_json(text)
        except ValueError as exc:
            repaired = (
                _repair_unescaped_json_string_quotes(text)
                if draft_recovery_warnings is not None
                else None
            )
            if repaired is None:
                raise ContractError(f"{context}: invalid JSON: {exc}") from exc
            try:
                payload = _loads_json(repaired)
            except ValueError:
                raise ContractError(f"{context}: invalid JSON: {exc}") from exc
            raw = repaired.encode("utf-8")
            warning = (
                f"Recovered unescaped quotation marks in unsealed {context}."
            )
            if warning not in draft_recovery_warnings:
                draft_recovery_warnings.append(warning)
        if require_object and not isinstance(payload, dict):
            raise ContractError(f"{context}: expected a JSON object")
        _require_safe_json_value(payload, context, validate_strings=False)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return payload, raw


def _read_scan_local_json(scan_dir: Path, relative_path: str, context: str) -> dict[str, Any]:
    payload, _ = _read_scan_local_json_bytes(scan_dir, relative_path, context)
    return payload


def _sha256_scan_local_file(scan_dir: Path, relative_path: str, context: str) -> str:
    descriptor = open_scan_local_file_descriptor(scan_dir, relative_path, context)
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest()


def write_scan_local_bytes(
    scan_dir: Path, relative_path: str, payload: bytes, *, external_name: bool = False
) -> None:
    scan_dir = _require_scan_directory(scan_dir)
    if external_name:
        if relative_path in {"", ".", ".."} or "/" in relative_path or "\0" in relative_path:
            raise ContractError("external output path: expected a safe file name")
    else:
        relative_path = _require_safe_relative_path(relative_path, "scan-local output path")
    path = scan_dir / relative_path
    if not _descriptor_relative_writes_available():
        if not _is_windows():
            raise ContractError("scan-local output requires descriptor-relative file operations")
        try:
            _windows_scan_local_files().atomic_write(scan_dir, relative_path, payload)
        except OSError as exc:
            raise ContractError(f"{relative_path}: {exc}") from exc
        return
    root_fd: int | None = None
    parent_fd: int | None = None
    temp_name: str | None = None
    try:
        root_fd = _open_verified_scan_directory(scan_dir)
        parts = PurePosixPath(relative_path).parts
        try:
            parent_fd = _open_scan_local_directory(root_fd, parts[:-1], create=True)
        except OSError as exc:
            raise ContractError(
                f"{relative_path}: expected a path inside the scan directory"
            ) from exc
        try:
            metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(metadata.st_mode):
                raise ContractError(f"{relative_path}: expected a regular non-symlink file")
        temp_name = f".{path.name}.{secrets.token_hex(8)}.tmp"
        temp_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
        with os.fdopen(temp_fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, parts[-1], src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_name = None
    finally:
        if temp_name is not None and parent_fd is not None:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        if parent_fd is not None:
            os.close(parent_fd)
        if root_fd is not None:
            os.close(root_fd)


def _remove_scan_local_file_if_exists(scan_dir: Path, relative_path: str) -> None:
    scan_dir = _require_scan_directory(scan_dir)
    relative_path = _require_safe_relative_path(relative_path, "scan-local cleanup path")
    if not _descriptor_relative_writes_available():
        if not _is_windows():
            raise ContractError("scan-local cleanup requires descriptor-relative file operations")
        try:
            _windows_scan_local_files().unlink_if_exists(scan_dir, relative_path)
        except OSError as exc:
            raise ContractError(f"{relative_path}: {exc}") from exc
        return
    root_fd: int | None = None
    parent_fd: int | None = None
    try:
        root_fd = _open_verified_scan_directory(scan_dir)
        parts = PurePosixPath(relative_path).parts
        parent_fd = _open_scan_local_directory(root_fd, parts[:-1], create=False)
        try:
            metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            raise ContractError(f"{relative_path}: expected a regular file or symlink")
        os.unlink(parts[-1], dir_fd=parent_fd)
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if root_fd is not None:
            os.close(root_fd)


def _write_scan_local_json(scan_dir: Path, relative_path: str, payload: Any) -> None:
    write_scan_local_bytes(scan_dir, relative_path, _contract_json_bytes(relative_path, payload))


def _validate_remote(remote: str, context: str) -> None:
    parsed = urlsplit(remote)
    if not parsed.scheme or not parsed.netloc:
        raise ContractError(f"{context}: expected a sanitized canonical absolute URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ContractError(
            f"{context}: remote URL must not contain credentials, query, or fragment"
        )


def _validate_date_time(value: str, context: str) -> None:
    if not RFC3339_RE.fullmatch(value):
        raise ContractError(f"{context}: expected an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value[-1] in "Zz" else value)
    except ValueError as exc:
        raise ContractError(f"{context}: expected an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{context}: expected an RFC 3339 timestamp")


def _validate_target(target: dict[str, Any]) -> None:
    kind = _require_str(target, "kind", "scan.target")
    if kind not in TARGET_KINDS:
        raise ContractError(f"scan.target.kind: unsupported target kind: {kind}")
    _require_str(target, "targetId", "scan.target")
    _require_str(target, "displayName", "scan.target")
    remote = target.get("remote")
    if remote is not None:
        if not isinstance(remote, str):
            raise ContractError("scan.target.remote: expected a string")
        _validate_remote(remote, "scan.target.remote")
    if kind == "git_revision":
        _require_str(target, "revision", "scan.target")
    elif kind == "git_worktree":
        _require_str(target, "snapshotDigest", "scan.target")
    elif kind == "git_diff":
        _require_str(target, "snapshotDigest", "scan.target")
    elif kind == "directory_snapshot":
        _require_str(target, "snapshotDigest", "scan.target")


def _fingerprint(target_id: str, finding: dict[str, Any]) -> str:
    identity = _require_dict(finding, "identity", "finding")
    anchor = _require_str(identity, "anchor", "finding.identity")
    if not SLUG_RE.fullmatch(anchor):
        raise ContractError("finding.identity.anchor: expected a stable lowercase semantic slug")
    instance = identity.get("instance", "")
    if not isinstance(instance, str):
        raise ContractError("finding.identity.instance: expected a string")
    if instance and not SLUG_RE.fullmatch(instance):
        raise ContractError("finding.identity.instance: expected a stable lowercase semantic slug")
    rule_id = _require_str(finding, "ruleId", "finding")
    if not SLUG_RE.fullmatch(rule_id):
        raise ContractError("finding.ruleId: expected a stable lowercase rule slug")
    material = "\0".join((FINGERPRINT_ALGORITHM, target_id, rule_id, anchor, instance))
    return f"{FINGERPRINT_ALGORITHM}:sha256:{_sha256_text(material)}"


def _stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}_{_sha256_text(chr(0).join(parts))[:24]}"


def _validate_location(location: dict[str, Any], context: str) -> None:
    _require_safe_relative_path(_require_str(location, "path", context), f"{context}.path")
    start = location.get("startLine")
    end = location.get("endLine", start)
    if not isinstance(start, int) or start < 1:
        raise ContractError(f"{context}.startLine: expected a positive integer")
    if not isinstance(end, int) or end < start:
        raise ContractError(f"{context}.endLine: expected an integer >= startLine")
    role = location.get("role")
    if role is not None and (not isinstance(role, str) or not role):
        raise ContractError(f"{context}.role: expected a non-empty string")


def _derived_finding_identity_rows(
    manifest: dict[str, Any],
    findings: dict[str, Any],
) -> list[tuple[str, dict[str, Any], str, str, dict[str, str]]]:
    scan = _require_dict(manifest, "scan", "manifest")
    scan_id = _require_str(scan, "id", "manifest.scan")
    target_id = _require_str(
        _require_dict(scan, "target", "manifest.scan"), "targetId", "scan.target"
    )
    if findings.get("scanId") != scan_id:
        raise ContractError("findings.scanId: must match manifest scan id")

    finding_ids: set[str] = set()
    occurrence_ids: set[str] = set()
    rows: list[tuple[str, dict[str, Any], str, str, dict[str, str]]] = []
    for index, finding in enumerate(_require_list(findings, "findings", "findings")):
        context = f"findings.findings[{index}]"
        if not isinstance(finding, dict):
            raise ContractError(f"{context}: expected an object")
        fingerprint = _fingerprint(target_id, finding)
        expected_finding_id = _stable_id("csf", fingerprint)
        expected_occurrence_id = _stable_id("occ", scan_id, fingerprint)
        expected_fingerprints = {"algorithm": FINGERPRINT_ALGORITHM, "primary": fingerprint}
        rows.append(
            (
                context,
                finding,
                expected_finding_id,
                expected_occurrence_id,
                expected_fingerprints,
            )
        )
        finding_ids.add(expected_finding_id)
        if expected_occurrence_id in occurrence_ids:
            raise ContractError(
                f"{context}: duplicate occurrence identity; use identity.instance to split siblings"
            )
        occurrence_ids.add(expected_occurrence_id)

    if len(finding_ids) != len(occurrence_ids):
        raise ContractError("findings: duplicate logical findings in one scan")
    return rows


def _populate_unsealed_finding_identities(
    manifest: dict[str, Any],
    findings: dict[str, Any],
) -> None:
    """Replace draft-owned finding identities with deterministic finalizer values."""

    for _, finding, finding_id, occurrence_id, fingerprints in _derived_finding_identity_rows(
        manifest,
        findings,
    ):
        finding["findingId"] = finding_id
        finding["occurrenceId"] = occurrence_id
        finding["fingerprints"] = fingerprints


def _finding_strength(finding: dict[str, Any]) -> tuple[int, int, int]:
    return (
        ("informational", "low", "medium", "high", "critical").index(finding["severity"]["level"]),
        ("low", "medium", "high").index(finding["confidence"]["level"]),
        len(finding.get("codeEvidence") or []),
    )


def _prune_unknown_evidence_refs(finding: dict[str, Any]) -> list[tuple[str, int]]:
    code_evidence = finding.get("codeEvidence")
    if not isinstance(code_evidence, list):
        return []
    evidence_ids = {
        evidence.get("id")
        for evidence in code_evidence
        if isinstance(evidence, dict)
        and isinstance(evidence.get("id"), str)
        and evidence["id"]
    }
    recovered: list[tuple[str, int]] = []
    for section_name in ("rootCause", "validation", "attackPath"):
        section = finding.get(section_name)
        if not isinstance(section, dict) or "evidenceRefs" not in section:
            continue
        refs = section["evidenceRefs"]
        if not isinstance(refs, list) or any(
            not isinstance(ref, str) or not ref for ref in refs
        ):
            continue
        retained = [ref for ref in refs if ref in evidence_ids]
        removed = len(refs) - len(retained)
        if removed:
            section["evidenceRefs"] = retained
            recovered.append((section_name, removed))
    return recovered


def _recover_unsealed_findings(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    schema_dir: Path,
    scan_dir: Path,
    warnings: list[str],
) -> list[str]:
    schema = _read_json(schema_dir / "findings.schema.json")
    _require_safe_schema(schema, "findings.schema.json")
    properties = _require_dict(schema, "properties", "findings.schema")
    finding_array = _require_dict(properties, "findings", "findings.schema.properties")
    finding_schema = _require_dict(finding_array, "items", "findings.schema.properties.findings")
    finding_properties = _require_dict(
        finding_schema, "properties", "findings.schema.properties.findings.items"
    )
    writeup_schema = _require_dict(
        finding_properties, "writeup", "findings.schema.properties.findings.items.properties"
    )
    scan = _require_dict(manifest, "scan", "manifest")
    scan_id = _require_str(scan, "id", "manifest.scan")
    if findings.get("scanId") != scan_id:
        raise ContractError("findings.scanId: must match manifest scan id")

    recovered: list[dict[str, Any]] = []
    discarded: list[str] = []
    finding_positions: dict[str, int] = {}
    writeup_paths: set[str] = set()
    for index, finding in enumerate(_require_list(findings, "findings", "findings")):
        context = f"findings.findings[{index}]"
        try:
            if not isinstance(finding, dict):
                raise ContractError(f"{context}: expected an object")
            identity = _require_dict(finding, "identity", context)
            fields: list[tuple[dict[str, Any], str, str, str]] = [
                (finding, "ruleId", context, "rule identifier"),
                (identity, "anchor", f"{context}.identity", "semantic anchor"),
            ]
            if "instance" in identity:
                fields.append((identity, "instance", f"{context}.identity", "instance"))
            normalized_fields = []
            for parent, field, field_context, label in fields:
                value = _require_str(parent, field, field_context)
                if SLUG_RE.fullmatch(value):
                    continue
                normalized = re.sub(r"[^a-z0-9._/-]+", "-", value.lower()).strip("._/-")
                if not SLUG_RE.fullmatch(normalized):
                    raise ContractError(
                        f"{field_context}.{field}: expected a stable lowercase semantic slug"
                    )
                parent[field] = normalized
                normalized_fields.append(label)

            _populate_unsealed_finding_identities(
                manifest,
                {"scanId": scan_id, "findings": [finding]},
            )
            finding_id = finding["findingId"]
            previous_position = finding_positions.get(finding_id)
            pruned_evidence_refs = _prune_unknown_evidence_refs(finding)
            _validate_finding(finding, context)
            if "writeup" in finding:
                try:
                    _validate_schema_node(finding["writeup"], writeup_schema, f"{context}.writeup")
                    report_path = finding["writeup"]["reportPath"]
                    previous_writeup = (
                        recovered[previous_position].get("writeup")
                        if previous_position is not None
                        else None
                    )
                    if report_path in writeup_paths and (
                        previous_writeup is None or previous_writeup["reportPath"] != report_path
                    ):
                        raise ContractError(f"{context}.writeup.reportPath: duplicate report path")
                    _require_scan_local_file(scan_dir, report_path, f"{context}.writeup.reportPath")
                except ContractError as exc:
                    finding.pop("writeup")
                    warnings.append(f"Skipped malformed writeup for finding {index + 1}: {exc}.")
            _validate_schema_node(finding, finding_schema, context)
        except ContractError as exc:
            warning = f"Skipped malformed finding {index + 1}: {exc}."
            warnings.append(warning)
            discarded.append(warning)
            continue

        if previous_position is not None:
            previous = recovered[previous_position]
            if _finding_strength(finding) <= _finding_strength(previous):
                warnings.append(
                    f"Skipped malformed finding {index + 1}: duplicate logical finding."
                )
                continue
            previous_writeup = previous.get("writeup")
            if previous_writeup is not None:
                writeup_paths.discard(previous_writeup["reportPath"])
            recovered[previous_position] = finding
            warnings.append(
                f"Recovered finding {index + 1}: retained stronger duplicate logical finding."
            )
        else:
            finding_positions[finding_id] = len(recovered)
            recovered.append(finding)

        if "writeup" in finding:
            writeup_paths.add(finding["writeup"]["reportPath"])
        if normalized_fields:
            warnings.append(
                f"Recovered finding {index + 1}: normalized {', '.join(normalized_fields)}."
            )
        for section_name, removed in pruned_evidence_refs:
            label = {
                "rootCause": "root-cause",
                "validation": "validation",
                "attackPath": "attack-path",
            }[section_name]
            noun = "reference" if removed == 1 else "references"
            warnings.append(
                f"Recovered finding {index + 1}: removed {removed} unknown "
                f"{label} code-evidence {noun}."
            )

    findings["findings"] = recovered
    return discarded


def _recover_unsealed_coverage(
    coverage: dict[str, Any],
    schema_dir: Path,
    scan_dir: Path,
    warnings: list[str],
    discarded_findings: list[str],
) -> None:
    schema = _read_json(schema_dir / "coverage.schema.json")
    _require_safe_schema(schema, "coverage.schema.json")
    properties = _require_dict(schema, "properties", "coverage.schema")
    completeness = coverage.get("completeness")
    partial = completeness not in ("complete", "partial", "unknown")
    if partial:
        warnings.append("Recovered malformed coverage completeness; marked coverage as partial.")

    surface_ids: set[str] = set()
    for field, label in (
        ("surfaces", "coverage surface"),
        ("explicitExclusions", "coverage exclusion"),
        ("deferred", "deferred coverage item"),
    ):
        array_schema = _require_dict(properties, field, "coverage.schema.properties")
        item_schema = _require_dict(array_schema, "items", f"coverage.schema.properties.{field}")
        items = coverage.get(field)
        if not isinstance(items, list):
            warnings.append(f"Skipped malformed {label} records: expected an array.")
            coverage[field] = []
            partial = True
            continue

        recovered: list[dict[str, Any]] = []
        for index, item in enumerate(items):
            context = f"coverage.{field}[{index}]"
            try:
                if not isinstance(item, dict):
                    raise ContractError(f"{context}: expected an object")
                if field == "surfaces":
                    surface_id = _require_str(item, "id", context)
                    if surface_id in surface_ids:
                        raise ContractError(f"{context}.id: duplicate surface id")
                    disposition = item.get("disposition")
                    surface_recovered = False
                    if not isinstance(disposition, str) or disposition not in DISPOSITIONS:
                        warnings.append(
                            f"Recovered coverage surface {index + 1}: "
                            "the review disposition could not be verified."
                        )
                        item["disposition"] = "needs_follow_up"
                        surface_recovered = True

                    receipt_refs = item.get("receiptRefs")
                    if not isinstance(receipt_refs, list):
                        warnings.append(
                            f"Skipped malformed receipt references for coverage surface "
                            f"{index + 1}: expected an array."
                        )
                        receipt_refs = []
                        surface_recovered = True

                    recovered_receipts: list[str] = []
                    for ref_index, ref in enumerate(receipt_refs):
                        ref_context = f"{context}.receiptRefs[{ref_index}]"
                        try:
                            if not isinstance(ref, str):
                                raise ContractError(f"{ref_context}: expected a string")
                            normalized_ref = _require_safe_relative_path(ref, ref_context)
                            if not normalized_ref.startswith("artifacts/"):
                                raise ContractError(
                                    f"{ref_context}: expected a file under artifacts/"
                                )
                            _require_scan_local_file(scan_dir, normalized_ref, ref_context)
                        except ContractError as exc:
                            warnings.append(
                                f"Skipped malformed coverage receipt "
                                f"{index + 1}.{ref_index + 1}: {exc}."
                            )
                            surface_recovered = True
                            continue
                        recovered_receipts.append(normalized_ref)

                    item["receiptRefs"] = recovered_receipts
                    if surface_recovered or item["disposition"] == "needs_follow_up":
                        if not surface_recovered and completeness != "partial":
                            warnings.append(
                                f"Coverage surface {index + 1} requires follow-up; "
                                "marked coverage as partial."
                            )
                        item["disposition"] = "needs_follow_up"
                        partial = True

                _validate_schema_node(item, item_schema, context)
            except ContractError as exc:
                warnings.append(f"Skipped malformed {label} {index + 1}: {exc}.")
                partial = True
                continue

            if field == "surfaces":
                surface_ids.add(surface_id)
            recovered.append(item)

        coverage[field] = recovered

    if discarded_findings:
        for surface in coverage["surfaces"]:
            surface["disposition"] = "needs_follow_up"
        coverage["deferred"].extend(
            {"id": f"discarded-finding-{index}", "reason": warning}
            for index, warning in enumerate(discarded_findings, 1)
        )
        partial = True

    if coverage["deferred"] and completeness != "partial":
        if not discarded_findings:
            warnings.append("Coverage has deferred review work; marked coverage as partial.")
        partial = True
    if partial:
        coverage["completeness"] = "partial"


def _recover_unsealed_hardening(
    manifest: dict[str, Any],
    scan_dir: Path,
    warnings: list[str],
) -> None:
    scan = _require_dict(manifest, "scan", "manifest")
    if "hardening" not in scan:
        return

    try:
        hardening = _require_dict(scan, "hardening", "manifest.scan")
        portfolio_path = _require_str(hardening, "portfolioPath", "manifest.scan.hardening")
        if portfolio_path != "hardening/hardening.md":
            raise ContractError(
                "manifest.scan.hardening.portfolioPath: expected hardening/hardening.md"
            )
        _require_hardening_portfolio_file(scan_dir, scan)
    except ContractError as exc:
        scan.pop("hardening")
        warnings.append(f"Skipped malformed hardening portfolio: {exc}.")


def _validate_derived_finding_identities(
    manifest: dict[str, Any],
    findings: dict[str, Any],
) -> None:
    """Require sealed finding identities to equal their deterministic values."""

    for context, finding, finding_id, occurrence_id, fingerprints in _derived_finding_identity_rows(
        manifest,
        findings,
    ):
        if finding.get("findingId") != finding_id:
            raise ContractError(f"{context}.findingId: does not match derived fingerprint identity")
        if finding.get("occurrenceId") != occurrence_id:
            raise ContractError(f"{context}.occurrenceId: does not match scan occurrence identity")
        if finding.get("fingerprints") != fingerprints:
            raise ContractError(f"{context}.fingerprints: does not match derived fingerprint")


def _populate_unsealed_manifest_envelope(
    manifest: dict[str, Any],
    scan: dict[str, Any],
    completion_binding: dict[str, Any] | None,
) -> None:
    """Populate non-semantic draft fields owned by finalization or the workbench."""

    manifest["documentType"] = "copilot-security.scan-manifest"
    manifest["schemaVersion"] = SCHEMA_VERSION
    scan["status"] = "completed"
    scan["coverageRef"] = "coverage.json"
    scan["findingsRef"] = "findings.json"
    if completion_binding is None:
        started_at = os.environ.get("COPILOT_SECURITY_STARTED_AT")
        if started_at is not None:
            _validate_date_time(started_at, "COPILOT_SECURITY_STARTED_AT")
            scan["startedAt"] = started_at
            scan["completedAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return

    scan["id"] = completion_binding["scanId"]
    scan["startedAt"] = completion_binding["startedAt"]
    scan["completedAt"] = completion_binding["completedAt"]
    scan["producer"] = copy.deepcopy(completion_binding["producer"])

    target = scan.get("target")
    if isinstance(target, dict):
        _populate_unsealed_target_binding(target, completion_binding["target"])

    scope = scan.get("scope")
    if isinstance(scope, dict):
        for field in list(scope):
            if field not in SCOPE_FIELDS:
                scope.pop(field, None)
        scope.update(copy.deepcopy(completion_binding["scope"]))


def _populate_unsealed_target_binding(
    target: dict[str, Any],
    target_binding: dict[str, Any],
) -> None:
    """Replace workbench-owned target coordinates without retaining incompatible drafts."""

    target_kind = target.get("kind")
    required_coordinates = (
        TARGET_REQUIRED_COORDINATE_FIELDS.get(target_kind, set())
        if isinstance(target_kind, str)
        else set()
    )
    for field in TARGET_COORDINATE_FIELDS:
        if field not in target_binding and field not in required_coordinates:
            target.pop(field, None)
    target.update(copy.deepcopy(target_binding))


def _populate_unsealed_artifact_envelope(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
    completion_binding: dict[str, Any] | None,
) -> None:
    """Populate deterministic top-level draft fields after refs have been resolved."""

    findings["documentType"] = "copilot-security.findings"
    findings["schemaVersion"] = SCHEMA_VERSION
    coverage["documentType"] = "copilot-security.coverage"
    coverage["schemaVersion"] = SCHEMA_VERSION
    if completion_binding is None:
        return

    scan_id = completion_binding["scanId"]
    findings["scanId"] = scan_id
    coverage["scanId"] = scan_id
    coverage["mode"] = completion_binding["coverageMode"]

    scan = _require_dict(manifest, "scan", "manifest")
    scope = _require_dict(scan, "scope", "manifest.scan")
    if "includePaths" in scope:
        coverage["includePaths"] = copy.deepcopy(scope["includePaths"])
    if "excludePaths" in scope:
        coverage["excludePaths"] = copy.deepcopy(scope["excludePaths"])


def _normalize_unsealed_open_questions(coverage: dict[str, Any]) -> None:
    """Keep only schema-valid optional open-question rows without inventing content."""

    open_questions = coverage.get("openQuestions")
    if not isinstance(open_questions, list):
        coverage.pop("openQuestions", None)
        return

    normalized: list[Any] = []
    for item in open_questions:
        if isinstance(item, str):
            question = item.strip()
            if question:
                normalized.append({"question": question})
            continue
        if not isinstance(item, dict):
            continue

        question = item.get("question")
        if not isinstance(question, str) or not question.strip():
            continue
        row = dict(item)
        row["question"] = question.strip()
        follow_up = row.get("followUpPrompt")
        if not isinstance(follow_up, str) or not follow_up.strip():
            row.pop("followUpPrompt", None)
        normalized.append(row)
    coverage["openQuestions"] = normalized


def _normalize_unsealed_deep_repository_inventory_strategy(
    coverage: dict[str, Any],
    *,
    expected_coverage_mode: str | None,
) -> None:
    """Normalize the old Deep workflow label to the ordinary repository inventory."""

    if (
        expected_coverage_mode == "deep_repository"
        and coverage.get("inventoryStrategy") == "deep_repository_repeated_discovery"
    ):
        coverage["inventoryStrategy"] = "repository"


def _validate_completion_binding(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
    completion_binding: dict[str, Any] | None,
) -> None:
    """Verify populated workbench-owned fields before an unsealed draft is written."""

    if completion_binding is None:
        return
    scan = _require_dict(manifest, "scan", "manifest")
    if scan.get("id") != completion_binding["scanId"]:
        raise ContractError("manifest.scan.id: must match the workbench scan")
    if scan.get("startedAt") != completion_binding["startedAt"]:
        raise ContractError("manifest.scan.startedAt: must match the workbench scan")
    if scan.get("completedAt") != completion_binding["completedAt"]:
        raise ContractError("manifest.scan.completedAt: must match the workbench completion")
    if scan.get("producer") != completion_binding["producer"]:
        raise ContractError("manifest.scan.producer: must match the workbench producer")
    target = _require_dict(scan, "target", "manifest.scan")
    allowed_target_kinds = completion_binding["allowedTargetKinds"]
    if target.get("kind") not in allowed_target_kinds:
        raise ContractError("scan.target.kind: must match the workbench target")
    for key, expected in completion_binding["target"].items():
        if target.get(key) != expected:
            raise ContractError(f"scan.target.{key}: must match the workbench target")
    scope = _require_dict(scan, "scope", "manifest.scan")
    for key, expected in completion_binding["scope"].items():
        if scope.get(key) != expected:
            raise ContractError(f"manifest.scan.scope.{key}: must match the workbench scan")
    if findings.get("scanId") != completion_binding["scanId"]:
        raise ContractError("findings.scanId: must match the workbench scan")
    if coverage.get("scanId") != completion_binding["scanId"]:
        raise ContractError("coverage.scanId: must match the workbench scan")
    if coverage.get("mode") != completion_binding["coverageMode"]:
        raise ContractError("coverage.mode: must match the workbench scan")
    for key, expected in completion_binding["scope"].items():
        if coverage.get(key) != expected:
            raise ContractError(f"coverage.{key}: must match the workbench scan")


def _validate_finding(finding: dict[str, Any], context: str) -> None:
    for key in ("findingId", "occurrenceId", "ruleId", "title", "summary", "remediation"):
        _require_str(finding, key, context)
    _require_dict(finding, "identity", context)
    fingerprints = _require_dict(finding, "fingerprints", context)
    if fingerprints.get("algorithm") != FINGERPRINT_ALGORITHM:
        raise ContractError(f"{context}.fingerprints.algorithm: unsupported algorithm")
    _require_str(fingerprints, "primary", f"{context}.fingerprints")

    severity = _require_dict(finding, "severity", context)
    level = _require_str(severity, "level", f"{context}.severity")
    if level not in SEVERITIES:
        raise ContractError(f"{context}.severity.level: unsupported severity: {level}")
    score = severity.get("score")
    if score is not None:
        if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 10:
            raise ContractError(f"{context}.severity.score: expected a number from 0 through 10")
        _require_str(severity, "scoringSystem", f"{context}.severity")

    confidence = _require_dict(finding, "confidence", context)
    confidence_level = _require_str(confidence, "level", f"{context}.confidence")
    if confidence_level not in CONFIDENCES:
        raise ContractError(
            f"{context}.confidence.level: unsupported confidence: {confidence_level}"
        )
    _require_str(confidence, "rationale", f"{context}.confidence")

    taxonomy = _require_dict(finding, "taxonomy", context)
    _require_str(taxonomy, "category", f"{context}.taxonomy")
    cwe = taxonomy.get("cwe", [])
    if not isinstance(cwe, list) or any(not isinstance(item, str) or not item for item in cwe):
        raise ContractError(f"{context}.taxonomy.cwe: expected an array of strings")

    locations = _require_list(finding, "locations", context)
    if not locations:
        raise ContractError(f"{context}.locations: expected at least one location")
    for index, location in enumerate(locations):
        if not isinstance(location, dict):
            raise ContractError(f"{context}.locations[{index}]: expected an object")
        _validate_location(location, f"{context}.locations[{index}]")

    evidence_ids: set[str] = set()
    code_evidence = finding.get("codeEvidence")
    if code_evidence is not None:
        if not isinstance(code_evidence, list):
            raise ContractError(f"{context}.codeEvidence: expected an array")
        for index, evidence in enumerate(code_evidence):
            evidence_context = f"{context}.codeEvidence[{index}]"
            if not isinstance(evidence, dict):
                raise ContractError(f"{evidence_context}: expected an object")
            evidence_id = _require_str(evidence, "id", evidence_context)
            if evidence_id in evidence_ids:
                raise ContractError(f"{evidence_context}.id: duplicate code-evidence id")
            evidence_ids.add(evidence_id)
            _require_str(evidence, "code", evidence_context)

    for section_name in ("rootCause", "validation", "attackPath"):
        section = finding.get(section_name)
        if not isinstance(section, dict) or "evidenceRefs" not in section:
            continue
        refs = section["evidenceRefs"]
        if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref for ref in refs):
            raise ContractError(f"{context}.{section_name}.evidenceRefs: expected strings")
        unknown_refs = sorted(set(refs) - evidence_ids)
        if unknown_refs:
            raise ContractError(
                f"{context}.{section_name}.evidenceRefs: unknown code-evidence ids: "
                + ", ".join(unknown_refs)
            )

    provenance = _require_dict(finding, "provenance", context)
    _require_str(provenance, "source", f"{context}.provenance")
    extensions = finding.get("extensions")
    if extensions is not None and not isinstance(extensions, dict):
        raise ContractError(f"{context}.extensions: expected an object")


def _validate_coverage(manifest: dict[str, Any], coverage: dict[str, Any], scan_dir: Path) -> None:
    scan = _require_dict(manifest, "scan", "manifest")
    scan_id = _require_str(scan, "id", "manifest.scan")
    if coverage.get("scanId") != scan_id:
        raise ContractError("coverage.scanId: must match manifest scan id")
    _require_str(coverage, "mode", "coverage")
    completeness = _require_str(coverage, "completeness", "coverage")
    _require_str(coverage, "inventoryStrategy", "coverage")
    scope = _require_dict(scan, "scope", "manifest.scan")
    if coverage.get("includePaths") != scope.get("includePaths"):
        raise ContractError("coverage.includePaths: must match manifest scope")
    if coverage.get("excludePaths") != scope.get("excludePaths"):
        raise ContractError("coverage.excludePaths: must match manifest scope")
    surface_ids: set[str] = set()
    has_needs_follow_up = False
    for index, surface in enumerate(_require_list(coverage, "surfaces", "coverage")):
        context = f"coverage.surfaces[{index}]"
        if not isinstance(surface, dict):
            raise ContractError(f"{context}: expected an object")
        surface_id = _require_str(surface, "id", context)
        if surface_id in surface_ids:
            raise ContractError(f"{context}.id: duplicate surface id")
        surface_ids.add(surface_id)
        _require_str(surface, "label", context)
        disposition = _require_str(surface, "disposition", context)
        if disposition not in DISPOSITIONS:
            raise ContractError(f"{context}.disposition: unsupported disposition: {disposition}")
        has_needs_follow_up = has_needs_follow_up or disposition == "needs_follow_up"
        receipt_refs = surface.get("receiptRefs", [])
        if not isinstance(receipt_refs, list):
            raise ContractError(f"{context}.receiptRefs: expected an array")
        for ref_index, ref in enumerate(receipt_refs):
            if not isinstance(ref, str):
                raise ContractError(f"{context}.receiptRefs[{ref_index}]: expected a string")
            normalized_ref = _require_safe_relative_path(ref, f"{context}.receiptRefs[{ref_index}]")
            if not normalized_ref.startswith("artifacts/"):
                raise ContractError(
                    f"{context}.receiptRefs[{ref_index}]: expected a file under artifacts/"
                )
            receipt_refs[ref_index] = normalized_ref
            _require_scan_local_file(
                scan_dir, normalized_ref, f"{context}.receiptRefs[{ref_index}]"
            )
    for field in ("explicitExclusions", "deferred"):
        if not isinstance(coverage.get(field, []), list):
            raise ContractError(f"coverage.{field}: expected an array")
    if completeness == "complete" and (has_needs_follow_up or coverage.get("deferred")):
        raise ContractError("coverage.completeness: complete coverage cannot have deferred work")
    _require_safe_json_value(coverage, "coverage.json")


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("documentType") != "copilot-security.scan-manifest":
        raise ContractError("manifest.documentType: expected copilot-security.scan-manifest")
    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        raise ContractError(f"manifest.schemaVersion: expected {SCHEMA_VERSION}")
    scan = _require_dict(manifest, "scan", "manifest")
    for key in ("id", "startedAt", "completedAt", "sealedAt"):
        _require_str(scan, key, "manifest.scan")
    if scan.get("status") != "completed":
        raise ContractError("manifest.scan.status: expected completed")
    producer = _require_dict(scan, "producer", "manifest.scan")
    _require_str(producer, "name", "manifest.scan.producer")
    _require_str(producer, "version", "manifest.scan.producer")
    _validate_target(_require_dict(scan, "target", "manifest.scan"))
    scope = _require_dict(scan, "scope", "manifest.scan")
    for field in ("includePaths", "excludePaths"):
        values = _require_list(scope, field, "manifest.scan.scope")
        for index, value in enumerate(values):
            if not isinstance(value, str):
                raise ContractError(f"manifest.scan.scope.{field}[{index}]: expected a string")
            _require_safe_relative_path(
                value, f"manifest.scan.scope.{field}[{index}]", allow_dot=True
            )
    _validate_contract_refs(scan)
    artifacts = _require_list(scan, "artifacts", "manifest.scan")
    if not artifacts:
        raise ContractError("manifest.scan.artifacts: expected generated artifact records")
    artifact_paths: set[str] = set()
    for index, artifact in enumerate(artifacts):
        context = f"manifest.scan.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise ContractError(f"{context}: expected an object")
        path = _require_safe_relative_path(
            _require_str(artifact, "path", context), f"{context}.path"
        )
        if path in artifact_paths:
            raise ContractError(f"{context}.path: duplicate artifact path")
        artifact_paths.add(path)
        _require_str(artifact, "sha256", context)
        _require_str(artifact, "mediaType", context)
    for required_path in ("findings.json", "coverage.json"):
        if required_path not in artifact_paths:
            raise ContractError(
                f"manifest.scan.artifacts: missing required artifact: {required_path}"
            )
    _require_safe_json_value(manifest, "scan-manifest.json")


def _validate_findings(manifest: dict[str, Any], findings: dict[str, Any]) -> None:
    if findings.get("documentType") != "copilot-security.findings":
        raise ContractError("findings.documentType: expected copilot-security.findings")
    if findings.get("schemaVersion") != SCHEMA_VERSION:
        raise ContractError(f"findings.schemaVersion: expected {SCHEMA_VERSION}")
    scan_id = _require_str(_require_dict(manifest, "scan", "manifest"), "id", "manifest.scan")
    if findings.get("scanId") != scan_id:
        raise ContractError("findings.scanId: must match manifest scan id")
    finding_ids: set[str] = set()
    occurrence_ids: set[str] = set()
    for index, finding in enumerate(_require_list(findings, "findings", "findings")):
        context = f"findings.findings[{index}]"
        if not isinstance(finding, dict):
            raise ContractError(f"{context}: expected an object")
        _validate_finding(finding, context)
        finding_id = str(finding["findingId"])
        occurrence_id = str(finding["occurrenceId"])
        if finding_id in finding_ids or occurrence_id in occurrence_ids:
            raise ContractError(f"{context}: duplicate finding or occurrence id")
        finding_ids.add(finding_id)
        occurrence_ids.add(occurrence_id)
    _require_safe_json_value(findings, "findings.json")


def _schema_type_matches(value: Any, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
        "null": value is None,
    }[expected]


def _validate_schema_node(value: Any, schema: dict[str, Any], context: str) -> None:
    expected = schema.get("type")
    if isinstance(expected, list):
        if not any(_schema_type_matches(value, item) for item in expected):
            raise ContractError(f"{context}: does not match schema type {expected}")
    elif isinstance(expected, str) and not _schema_type_matches(value, expected):
        raise ContractError(f"{context}: expected schema type {expected}")
    if "const" in schema and value != schema["const"]:
        raise ContractError(f"{context}: expected {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ContractError(f"{context}: unsupported value {value!r}")
    if isinstance(value, str):
        if schema.get("minLength", 0) and len(value) < schema["minLength"]:
            raise ContractError(f"{context}: string is too short")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise ContractError(f"{context}: string does not match schema pattern")
        if schema.get("format") == "date-time":
            _validate_date_time(value, context)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ContractError(f"{context}: value is below schema minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ContractError(f"{context}: value is above schema maximum")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ContractError(f"{context}: array has too few items")
        contains = schema.get("contains")
        if isinstance(contains, dict):
            matches = 0
            for item in value:
                try:
                    _validate_schema_node(item, contains, context)
                except ContractError:
                    pass
                else:
                    matches += 1
            if matches < schema.get("minContains", 1):
                raise ContractError(f"{context}: array contains too few matching items")
            if "maxContains" in schema and matches > schema["maxContains"]:
                raise ContractError(f"{context}: array contains too many matching items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_schema_node(item, item_schema, f"{context}[{index}]")
    if isinstance(value, dict):
        for item_schema in schema.get("allOf", []):
            _validate_schema_node(value, item_schema, context)
        condition = schema.get("if")
        if isinstance(condition, dict):
            try:
                _validate_schema_node(value, condition, context)
            except ContractError:
                pass
            else:
                then_schema = schema.get("then")
                if isinstance(then_schema, dict):
                    _validate_schema_node(value, then_schema, context)
        for key in schema.get("required", []):
            if key not in value:
                raise ContractError(f"{context}.{key}: missing required schema property")
        properties = schema.get("properties", {})
        for key, item in value.items():
            item_schema = properties.get(key)
            if isinstance(item_schema, dict):
                _validate_schema_node(item, item_schema, f"{context}.{key}")
            elif schema.get("additionalProperties") is False:
                raise ContractError(f"{context}.{key}: unexpected schema property")


def validate_against_schema(payload: dict[str, Any], schema_path: Path) -> None:
    schema = _read_json(schema_path)
    _require_safe_schema(schema, schema_path.name)
    _validate_schema_node(payload, schema, schema_path.stem)


def _require_safe_schema(schema: dict[str, Any], context: str) -> None:
    pending: list[tuple[Any, bool]] = [(schema, True)]
    nodes = 0
    applicator_edges = 0
    unsupported_keywords = {
        "$async",
        "$ref",
        "$dynamicRef",
        "$recursiveRef",
        "prefixItems",
        "patternProperties",
        "propertyNames",
        "dependentSchemas",
        "dependencies",
        "uniqueItems",
    }
    while pending:
        value, is_schema = pending.pop()
        nodes += 1
        if nodes > MAX_SCHEMA_NODES:
            raise ContractError(
                f"{context}: JSON Schema exceeds the {MAX_SCHEMA_NODES}-node complexity limit"
            )
        if isinstance(value, list):
            if len(value) > MAX_SCHEMA_COLLECTION_ENTRIES:
                raise ContractError(
                    f"{context}: JSON Schema exceeds the "
                    f"{MAX_SCHEMA_COLLECTION_ENTRIES}-entry collection limit"
                )
            pending.extend((child, is_schema) for child in value)
            continue
        if not isinstance(value, dict):
            continue
        if len(value) > MAX_SCHEMA_COLLECTION_ENTRIES:
            raise ContractError(
                f"{context}: JSON Schema exceeds the "
                f"{MAX_SCHEMA_COLLECTION_ENTRIES}-entry collection limit"
            )
        for keyword, child in value.items():
            if not is_schema:
                pending.append((child, False))
                continue
            if keyword in unsupported_keywords:
                raise ContractError(f"{context}: unsupported JSON Schema keyword")
            edges = 0
            if keyword in {"allOf", "anyOf", "oneOf"} and isinstance(child, list):
                edges = len(child)
            elif keyword in {
                "if",
                "then",
                "else",
                "not",
                "items",
                "contains",
                "additionalProperties",
                "unevaluatedProperties",
                "unevaluatedItems",
            } and isinstance(child, (dict, bool)):
                edges = 1
            elif keyword in {"properties", "$defs", "definitions"} and isinstance(child, dict):
                edges = len(child)
            applicator_edges += edges
            if applicator_edges > MAX_SCHEMA_APPLICATOR_EDGES:
                raise ContractError(
                    f"{context}: JSON Schema exceeds the "
                    f"{MAX_SCHEMA_APPLICATOR_EDGES}-edge applicator limit"
                )
            if keyword == "pattern" and isinstance(child, str):
                if child not in SAFE_SCHEMA_PATTERNS:
                    raise ContractError(f"{context}: unsupported JSON Schema pattern")
            if keyword in {"properties", "$defs", "definitions"} and isinstance(child, dict):
                pending.extend((child_schema, True) for child_schema in child.values())
                continue
            pending.append(
                (
                    child,
                    keyword not in {"const", "enum", "default", "examples", "dependentRequired"},
                )
            )


def _validate_canonical_schemas_before_projection(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
    schema_dir: Path,
) -> None:
    provisional_manifest = copy.deepcopy(manifest)
    provisional_scan = _require_dict(provisional_manifest, "scan", "manifest")
    provisional_scan["artifacts"] = [
        {"path": "findings.json", "sha256": "0" * 64, "mediaType": "application/json"},
        {"path": "coverage.json", "sha256": "0" * 64, "mediaType": "application/json"},
    ]
    validate_against_schema(provisional_manifest, schema_dir / "scan-manifest.schema.json")
    validate_against_schema(findings, schema_dir / "findings.schema.json")
    validate_against_schema(coverage, schema_dir / "coverage.schema.json")


def _validate_contract_refs(scan: dict[str, Any]) -> None:
    for field, expected in (
        ("coverageRef", "coverage.json"),
        ("findingsRef", "findings.json"),
    ):
        actual = _require_str(scan, field, "manifest.scan")
        if actual != expected:
            raise ContractError(f"manifest.scan.{field}: expected {expected!r}")


def _sarif_rule(rule_id: str) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": rule_id},
        "properties": {"tags": ["security"]},
    }


def _utf16_code_units(value: str) -> Iterator[int]:
    encoded = value.encode("utf-16-le")
    for index in range(0, len(encoded), 2):
        yield int.from_bytes(encoded[index : index + 2], "little")


def _github_line_hashes(
    handle: TextIO,
    requested_lines: set[int] | None = None,
    source_read_budget: list[int] | None = None,
) -> dict[int, str] | None:
    if source_read_budget is not None and source_read_budget[0] <= 0:
        return None
    window = [0] * GITHUB_HASH_BLOCK_SIZE
    line_numbers = [-1] * GITHUB_HASH_BLOCK_SIZE
    hash_counts: dict[str, int] = {}
    hashes: dict[int, str] = {}
    first_mod = pow(GITHUB_HASH_MOD, GITHUB_HASH_BLOCK_SIZE, 1 << 64)
    hash_raw = 0
    index = 0
    line_number = 0
    line_start = True
    previous_was_cr = False
    source_bytes = 0

    def output_hash() -> None:
        nonlocal index
        hash_value = format(hash_raw & GITHUB_HASH_MASK, "x")
        hash_counts[hash_value] = hash_counts.get(hash_value, 0) + 1
        line_number = line_numbers[index]
        if requested_lines is None or line_number in requested_lines:
            hashes[line_number] = f"{hash_value}:{hash_counts[hash_value]}"
        line_numbers[index] = -1

    def update_hash(current: int) -> None:
        nonlocal hash_raw, index
        beginning = window[index]
        window[index] = current
        hash_raw = (GITHUB_HASH_MOD * hash_raw + current - first_mod * beginning) & GITHUB_HASH_MASK
        index = (index + 1) % GITHUB_HASH_BLOCK_SIZE

    def process_character(current: int) -> bool:
        nonlocal line_number, line_start, previous_was_cr
        if current in {ord(" "), ord("\t")} or (previous_was_cr and current == ord("\n")):
            previous_was_cr = False
            return True
        if current == ord("\r"):
            current = ord("\n")
            previous_was_cr = True
        else:
            previous_was_cr = False
        if line_numbers[index] != -1:
            output_hash()
        if line_start:
            line_start = False
            line_number += 1
            if line_number > GITHUB_HASH_MAX_LINES:
                return False
            line_numbers[index] = line_number
        if current == ord("\n"):
            line_start = True
        update_hash(current)
        return True

    while chunk := handle.read(SOURCE_READ_CHUNK_SIZE):
        chunk_bytes = len(chunk.encode("utf-8", errors="replace"))
        source_bytes += chunk_bytes
        if source_bytes > SOURCE_READ_MAX_BYTES:
            return None
        if source_read_budget is not None:
            source_read_budget[0] -= chunk_bytes
            if source_read_budget[0] < 0:
                return None
        for code_unit in _utf16_code_units(chunk):
            if not process_character(code_unit):
                return None
    if not process_character(GITHUB_HASH_EOF):
        return None
    for _ in range(GITHUB_HASH_BLOCK_SIZE):
        if line_numbers[index] != -1:
            output_hash()
        update_hash(0)
    return hashes


def _open_source_file(source_root: Path, relative_path: str) -> TextIO | None:
    file_fd: int | None = None
    try:
        file_fd = open_scan_local_file_descriptor(
            source_root, relative_path, f"source file {relative_path}"
        )
        handle = os.fdopen(file_fd, "r", encoding="utf-8", errors="replace")
        file_fd = None
        return handle
    except (ContractError, OSError, ValueError):
        return None
    finally:
        if file_fd is not None:
            os.close(file_fd)


def _github_line_hashes_for_source(
    source_root: Path,
    relative_path: str,
    requested_lines: set[int] | None = None,
    source_read_budget: list[int] | None = None,
) -> dict[int, str] | None:
    handle = _open_source_file(source_root, relative_path)
    if handle is None:
        return None
    try:
        with handle:
            return _github_line_hashes(handle, requested_lines, source_read_budget)
    except OSError:
        return None


def _sarif_primary_location(finding: dict[str, Any]) -> dict[str, Any]:
    return next(
        (location for location in finding["locations"] if location.get("role") == "root_control"),
        finding["locations"][0],
    )


def _sarif_locations(finding: dict[str, Any]) -> list[dict[str, Any]]:
    primary = _sarif_primary_location(finding)
    locations = [
        primary,
        *(location for location in finding["locations"] if location is not primary),
    ]
    locations.extend(
        {
            "path": evidence["path"],
            "startLine": evidence["startLine"],
            "endLine": evidence.get("endLine", evidence["startLine"]),
            "role": f"evidence:{evidence['id']}",
        }
        for evidence in finding.get("codeEvidence", [])
    )
    unique: dict[tuple[str, int, int], dict[str, Any]] = {}
    for location in locations:
        key = (
            location["path"],
            location["startLine"],
            location.get("endLine", location["startLine"]),
        )
        unique.setdefault(key, location)
    return list(unique.values())


def _github_primary_location_line_hash(
    finding: dict[str, Any],
    source_root: Path | None,
    line_hash_cache: dict[tuple[Path, int], str | None] | None = None,
) -> str | None:
    if source_root is None:
        return None
    primary_location = _sarif_primary_location(finding)
    try:
        source_root = source_root.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    relative_path = _require_safe_relative_path(primary_location["path"], "SARIF source location")
    source_path = source_root / relative_path
    start_line = primary_location["startLine"]
    cache_key = (source_path, start_line)
    if line_hash_cache is not None and cache_key in line_hash_cache:
        return line_hash_cache[cache_key]
    line_hashes = _github_line_hashes_for_source(source_root, relative_path, {start_line})
    line_hash = None if line_hashes is None else line_hashes.get(start_line)
    if line_hash_cache is not None:
        line_hash_cache[cache_key] = line_hash
    return line_hash


def _github_line_hash_cache(
    findings: list[dict[str, Any]], source_root: Path | None
) -> dict[tuple[Path, int], str | None]:
    if source_root is None:
        return {}
    try:
        source_root = source_root.resolve(strict=True)
    except (OSError, RuntimeError):
        return {}
    requested_lines_by_path: dict[str, set[int]] = {}
    for finding in findings:
        primary_location = _sarif_primary_location(finding)
        relative_path = _require_safe_relative_path(
            primary_location["path"], "SARIF source location"
        )
        requested_lines_by_path.setdefault(relative_path, set()).add(primary_location["startLine"])
    line_hash_cache: dict[tuple[Path, int], str | None] = {}
    source_read_budget = [SOURCE_READ_MAX_BYTES]
    for relative_path, requested_lines in requested_lines_by_path.items():
        line_hashes = (
            None
            if source_read_budget[0] <= 0
            else _github_line_hashes_for_source(
                source_root, relative_path, requested_lines, source_read_budget
            )
        )
        source_path = source_root / relative_path
        for line_number in requested_lines:
            line_hash_cache[(source_path, line_number)] = (
                None if line_hashes is None else line_hashes.get(line_number)
            )
    return line_hash_cache


def _sarif_location(location: dict[str, Any], location_id: int | None = None) -> dict[str, Any]:
    sarif_location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": quote(location["path"], safe="/"),
            },
            "region": {
                "startLine": location["startLine"],
                "endLine": location.get("endLine", location["startLine"]),
            },
        }
    }
    if location_id is not None:
        sarif_location["id"] = location_id
    if location.get("role"):
        sarif_location["message"] = {"text": location["role"]}
    return sarif_location


def _sarif_result(
    finding: dict[str, Any],
    rule_index: int,
    source_root: Path | None = None,
    line_hash_cache: dict[tuple[Path, int], str | None] | None = None,
) -> dict[str, Any]:
    properties = {
        "category": finding["taxonomy"]["category"],
        "confidence": finding["confidence"]["level"],
        "findingId": finding["findingId"],
        "occurrenceId": finding["occurrenceId"],
        "severity": finding["severity"]["level"],
    }
    extensions = finding.get("extensions")
    candidate_id = extensions.get("candidateId") if isinstance(extensions, dict) else None
    if isinstance(candidate_id, str) and candidate_id:
        properties["candidateId"] = candidate_id
    partial_fingerprints = {
        "copilotSecurity/v1": finding["fingerprints"]["primary"],
    }
    line_hash = _github_primary_location_line_hash(finding, source_root, line_hash_cache)
    if line_hash is not None:
        partial_fingerprints["primaryLocationLineHash"] = line_hash
    result = {
        "ruleId": finding["ruleId"],
        "ruleIndex": rule_index,
        "level": SARIF_LEVELS[finding["severity"]["level"]],
        "message": {"text": finding["summary"]},
        "locations": [_sarif_location(location) for location in _sarif_locations(finding)],
        "partialFingerprints": partial_fingerprints,
        "properties": properties,
    }
    return result


def build_sarif(
    manifest: dict[str, Any], findings: dict[str, Any], source_root: Path | None = None
) -> dict[str, Any]:
    scan = manifest["scan"]
    target = scan["target"]
    ordered_findings = sorted(findings["findings"], key=lambda finding: finding["occurrenceId"])
    findings_by_rule: dict[str, list[dict[str, Any]]] = {}
    for finding in ordered_findings:
        findings_by_rule.setdefault(finding["ruleId"], []).append(finding)
    ordered_rule_ids = sorted(findings_by_rule)
    rule_index = {rule_id: index for index, rule_id in enumerate(ordered_rule_ids)}
    line_hash_cache = _github_line_hash_cache(ordered_findings, source_root)
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Copilot Security",
                "version": scan["producer"]["version"],
                "rules": [_sarif_rule(rule_id) for rule_id in ordered_rule_ids],
            }
        },
        "automationDetails": {"id": scan["id"]},
        "results": [
            _sarif_result(finding, rule_index[finding["ruleId"]], source_root, line_hash_cache)
            for finding in ordered_findings
        ],
        "properties": {
            "copilotSecuritySchemaVersion": manifest["schemaVersion"],
            "copilotSecurityTargetKind": target["kind"],
        },
    }
    if target["kind"] == "git_revision" and target.get("remote") and target.get("revision"):
        run["versionControlProvenance"] = [
            {
                "repositoryUri": target["remote"],
                "revisionId": target["revision"],
            }
        ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def _validate_sarif(sarif: dict[str, Any]) -> None:
    if sarif.get("version") != "2.1.0":
        raise ContractError("SARIF: expected version 2.1.0")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise ContractError("SARIF: expected exactly one run")
    run = runs[0]
    if not isinstance(run, dict):
        raise ContractError("SARIF: expected a run object")
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    for result in run["results"]:
        if result["ruleId"] not in rule_ids:
            raise ContractError("SARIF: result references an unknown rule")
        if not result.get("partialFingerprints"):
            raise ContractError("SARIF: result is missing partialFingerprints")


def _artifact_record(
    scan_dir: Path, relative_path: str, media_type: str, contents: bytes | None = None
) -> dict[str, str]:
    relative_path = _require_safe_relative_path(relative_path, "artifact path")
    if contents is not None:
        _require_scan_local_file(scan_dir, relative_path, relative_path)
    return {
        "mediaType": media_type,
        "path": relative_path,
        "sha256": (
            _sha256_bytes(contents)
            if contents is not None
            else _sha256_scan_local_file(scan_dir, relative_path, relative_path)
        ),
    }


def _coverage_receipt_refs(coverage: dict[str, Any]) -> list[str]:
    refs = {ref for surface in coverage["surfaces"] for ref in surface.get("receiptRefs", [])}
    return sorted(refs)


def _validate_sealed_coverage_receipts(scan: dict[str, Any], coverage: dict[str, Any]) -> None:
    artifact_paths = {
        _require_safe_relative_path(artifact["path"], "sealed artifact path")
        for artifact in scan["artifacts"]
    }
    for ref in _coverage_receipt_refs(coverage):
        if ref not in artifact_paths:
            raise ContractError(f"coverage receipt is missing from sealed artifacts: {ref}")


def _validate_existing_seal(
    scan_dir: Path,
    scan: dict[str, Any],
    *,
    artifact_contents: dict[str, bytes] | None = None,
) -> None:
    sealed_at = scan.get("sealedAt")
    artifacts = scan.get("artifacts")
    if sealed_at is None and artifacts is None:
        return
    if sealed_at != scan.get("completedAt"):
        raise ContractError("manifest.scan.sealedAt: must match completedAt")
    if not isinstance(artifacts, list) or not artifacts:
        raise ContractError("manifest.scan.artifacts: sealed manifest requires artifact records")
    artifact_paths: set[str] = set()
    for index, artifact in enumerate(artifacts):
        context = f"manifest.scan.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise ContractError(f"{context}: expected an object")
        path = _require_safe_relative_path(
            _require_str(artifact, "path", context), f"{context}.path"
        )
        if path in artifact_paths:
            raise ContractError(f"{context}.path: duplicate artifact path")
        artifact_paths.add(path)
        expected_sha256 = _require_str(artifact, "sha256", context)
        contents = (artifact_contents or {}).get(path)
        actual_sha256 = (
            _sha256_bytes(contents)
            if contents is not None
            else _sha256_scan_local_file(scan_dir, path, context)
        )
        if actual_sha256 != expected_sha256:
            raise ContractError(f"{context}: sealed artifact changed or is missing")


def _read_sealed_scan(
    scan_dir: Path, schema_dir: Path | None, required_for: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes]:
    scan_dir = _require_scan_directory(scan_dir)
    schema_dir = schema_dir or Path(__file__).resolve().parent.parent / "schemas"
    manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "scan-manifest.json")
    scan = _require_dict(manifest, "scan", "manifest")
    _validate_contract_refs(scan)
    if scan.get("sealedAt") is None or scan.get("artifacts") is None:
        raise ContractError(f"manifest.scan: {required_for} requires a sealed scan")
    findings, findings_bytes = _read_scan_local_json_bytes(
        scan_dir, scan["findingsRef"], scan["findingsRef"]
    )
    coverage, coverage_bytes = _read_scan_local_json_bytes(
        scan_dir, scan["coverageRef"], scan["coverageRef"]
    )
    _validate_existing_seal(
        scan_dir,
        scan,
        artifact_contents={
            scan["findingsRef"]: findings_bytes,
            scan["coverageRef"]: coverage_bytes,
        },
    )
    _validate_manifest(manifest)
    _validate_findings(manifest, findings)
    _validate_coverage(manifest, coverage, scan_dir)
    _validate_sealed_coverage_receipts(scan, coverage)
    validate_against_schema(manifest, schema_dir / "scan-manifest.schema.json")
    validate_against_schema(findings, schema_dir / "findings.schema.json")
    validate_against_schema(coverage, schema_dir / "coverage.schema.json")
    _validate_derived_finding_identities(manifest, findings)
    return manifest, findings, coverage, findings_bytes


def build_sarif_projection(
    scan_dir: Path, source_root: Path | None = None, schema_dir: Path | None = None
) -> dict[str, Any]:
    if source_root is not None:
        try:
            source_root = source_root.resolve(strict=True)
            source_root_is_directory = source_root.is_dir()
        except (OSError, RuntimeError):
            source_root_is_directory = False
        if not source_root_is_directory:
            raise ContractError("source root: expected an existing directory")
    manifest, findings, coverage, _ = _read_sealed_scan(scan_dir, schema_dir, "SARIF projection")
    sarif = build_sarif(manifest, findings, source_root)
    if coverage["completeness"] != "complete":
        run = sarif["runs"][0]
        run["properties"]["copilotSecurityCoverageCompleteness"] = coverage["completeness"]
        if coverage["deferred"]:
            run["invocations"] = [
                {
                    "executionSuccessful": True,
                    "toolExecutionNotifications": [
                        {"level": "warning", "message": {"text": item["reason"]}}
                        for item in coverage["deferred"]
                    ],
                }
            ]
    _validate_sarif(sarif)
    return sarif


def write_sarif_projection(
    scan_dir: Path, source_root: Path | None = None, schema_dir: Path | None = None
) -> None:
    sarif = build_sarif_projection(scan_dir, source_root, schema_dir)
    _write_scan_local_json(scan_dir, "exports/results.sarif", sarif)


def write_sarif_output(scan_dir: Path, output: Path, sarif: dict[str, Any]) -> None:
    write_export_output(scan_dir, output, "sarif", _json_bytes(sarif))


def csv_cell(value: Any) -> Any:
    if isinstance(value, str) and (
        value.startswith(("\t", "\r", "\n"))
        or value.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠"))
    ):
        return f"'{value}"
    return value


def finding_candidate_id(finding: dict[str, Any]) -> str | None:
    extensions = finding.get("extensions")
    if not isinstance(extensions, dict):
        return None
    return next(
        (
            value
            for field in ("candidateId", "reportId", "ledgerRowId")
            if isinstance(value := extensions.get(field), str) and value.strip()
        ),
        None,
    )


def build_csv_projection(findings: dict[str, Any], coverage: dict[str, Any]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    deep_scan = coverage.get("mode") == "deep_repository" or (
        coverage.get("mode") == "scoped_path"
        and any(
            isinstance(finding.get("extensions"), dict)
            and any(
                isinstance(finding["extensions"].get(field), str)
                and finding["extensions"][field].strip()
                for field in ("candidateId", "reportId")
            )
            for finding in findings["findings"]
        )
    )
    writer.writerow(
        (
            "occurrence_id",
            "finding_id",
            *(("candidate_id",) if deep_scan else ()),
            "title",
            "summary",
            "severity",
            "confidence",
            "status",
            "close_reason",
            "note",
            "remediation",
            "path",
            "start_line",
            "end_line",
        )
    )
    for finding in findings["findings"]:
        locations = finding["locations"]
        location = next(
            (candidate for candidate in locations if candidate.get("role") == "root_control"),
            locations[0],
        )
        writer.writerow(
            (
                csv_cell(finding["occurrenceId"]),
                csv_cell(finding["findingId"]),
                *((csv_cell(finding_candidate_id(finding)),) if deep_scan else ()),
                csv_cell(finding["title"]),
                csv_cell(finding["summary"]),
                csv_cell(finding["severity"]["level"]),
                csv_cell(finding["confidence"]["level"]),
                "open",
                "",
                "",
                csv_cell(finding["remediation"]),
                csv_cell(location["path"]),
                location["startLine"],
                location.get("endLine", location["startLine"]),
            )
        )
    return output.getvalue().encode("utf-8")


def build_findings_export(
    scan_dir: Path,
    export_format: str,
    source_root: Path | None = None,
    schema_dir: Path | None = None,
) -> bytes:
    if export_format not in EXPORT_PATHS:
        raise ContractError(f"unsupported export format: {export_format}")
    if export_format == "sarif":
        return _json_bytes(build_sarif_projection(scan_dir, source_root, schema_dir))
    if source_root is not None:
        raise ContractError("source-root is only supported for SARIF exports")
    _, findings, coverage, findings_bytes = _read_sealed_scan(
        scan_dir, schema_dir, f"{export_format.upper()} export"
    )
    if export_format == "json":
        return findings_bytes
    return build_csv_projection(findings, coverage)


def write_export_output(scan_dir: Path, output: Path, export_format: str, contents: bytes) -> None:
    if export_format not in EXPORT_PATHS:
        raise ContractError(f"unsupported export format: {export_format}")
    scan_dir = _require_scan_directory(scan_dir)
    output = Path(os.path.abspath(output))
    try:
        relative_output = output.relative_to(scan_dir).as_posix()
    except ValueError:
        for ancestor in output.parents:
            try:
                inside_scan = ancestor.samefile(scan_dir)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ContractError(
                    "export output path: unable to inspect output directory"
                ) from exc
            if inside_scan:
                if any(parent.is_symlink() for parent in (ancestor, *ancestor.parents)):
                    raise ContractError(
                        "export output path: symbolic links cannot alias the scan directory"
                    ) from None
                relative_output = output.relative_to(ancestor).as_posix()
                break
        else:
            write_scan_local_bytes(output.parent, output.name, contents, external_name=True)
            return
    if relative_output != EXPORT_PATHS[export_format]:
        raise ContractError(f"{export_format.upper()} output path cannot overwrite a scan artifact")
    manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "scan-manifest.json")
    scan = _require_dict(manifest, "scan", "manifest")
    artifacts = _require_list(scan, "artifacts", "manifest.scan")
    artifact_paths = [
        _require_safe_relative_path(
            _require_str(artifact, "path", f"manifest.scan.artifacts[{index}]"),
            f"manifest.scan.artifacts[{index}].path",
        )
        for index, artifact in enumerate(artifacts)
        if isinstance(artifact, dict)
    ]
    try:
        output_metadata = output.stat(follow_symlinks=False)
    except FileNotFoundError:
        output_metadata = None
    except OSError as exc:
        raise ContractError(f"{relative_output}: unable to inspect export output") from exc
    for artifact_path in artifact_paths:
        if artifact_path == relative_output:
            raise ContractError(
                f"{export_format.upper()} output path cannot overwrite a sealed scan artifact"
            )
        if output_metadata is None:
            continue
        descriptor = open_scan_local_file_descriptor(
            scan_dir, artifact_path, f"sealed artifact {artifact_path}"
        )
        try:
            artifact_metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if os.path.samestat(output_metadata, artifact_metadata):
            raise ContractError(
                f"{export_format.upper()} output path cannot overwrite a sealed scan artifact"
            )
    write_scan_local_bytes(scan_dir, relative_output, contents)


def _write_sarif_projection_if_possible(
    scan_dir: Path, source_root: Path | None = None, schema_dir: Path | None = None
) -> None:
    try:
        write_sarif_projection(scan_dir, source_root, schema_dir)
    except (ContractError, OSError) as error:
        print(
            f"copilot-security: warning: automatic SARIF export failed: {error}. "
            "Run `copilot-security export <scan-dir> --export-format sarif` to retry.",
            file=sys.stderr,
        )


PreparedScanFinalization = tuple[
    Path,
    Path,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    bool,
    bytes,
]


def _standalone_slug(value: Any, fallback: str) -> str:
    source = value if isinstance(value, str) else ""
    normalized = re.sub(r"[^a-z0-9._/-]+", "-", source.lower()).strip("._/-")
    normalized = normalized[:160].rstrip("._/-")
    return normalized if SLUG_RE.fullmatch(normalized) else fallback


def _normalize_standalone_manifest_draft(
    manifest: Any,
    completion_binding: dict[str, Any] | None,
) -> tuple[dict[str, Any], bool]:
    """Accept the compact draft a Copilot turn may emit and add the canonical envelope."""

    if not isinstance(manifest, dict):
        raise ContractError("scan-manifest.json: expected an object")
    existing_scan = manifest.get("scan")
    if isinstance(existing_scan, dict):
        changed = False
        if (
            completion_binding is not None
            and "threatModel" in existing_scan
            and not isinstance(existing_scan.get("threatModel"), dict)
            and existing_scan.get("sealedAt") is None
            and not isinstance(existing_scan.get("artifacts"), list)
        ):
            # The detailed threat model is already a sealed scan-local artifact.
            # Copilot sometimes writes that artifact path into the optional
            # structured summary field. Drop only the malformed optional draft
            # value; never rewrite a previously sealed manifest.
            existing_scan.pop("threatModel", None)
            changed = True
        if not isinstance(existing_scan.get("target"), dict):
            top_level_target = manifest.get("target")
            existing_scan["target"] = (
                copy.deepcopy(top_level_target)
                if isinstance(top_level_target, dict)
                else {}
            )
            changed = True
        if not isinstance(existing_scan.get("scope"), dict):
            existing_scan["scope"] = {}
            changed = True
        if completion_binding is not None:
            allowed_kinds = completion_binding.get("allowedTargetKinds")
            allowed_kinds = allowed_kinds if isinstance(allowed_kinds, list) else []
            target = existing_scan["target"]
            if isinstance(target, dict) and target.get("kind") not in allowed_kinds:
                target["kind"] = (
                    allowed_kinds[0] if allowed_kinds else "directory_snapshot"
                )
                changed = True
        return manifest, changed
    if completion_binding is None:
        return manifest, False

    target = manifest.get("target")
    target = copy.deepcopy(target) if isinstance(target, dict) else {}
    allowed_kinds = completion_binding.get("allowedTargetKinds")
    allowed_kinds = allowed_kinds if isinstance(allowed_kinds, list) else []
    if target.get("kind") not in allowed_kinds:
        target["kind"] = allowed_kinds[0] if allowed_kinds else "directory_snapshot"

    scan: dict[str, Any] = {
        "target": target,
        "scope": {},
    }
    threat_model = manifest.get("threatModel")
    if isinstance(threat_model, dict):
        scan["threatModel"] = copy.deepcopy(threat_model)
    return {"scan": scan}, True


def _standalone_taxonomy(finding: dict[str, Any]) -> tuple[str, list[str]]:
    taxonomy = finding.get("taxonomy")
    category = taxonomy.get("category") if isinstance(taxonomy, dict) else None
    text = " ".join(
        [
            *(
                str(finding.get(field, ""))
                for field in ("title", "description", "summary", "evidence")
            ),
            str(category or ""),
        ]
    ).lower()
    if (
        "authorization cache" in text
        or "authorization-cache" in text
        or "tenant cache key" in text
        or "tenant-cache" in text
        or "cross-tenant cache" in text
        or "cache key omits tenant" in text
        or "cache key omits principal" in text
        or (
            "application cache" in text
            and ("cross-tenant" in text or "cross-principal" in text)
            and ("cache hit" in text or "cached object" in text)
        )
    ):
        return "authorization-cache-key-confusion", ["CWE-524", "CWE-862"]
    if (
        "web cache deception" in text
        or "web-cache-deception" in text
        or (
            "shared cache" in text
            and ("authenticated response" in text or "private response" in text)
            and ("credential-free" in text or "unauthenticated" in text)
        )
    ):
        # CWE-525 is specific to browser caches. Cross-principal edge, CDN,
        # proxy, or application shared caches use the broader CWE-524.
        return "web-cache-deception", ["CWE-524", "CWE-200"]
    if (
        "graphql" in text
        and (
            "operation amplification" in text
            or "alias amplification" in text
            or "aliases" in text
            or "aliased" in text
            or "resolver amplification" in text
            or "resolver calls" in text
            or "verifyrecoverycode" in text
            or "selection fan-out" in text
            or "selections bypass" in text
            or "unbounded selections" in text
            or ("unbounded" in text and "selections" in text)
        )
        and (
            "rate limit" in text
            or "quota" in text
            or "attempt" in text
            or "recovery code" in text
            or "recovery-code" in text
            or "mfa" in text
            or "one request" in text
        )
    ):
        # CWE-307 captures the defeated authentication-attempt restriction;
        # CWE-799 captures the transport-to-resolver interaction-frequency gap.
        return "graphql-operation-amplification", ["CWE-307", "CWE-799"]
    if (
        ("webhook" in text or "signed callback" in text)
        and (
            "capture-replay" in text
            or "capture replay" in text
            or "replay" in text
            or "duplicate delivery" in text
            or "processed repeatedly" in text
        )
        and (
            "hmac" in text
            or "signature" in text
            or "signed" in text
        )
        and (
            "credit" in text
            or "payment" in text
            or "financial" in text
            or "protected effect" in text
            or "state-changing" in text
        )
    ):
        return "signed-webhook-replay", ["CWE-294"]
    if (
        "jwt" in text
        and (
            "algorithm confusion" in text
            or "algorithm-confusion" in text
            or "algorithm/key-type confusion" in text
            or "algorithm key type confusion" in text
            or "public-key-as-hmac" in text
            or "public key as hmac" in text
            or (
                ("hs256" in text or "hmac" in text)
                and (
                    "rs256" in text
                    or "rsa public key" in text
                    or "public key" in text
                )
            )
        )
    ):
        return "jwt-algorithm-key-confusion", ["CWE-347"]
    if (
        ("oidc" in text or "id token" in text or "id-token" in text)
        and (
            "sibling client" in text
            or "sibling-client" in text
            or "cross-client" in text
            or "wrong audience" in text
            or "wrong-audience" in text
            or "foreign azp" in text
            or "missing audience" in text
            or "audience misbinding" in text
            or "nonce misbinding" in text
            or "not bound to its client" in text
            or "client and transaction binding" in text
            or (
                (
                    "never validates" in text
                    or "does not check" in text
                    or "omits" in text
                )
                and "aud" in text
                and "azp" in text
                and "nonce" in text
            )
        )
        and (
            "aud" in text
            or "azp" in text
            or "audience" in text
            or "nonce" in text
        )
        and (
            "session" in text
            or "login" in text
            or "account" in text
            or "principal" in text
            or "authentication" in text
        )
    ):
        return "oidc-id-token-binding", ["CWE-287", "CWE-345"]
    if (
        re.search(r"\bredos\b", text)
        or "regular expression denial of service" in text
        or "regular-expression denial of service" in text
        or "catastrophic backtracking" in text
        or (
            ("regex" in text or "regular expression" in text)
            and (
                "backtracking" in text
                or "superlinear" in text
                or "exponential" in text
            )
            and (
                "denial" in text
                or "event loop" in text
                or "timeout" in text
                or "worker" in text
            )
        )
    ):
        return "regular-expression-denial-of-service", ["CWE-1333"]
    if (
        (
            "dns rebinding" in text
            or "dns-rebinding" in text
            or "dns rebind" in text
            or (
                ("resolves again" in text or "second dns" in text)
                and ("connect" in text or "request" in text)
            )
        )
        and (
            "metadata" in text
            or "private address" in text
            or "private ip" in text
            or "internal address" in text
            or "link-local" in text
            or "169.254.169.254" in text
        )
        and (
            "request" in text
            or "fetch" in text
            or "http client" in text
            or "transport" in text
        )
    ):
        return "dns-rebinding-ssrf", ["CWE-918"]
    if (
        (
            "fail open" in text
            or "fail-open" in text
            or "fails open" in text
            or "default allow" in text
            or "defaults to allow" in text
            or (
                ("policy" in text or "authorizer" in text or "entitlement" in text)
                and ("exception" in text or "unavailable" in text)
                and ("bypass" in text or "grants" in text or "allows" in text)
            )
        )
        and (
            "authorization" in text
            or "authorizer" in text
            or "access decision" in text
            or "permission" in text
            or "policy" in text
            or "entitlement" in text
        )
        and (
            "error" in text
            or "exception" in text
            or "timeout" in text
            or "unavailable" in text
            or "malformed" in text
            or "fallback" in text
        )
    ):
        return "fail-open-authorization", ["CWE-636", "CWE-863"]
    if isinstance(taxonomy, dict):
        cwe = taxonomy.get("cwe")
        normalized_cwe = (
            [
                item for item in cwe if isinstance(item, str) and item.strip()
            ]
            if isinstance(cwe, list)
            else []
        )
        if isinstance(category, str) and category.strip() and normalized_cwe:
            return category.strip(), normalized_cwe

    if (
        "command injection" in text
        or re.search(r"\bchild_process\.exec(?!file)\b", text)
        or "shell command" in text
    ):
        return "command-injection", ["CWE-78"]
    if (
        "ssrf" in text
        or "server-side request forgery" in text
        or "network probing" in text
        or "internal host" in text
    ):
        return "server-side-request-forgery", ["CWE-918"]
    if "sql injection" in text or "sqli" in text:
        return "sql-injection", ["CWE-89"]
    if (
        "unsafe deserialization" in text
        or "insecure deserialization" in text
        or "pickle.loads" in text
        or "objectinputstream" in text
    ):
        return "unsafe-deserialization", ["CWE-502"]
    if (
        "prototype pollution" in text
        or "__proto__" in text
        or (
            "object prototype" in text
            and (
                "attacker" in text
                or "computed property" in text
                or "mutation" in text
                or "pollution" in text
            )
        )
    ):
        return "prototype-pollution", ["CWE-1321"]
    if (
        "cross-site scripting" in text
        or "cross site scripting" in text
        or re.search(r"\b(?:reflected|stored|dom)[ -]?xss\b", text)
        or re.search(r"\bxss\b", text)
    ):
        return "cross-site-scripting", ["CWE-79"]
    if (
        "xml external entity" in text
        or "external xml entity" in text
        or re.search(r"\bxxe\b", text)
    ):
        return "xml-external-entity", ["CWE-611"]
    if (
        (
            "certificate verification" in text
            and (
                "disabled" in text
                or "bypass" in text
                or "false" in text
                or "missing" in text
            )
        )
        or "rejectunauthorized=false" in text
        or "verify=false" in text
        or "ssl.cert_none" in text
    ):
        return "improper-certificate-validation", ["CWE-295"]
    if (
        "signature verification" in text
        or "signature validation" in text
        or "unverified jwt" in text
        or "unsigned jwt" in text
        or "jwt" in text
        and (
            "auth" in text
            or "decode" in text
            or "signature" in text
            or "token" in text
            or "verify" in text
        )
    ):
        return "improper-signature-verification", ["CWE-347"]
    if (
        "path traversal" in text
        or "archive" in text
        and ("escape" in text or "containment" in text)
    ):
        return "path-traversal", ["CWE-22"]
    if (
        "idor" in text
        or "object authorization" in text
        or "ownership" in text
        or "owner check" in text
    ):
        return "broken-object-authorization", ["CWE-639", "CWE-862"]
    return "security-defect", []


def _standalone_location_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    source = value.strip()
    repository = os.environ.get("COPILOT_SECURITY_REPOSITORY")
    if repository and os.path.isabs(source):
        try:
            relative = os.path.relpath(source, repository)
            if (
                relative != os.pardir
                and not relative.startswith(os.pardir + os.sep)
                and not os.path.isabs(relative)
            ):
                return PurePosixPath(Path(relative)).as_posix()
        except (OSError, ValueError):
            pass
    normalized = source.replace("\\", "/")
    marker = "/repository/"
    if marker in normalized.lower():
        position = normalized.lower().rfind(marker)
        normalized = normalized[position + len(marker) :]
    if re.match(r"^[A-Za-z]:/", normalized) or normalized.startswith("/"):
        return None
    normalized = PurePosixPath(normalized).as_posix()
    if normalized in {"", "."} or normalized == ".." or normalized.startswith("../"):
        return None
    return normalized


def _standalone_finding_is_non_vulnerability(finding: dict[str, Any]) -> bool:
    """Recognize explicit Copilot conclusions that must not become findings."""

    validation = finding.get("validation")
    if isinstance(validation, dict):
        if validation.get("exploitable") is False or validation.get("vulnerable") is False:
            return True
        negative_values = {
            "accepted risk",
            "defense in depth",
            "defense-in-depth",
            "false positive",
            "false-positive",
            "informational",
            "mitigated",
            "no issue",
            "no issue found",
            "no-issue",
            "not exploitable",
            "not vulnerable",
            "not-exploitable",
            "not-vulnerable",
            "not applicable",
            "rejected",
            "safe",
        }
        for field in ("status", "verdict", "disposition", "result"):
            value = validation.get(field)
            if (
                isinstance(value, str)
                and value.strip().lower().replace("_", " ") in negative_values
            ):
                return True
    return False


def _standalone_location(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    path = _standalone_location_path(
        raw.get(
            "path",
            raw.get("file", raw.get("filePath", raw.get("filename"))),
        )
    )
    start = raw.get(
        "startLine",
        raw.get(
            "start_line",
            raw.get("line", raw.get("lineNumber", raw.get("line_number"))),
        ),
    )
    end = raw.get(
        "endLine",
        raw.get("end_line", raw.get("endLineNumber", raw.get("end_line_number", start))),
    )
    if path is None:
        return None
    if not isinstance(start, int) or isinstance(start, bool) or start < 1:
        return None
    if not isinstance(end, int) or isinstance(end, bool) or end < start:
        end = start
    return {
        "path": path,
        "startLine": start,
        "endLine": end,
        "role": raw.get("role", "sink"),
    }


def _standalone_source_evidence(
    location: dict[str, Any],
    summary: str,
) -> dict[str, Any] | None:
    repository_value = os.environ.get("COPILOT_SECURITY_REPOSITORY")
    if not repository_value:
        return None
    repository = Path(repository_value).resolve()
    candidate = (repository / location["path"]).resolve()
    try:
        candidate.relative_to(repository)
        metadata = candidate.lstat()
    except (OSError, ValueError):
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or candidate.is_symlink()
        or metadata.st_size > 1024 * 1024
    ):
        return None
    try:
        lines = candidate.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    start = location["startLine"]
    end = min(location["endLine"], start + 40)
    if start > len(lines):
        return None
    code = "\n".join(lines[start - 1 : min(end, len(lines))]).strip()
    if not code:
        return None
    return {
        "id": "primary-code-evidence",
        "label": "Primary security-relevant operation",
        "path": location["path"],
        "startLine": start,
        "endLine": min(end, len(lines)),
        "role": location.get("role", "sink"),
        "code": code,
        "explanation": summary,
    }


def _normalize_standalone_finding(
    finding: Any,
    index: int,
) -> dict[str, Any] | None:
    if not isinstance(finding, dict):
        return finding
    if _standalone_finding_is_non_vulnerability(finding):
        return None
    raw_locations = finding.get("locations")
    locations_are_canonical = (
        isinstance(raw_locations, list)
        and bool(raw_locations)
        and all(
            isinstance(location, dict)
            and isinstance(location.get("path"), str)
            and _standalone_location_path(location.get("path")) == location.get("path")
            and isinstance(location.get("startLine"), int)
            and not isinstance(location.get("startLine"), bool)
            and location.get("startLine") >= 1
            for location in raw_locations
        )
    )
    raw_code_evidence = finding.get("codeEvidence")
    evidence_is_canonical = raw_code_evidence is None or (
        isinstance(raw_code_evidence, list)
        and all(
            isinstance(evidence, dict)
            and all(
                isinstance(evidence.get(field), str) and bool(evidence.get(field).strip())
                for field in ("id", "label", "path", "code", "explanation")
            )
            and isinstance(evidence.get("startLine"), int)
            and not isinstance(evidence.get("startLine"), bool)
            for evidence in raw_code_evidence
        )
    )
    has_canonical_envelope = any(
        field in finding for field in ("findingId", "occurrenceId", "fingerprints")
    )
    if (
        has_canonical_envelope
        and isinstance(raw_locations, list)
        and any(
            not isinstance(location, dict)
            or _standalone_location_path(location.get("path")) is None
            for location in raw_locations
        )
    ):
        # Do not turn an unsafe or malformed canonical path into a compact
        # recovery. The established validator will skip it with a precise
        # warning. Absolute paths inside the authoritative repository remain
        # recoverable because they normalize to a safe relative path.
        return finding
    if (
        locations_are_canonical
        and isinstance(finding.get("severity"), dict)
        and isinstance(finding.get("confidence"), dict)
        and isinstance(finding.get("taxonomy"), dict)
        and isinstance(finding.get("provenance"), dict)
        and evidence_is_canonical
        and has_canonical_envelope
    ):
        category, cwe = _standalone_taxonomy(finding)
        existing_taxonomy = finding.get("taxonomy")
        existing_cwe = (
            existing_taxonomy.get("cwe")
            if isinstance(existing_taxonomy, dict)
            else None
        )
        existing_category = (
            existing_taxonomy.get("category")
            if isinstance(existing_taxonomy, dict)
            else None
        )
        normalized_existing_category = (
            existing_category.strip()
            if isinstance(existing_category, str)
            else ""
        )
        normalized_existing_cwe = (
            [
                item
                for item in existing_cwe
                if isinstance(item, str) and item.strip()
            ]
            if isinstance(existing_cwe, list)
            else []
        )
        if cwe and (
            normalized_existing_cwe != cwe
            or normalized_existing_category != category
        ):
            recovered = copy.deepcopy(finding)
            recovered["taxonomy"] = {"category": category, "cwe": cwe}
            return recovered
        return finding

    title = finding.get("title")
    title = title.strip() if isinstance(title, str) and title.strip() else f"Security finding {index + 1}"
    summary = finding.get("summary", finding.get("description"))
    summary = (
        summary.strip()
        if isinstance(summary, str) and summary.strip()
        else "The scan identified a security-relevant data flow requiring remediation."
    )
    category, cwe = _standalone_taxonomy(finding)
    candidate_id = finding.get("id")
    anchor = _standalone_slug(candidate_id or title, f"finding-{index + 1}")
    rule_id = _standalone_slug(finding.get("ruleId") or category, "security-defect")

    raw_location = finding.get("location")
    if isinstance(raw_locations, list) and raw_locations:
        location_rows = raw_locations
    elif isinstance(raw_locations, dict):
        location_rows = [raw_locations]
    else:
        location_rows = [
            raw_location,
            finding,
            *(finding.get("codeEvidence") if isinstance(finding.get("codeEvidence"), list) else []),
        ]
    locations: list[dict[str, Any]] = []
    location_keys: set[tuple[str, int, int]] = set()
    for raw in location_rows:
        location = _standalone_location(raw)
        if location is None:
            continue
        key = (
            location["path"],
            location["startLine"],
            location["endLine"],
        )
        if key not in location_keys:
            location_keys.add(key)
            locations.append(location)

    severity = finding.get("severity")
    severity_value = severity.get("level") if isinstance(severity, dict) else severity
    severity_level = (
        severity_value.lower() if isinstance(severity_value, str) else "medium"
    )
    if severity_level not in SEVERITIES:
        severity_level = "medium"
    confidence = finding.get("confidence")
    confidence_value = (
        confidence.get("level") if isinstance(confidence, dict) else confidence
    )
    confidence_level = (
        confidence_value.lower() if isinstance(confidence_value, str) else "medium"
    )
    if confidence_level not in CONFIDENCES:
        confidence_level = "medium"

    code_evidence = []
    raw_code_evidence = finding.get("codeEvidence")
    if isinstance(raw_code_evidence, list):
        for evidence_index, raw in enumerate(raw_code_evidence):
            if not isinstance(raw, dict):
                continue
            path = _standalone_location_path(
                raw.get(
                    "path",
                    raw.get("file", raw.get("filePath", raw.get("filename"))),
                )
            )
            start = raw.get("startLine", raw.get("start_line"))
            end = raw.get("endLine", raw.get("end_line", start))
            code = raw.get("code", raw.get("snippet"))
            if (
                path is None
                or not isinstance(start, int)
                or isinstance(start, bool)
                or start < 1
                or not isinstance(code, str)
                or not code.strip()
            ):
                continue
            if not isinstance(end, int) or isinstance(end, bool) or end < start:
                end = start
            code_evidence.append(
                {
                    "id": _standalone_slug(
                        raw.get("id"), f"code-evidence-{evidence_index + 1}"
                    ),
                    "label": (
                        raw["label"].strip()
                        if isinstance(raw.get("label"), str)
                        and raw["label"].strip()
                        else "Security-relevant operation"
                    ),
                    "path": path,
                    "startLine": start,
                    "endLine": end,
                    "role": raw.get("role", "sink"),
                    "code": code.strip(),
                    "explanation": (
                        raw["explanation"].strip()
                        if isinstance(raw.get("explanation"), str)
                        and raw["explanation"].strip()
                        else summary
                    ),
                }
            )
    evidence = finding.get("evidence")
    if not code_evidence and isinstance(evidence, str) and evidence.strip() and locations:
        code_evidence.append(
            {
                "id": "primary-code-evidence",
                "label": "Primary vulnerable operation",
                "path": locations[0]["path"],
                "startLine": locations[0]["startLine"],
                "endLine": locations[0]["endLine"],
                "role": locations[0]["role"],
                "code": evidence.strip(),
                "explanation": summary,
            }
        )
    if not code_evidence and locations:
        recovered_evidence = _standalone_source_evidence(locations[0], summary)
        if recovered_evidence is not None:
            code_evidence.append(recovered_evidence)

    remediation = finding.get("remediation")
    remediation = (
        remediation.strip()
        if isinstance(remediation, str) and remediation.strip()
        else "Remove the vulnerable data flow and add a regression test for the affected control."
    )
    raw_attack_path = finding.get("attackPath", finding.get("attack_path"))
    normalized: dict[str, Any] = {
        "findingId": "draft",
        "occurrenceId": "draft",
        "ruleId": rule_id,
        "identity": {"anchor": anchor},
        "fingerprints": {
            "algorithm": FINGERPRINT_ALGORITHM,
            "primary": f"{FINGERPRINT_ALGORITHM}:sha256:" + "0" * 64,
        },
        "title": title,
        "summary": summary,
        "severity": {
            "level": severity_level,
            "rationale": summary,
        },
        "confidence": {
            "level": confidence_level,
            "rationale": summary,
        },
        "taxonomy": {"category": category, "cwe": cwe},
        "locations": locations,
        "remediation": remediation,
        "validation": (
            copy.deepcopy(finding["validation"])
            if isinstance(finding.get("validation"), dict)
            else None
        ),
        "attackPath": (
            copy.deepcopy(raw_attack_path)
            if isinstance(raw_attack_path, dict)
            else None
        ),
        "provenance": {"source": "local_plugin"},
        "extensions": {},
    }
    if code_evidence:
        normalized["codeEvidence"] = code_evidence
    if isinstance(candidate_id, str) and candidate_id.strip():
        normalized["extensions"]["candidateId"] = candidate_id.strip()
    return normalized


def _normalize_standalone_findings_draft(findings: Any) -> tuple[dict[str, Any], bool]:
    simplified_container = isinstance(findings, list)
    if simplified_container:
        findings = {"findings": findings}
    elif not isinstance(findings, dict):
        raise ContractError("findings.json: expected an object")
    rows = findings.get("findings")
    if not isinstance(rows, list):
        return findings, False
    normalized = [
        _normalize_standalone_finding(finding, index)
        for index, finding in enumerate(rows)
    ]
    converted = [
        after
        for before, after in zip(rows, normalized)
        if not (isinstance(before, dict) and after is None)
    ]
    changed = len(converted) != len(rows) or any(
        before is not after
        for before, after in zip(rows, normalized)
        if after is not None
    )
    if not changed:
        return findings, simplified_container
    return {"findings": converted}, True


def _normalize_standalone_coverage_draft(
    coverage: Any,
    completion_binding: dict[str, Any] | None,
) -> tuple[dict[str, Any], bool]:
    if isinstance(coverage, dict):
        if coverage.get("documentType") == "copilot-security.coverage":
            # A malformed canonical document belongs to the established
            # recovery path below, which preserves its per-field warnings.
            return coverage, False
        existing_surfaces = coverage.get("surfaces")
        if (
            isinstance(existing_surfaces, list)
            and all(
                isinstance(surface, dict)
                and isinstance(surface.get("id"), str)
                and isinstance(surface.get("label"), str)
                and isinstance(surface.get("disposition"), str)
                and isinstance(surface.get("receiptRefs"), list)
                for surface in existing_surfaces
            )
            and isinstance(coverage.get("completeness"), str)
            and isinstance(coverage.get("inventoryStrategy"), str)
        ):
            return coverage, False
        rows = existing_surfaces
    else:
        rows = coverage
    if not isinstance(rows, list) or completion_binding is None:
        raise ContractError("coverage.json: expected an object")

    surfaces = []
    deferred = []
    used_ids: set[str] = set()
    disposition_map = {
        "candidate_found": "reported",
        "candidate": "reported",
        "confirmed": "reported",
        "finding": "reported",
        "reported": "reported",
        "vulnerable": "reported",
        "no_finding": "no_issue_found",
        "no_findings": "no_issue_found",
        "no_exploitable_finding": "no_issue_found",
        "no_exploitable_findings": "no_issue_found",
        "reviewed": "no_issue_found",
        "reviewed_clean": "no_issue_found",
        "reviewed_safe": "no_issue_found",
        "reviewed_no_issue": "no_issue_found",
        "reviewed_no_issues": "no_issue_found",
        "reviewed_no_finding": "no_issue_found",
        "reviewed_no_findings": "no_issue_found",
        "reviewed_no_exploitable_finding": "no_issue_found",
        "reviewed_no_exploitable_findings": "no_issue_found",
        "reviewed_no_candidate": "no_issue_found",
        "reviewed_no_candidates": "no_issue_found",
        "no_candidate": "no_issue_found",
        "no_candidates": "no_issue_found",
        "safe": "no_issue_found",
        "clean": "no_issue_found",
        "no_issue_found": "no_issue_found",
        "rejected": "rejected",
        "not_applicable": "not_applicable",
        "deferred": "needs_follow_up",
        "needs_follow_up": "needs_follow_up",
    }
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        raw_path = row.get("path")
        path = _standalone_location_path(raw_path)
        label = path if path is not None else f"Surface {index + 1}"
        surface_id = _standalone_slug(label, f"surface-{index + 1}")
        while surface_id in used_ids:
            surface_id = f"{surface_id}-{index + 1}"
        used_ids.add(surface_id)
        disposition = "needs_follow_up"
        for outcome in (
            row.get("outcome"),
            row.get("disposition"),
            row.get("status"),
        ):
            token = (
                re.sub(r"[\s-]+", "_", outcome.strip().lower())
                if isinstance(outcome, str)
                else None
            )
            if token in disposition_map:
                disposition = disposition_map[token]
                break
        notes = row.get("notes", row.get("rationale", row.get("reason")))
        if disposition == "needs_follow_up" and isinstance(notes, str):
            notes_token = notes.strip().lower()
            if any(
                phrase in notes_token
                for phrase in (
                    "no direct findings",
                    "no exploitable finding",
                    "no exploitable issue",
                    "no finding",
                    "no issue found",
                )
            ):
                disposition = "no_issue_found"
        surface = {
            "id": surface_id,
            "label": label,
            "disposition": disposition,
            "receiptRefs": [],
        }
        if isinstance(notes, str) and notes.strip():
            surface["notes"] = notes.strip()
        surfaces.append(surface)
        if disposition == "needs_follow_up":
            deferred.append(
                {
                    "id": surface_id,
                    "reason": (
                        notes.strip()
                        if isinstance(notes, str) and notes.strip()
                        else "The scan did not close this review surface."
                    ),
                    **({"paths": [path]} if path is not None else {}),
                    "surfaceIds": [surface_id],
                }
            )

    mode = completion_binding.get("coverageMode")
    inventory_strategy = (
        "repository"
        if mode in {"repository", "deep_repository"}
        else "scoped_path"
        if mode == "scoped_path"
        else "diff"
    )
    return {
        "completeness": "partial" if deferred else "complete",
        "inventoryStrategy": inventory_strategy,
        "surfaces": surfaces,
        "explicitExclusions": [],
        "deferred": deferred,
    }, True


def _standalone_notes_close_review(notes: Any) -> bool:
    if not isinstance(notes, str):
        return False
    token = notes.strip().lower()
    return any(
        phrase in token
        for phrase in (
            "documentation reviewed",
            "no code paths to validate",
            "repository metadata",
            "used readme to confirm",
        )
    )


def _reconcile_standalone_coverage_with_findings(
    coverage: dict[str, Any],
    findings: dict[str, Any],
) -> None:
    finding_paths = {
        location.get("path")
        for finding in findings.get("findings", [])
        if isinstance(finding, dict)
        for location in finding.get("locations", [])
        if isinstance(location, dict) and isinstance(location.get("path"), str)
    }
    reported_surface_ids: set[str] = set()
    closed_surface_ids: set[str] = set()
    for surface in coverage.get("surfaces", []):
        if not isinstance(surface, dict):
            continue
        label = surface.get("label")
        if label in finding_paths:
            surface["disposition"] = "reported"
            surface_id = surface.get("id")
            if isinstance(surface_id, str):
                reported_surface_ids.add(surface_id)
        elif (
            surface.get("disposition") == "needs_follow_up"
            and _standalone_notes_close_review(surface.get("notes"))
        ):
            surface["disposition"] = "no_issue_found"
            surface_id = surface.get("id")
            if isinstance(surface_id, str):
                closed_surface_ids.add(surface_id)
        elif not finding_paths and surface.get("disposition") == "reported":
            # Compact drafts sometimes promote rejected observations into
            # findings and mirror them into coverage. Once filtered, those
            # reviewed surfaces carry no reportable issue.
            surface["disposition"] = "no_issue_found"
    deferred = coverage.get("deferred")
    reconciled_surface_ids = reported_surface_ids | closed_surface_ids
    if isinstance(deferred, list) and reconciled_surface_ids:
        retained = []
        for row in deferred:
            if not isinstance(row, dict):
                retained.append(row)
                continue
            surface_ids = row.get("surfaceIds")
            surface_ids = surface_ids if isinstance(surface_ids, list) else []
            if (
                row.get("id") not in reconciled_surface_ids
                and not reconciled_surface_ids.intersection(surface_ids)
            ):
                retained.append(row)
        coverage["deferred"] = retained
    if (
        not coverage.get("deferred")
        and all(
            not isinstance(surface, dict)
            or surface.get("disposition") != "needs_follow_up"
            for surface in coverage.get("surfaces", [])
        )
    ):
        coverage["completeness"] = "complete"


def _read_in_scope_inventory(scan_dir: Path) -> list[str]:
    relative_path = "artifacts/02_discovery/in_scope_files.txt"
    inventory_path = scan_dir / PurePosixPath(relative_path)
    if not inventory_path.exists() and not inventory_path.is_symlink():
        return []
    descriptor = open_scan_local_file_descriptor(
        scan_dir, relative_path, "in-scope file inventory"
    )
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size > IN_SCOPE_INVENTORY_MAX_BYTES:
            raise ContractError(
                "in-scope file inventory: exceeds the deterministic size limit"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(IN_SCOPE_INVENTORY_MAX_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > IN_SCOPE_INVENTORY_MAX_BYTES:
        raise ContractError(
            "in-scope file inventory: exceeds the deterministic size limit"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("in-scope file inventory: expected UTF-8 paths") from exc
    paths: list[str] = []
    seen: set[str] = set()
    for index, line in enumerate(text.splitlines()):
        candidate = line.strip()
        if not candidate:
            continue
        normalized = _require_safe_relative_path(
            candidate, f"in-scope file inventory line {index + 1}"
        )
        if normalized not in seen:
            paths.append(normalized)
            seen.add(normalized)
    return paths


def _reconcile_coverage_with_inventory(
    coverage: dict[str, Any],
    scan_dir: Path,
    completion_warnings: list[str] | None,
) -> None:
    inventory_paths = _read_in_scope_inventory(scan_dir)
    if not inventory_paths:
        return
    surfaces = coverage.get("surfaces")
    deferred = coverage.get("deferred")
    if not isinstance(surfaces, list) or not isinstance(deferred, list):
        return
    covered_paths = {
        surface.get("label")
        for surface in surfaces
        if isinstance(surface, dict)
        and isinstance(surface.get("label"), str)
    }
    missing_paths = [path for path in inventory_paths if path not in covered_paths]
    if not missing_paths:
        return

    used_ids = {
        surface.get("id")
        for surface in surfaces
        if isinstance(surface, dict) and isinstance(surface.get("id"), str)
    }
    for index, path in enumerate(missing_paths, start=1):
        base_id = _standalone_slug(path, f"coverage-gap-{index}")
        surface_id = base_id
        suffix = 2
        while surface_id in used_ids:
            surface_id = f"{base_id}-{suffix}"
            suffix += 1
        used_ids.add(surface_id)
        surfaces.append(
            {
                "id": surface_id,
                "label": path,
                "disposition": "needs_follow_up",
                "receiptRefs": [],
                "notes": (
                    "The immutable in-scope inventory contained this path, but "
                    "the scan did not provide a file-review closure."
                ),
            }
        )
        deferred.append(
            {
                "id": f"inventory-gap-{surface_id}",
                "reason": (
                    "Missing file-review closure for a path in the immutable "
                    "in-scope inventory."
                ),
                "paths": [path],
                "surfaceIds": [surface_id],
            }
        )
    coverage["completeness"] = "partial"
    if completion_warnings is not None:
        warning = (
            "Downgraded coverage to partial because "
            f"{len(missing_paths)} in-scope inventory "
            f"{'path lacks' if len(missing_paths) == 1 else 'paths lack'} "
            "a file-review closure."
        )
        if warning not in completion_warnings:
            completion_warnings.append(warning)


def _prepare_scan_finalization(
    scan_dir: Path,
    schema_dir: Path | None = None,
    *,
    expected_coverage_mode: str | None = None,
    completion_binding: dict[str, Any] | None = None,
    completion_warnings: list[str] | None = None,
) -> PreparedScanFinalization:
    """Read, populate, and validate a scan without writing any output files."""

    scan_dir = _require_scan_directory(scan_dir)
    schema_dir = schema_dir or Path(__file__).resolve().parent.parent / "schemas"
    manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "scan-manifest.json")
    manifest, simplified_manifest = _normalize_standalone_manifest_draft(
        manifest, completion_binding
    )
    scan = _require_dict(manifest, "scan", "manifest")
    was_sealed = scan.get("sealedAt") is not None or isinstance(
        scan.get("artifacts"), list
    )
    if not was_sealed:
        scan.pop("artifacts", None)
        _populate_unsealed_manifest_envelope(manifest, scan, completion_binding)
    _validate_contract_refs(scan)
    findings, findings_input_bytes = _read_scan_local_json_bytes(
        scan_dir,
        scan["findingsRef"],
        scan["findingsRef"],
        require_object=was_sealed,
        draft_recovery_warnings=completion_warnings if not was_sealed else None,
    )
    coverage, coverage_input_bytes = _read_scan_local_json_bytes(
        scan_dir,
        scan["coverageRef"],
        scan["coverageRef"],
        require_object=False,
        draft_recovery_warnings=completion_warnings if not was_sealed else None,
    )
    if not was_sealed:
        findings, simplified_findings = _normalize_standalone_findings_draft(findings)
        coverage, simplified_coverage = _normalize_standalone_coverage_draft(
            coverage, completion_binding
        )
        _reconcile_standalone_coverage_with_findings(coverage, findings)
        _reconcile_coverage_with_inventory(
            coverage, scan_dir, completion_warnings
        )
        if (
            completion_warnings is not None
            and (simplified_manifest or simplified_findings or simplified_coverage)
        ):
            completion_warnings.append(
                "Recovered compact Copilot draft artifacts into the canonical scan contract."
            )
        _populate_unsealed_artifact_envelope(manifest, findings, coverage, completion_binding)
        _normalize_unsealed_deep_repository_inventory_strategy(
            coverage,
            expected_coverage_mode=expected_coverage_mode,
        )
        _normalize_unsealed_open_questions(coverage)

    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        raise ContractError(f"manifest.schemaVersion: expected {SCHEMA_VERSION}")
    if scan.get("status") != "completed":
        raise ContractError("manifest.scan.status: expected completed before sealing")
    if (
        expected_coverage_mode is not None
        and completion_binding is not None
        and completion_binding["coverageMode"] != expected_coverage_mode
    ):
        raise ContractError("completion binding coverage mode does not match expected mode")
    if expected_coverage_mode is not None and coverage.get("mode") != expected_coverage_mode:
        raise ContractError(
            f"coverage.mode: must match selected scan mode {expected_coverage_mode}"
        )
    _validate_existing_seal(
        scan_dir,
        scan,
        artifact_contents={
            scan["findingsRef"]: findings_input_bytes,
            scan["coverageRef"]: coverage_input_bytes,
        },
    )
    scan["sealedAt"] = _require_str(scan, "completedAt", "manifest.scan")
    _validate_target(_require_dict(scan, "target", "manifest.scan"))
    _validate_completion_binding(manifest, findings, coverage, completion_binding)
    if was_sealed:
        _validate_findings(manifest, findings)
        _validate_derived_finding_identities(manifest, findings)
    elif completion_warnings is not None:
        discarded_findings = _recover_unsealed_findings(
            manifest, findings, schema_dir, scan_dir, completion_warnings
        )
        _recover_unsealed_coverage(
            coverage, schema_dir, scan_dir, completion_warnings, discarded_findings
        )
        _recover_unsealed_hardening(manifest, scan_dir, completion_warnings)
    else:
        _populate_unsealed_finding_identities(manifest, findings)
    _validate_findings(manifest, findings)
    _validate_coverage(manifest, coverage, scan_dir)
    _validate_canonical_schemas_before_projection(manifest, findings, coverage, schema_dir)
    _require_derived_writeup_files(scan_dir, findings)
    _require_hardening_portfolio_file(scan_dir, scan)
    if was_sealed:
        _validate_sealed_coverage_receipts(scan, coverage)
        _validate_manifest(manifest)
        validate_against_schema(manifest, schema_dir / "scan-manifest.schema.json")
        validate_against_schema(findings, schema_dir / "findings.schema.json")
        validate_against_schema(coverage, schema_dir / "coverage.schema.json")
        report_markdown_bytes = _generate_report_projection(manifest, findings, coverage)
        _validate_report_output_paths(scan_dir)
        return (
            scan_dir,
            schema_dir,
            manifest,
            findings,
            coverage,
            was_sealed,
            report_markdown_bytes,
        )

    findings_bytes = _contract_json_bytes("findings.json", findings)
    coverage_bytes = _contract_json_bytes("coverage.json", coverage)
    report_markdown_bytes = _generate_report_projection(manifest, findings, coverage)
    _validate_report_output_paths(scan_dir)
    scan["artifacts"] = [
        _artifact_record(scan_dir, "findings.json", "application/json", findings_bytes),
        _artifact_record(scan_dir, "coverage.json", "application/json", coverage_bytes),
        *[
            _artifact_record(scan_dir, ref, "application/octet-stream")
            for ref in _coverage_receipt_refs(coverage)
        ],
    ]
    _validate_sealed_coverage_receipts(scan, coverage)
    _validate_manifest(manifest)
    validate_against_schema(manifest, schema_dir / "scan-manifest.schema.json")
    validate_against_schema(findings, schema_dir / "findings.schema.json")
    validate_against_schema(coverage, schema_dir / "coverage.schema.json")
    _contract_json_bytes("scan-manifest.json", manifest)
    return (
        scan_dir,
        schema_dir,
        manifest,
        findings,
        coverage,
        was_sealed,
        report_markdown_bytes,
    )


def _write_prepared_scan_finalization(
    prepared: PreparedScanFinalization,
    source_root: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Write a previously validated scan finalization result."""

    (
        scan_dir,
        schema_dir,
        manifest,
        findings,
        coverage,
        was_sealed,
        report_markdown_bytes,
    ) = prepared
    scan = _require_dict(manifest, "scan", "manifest")
    if was_sealed:
        write_scan_local_bytes(scan_dir, "report.md", report_markdown_bytes)
        _remove_scan_local_file_if_exists(scan_dir, "report.html")
        _write_sarif_projection_if_possible(scan_dir, source_root, schema_dir)
        return manifest, findings, coverage

    _write_scan_local_json(scan_dir, "findings.json", findings)
    _write_scan_local_json(scan_dir, "coverage.json", coverage)
    write_scan_local_bytes(scan_dir, "report.md", report_markdown_bytes)
    _remove_scan_local_file_if_exists(scan_dir, "report.html")
    _write_scan_local_json(scan_dir, "scan-manifest.json", manifest)
    _validate_existing_seal(scan_dir, scan)
    _write_sarif_projection_if_possible(scan_dir, source_root, schema_dir)
    return manifest, findings, coverage


def finalize_scan(
    scan_dir: Path,
    schema_dir: Path | None = None,
    source_root: Path | None = None,
    *,
    expected_coverage_mode: str | None = None,
    completion_binding: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    prepared = _prepare_scan_finalization(
        scan_dir,
        schema_dir,
        expected_coverage_mode=expected_coverage_mode,
        completion_binding=completion_binding,
    )
    return _write_prepared_scan_finalization(prepared, source_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", required=True, type=Path)
    parser.add_argument("--schema-dir", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--sarif-only", action="store_true")
    parser.add_argument("--sarif-output", type=Path)
    parser.add_argument("--export-format", choices=sorted(EXPORT_PATHS))
    parser.add_argument("--export-output", type=Path)
    args = parser.parse_args()
    try:
        if args.sarif_only and args.export_format is not None:
            parser.error("--sarif-only cannot be combined with --export-format")
        if args.export_output is not None and args.export_format is None:
            parser.error("--export-output requires --export-format")
        if args.sarif_output is not None and not args.sarif_only:
            parser.error("--sarif-output requires --sarif-only")
        if args.export_format is not None:
            contents = build_findings_export(
                args.scan_dir, args.export_format, args.source_root, args.schema_dir
            )
            if args.export_output is None:
                sys.stdout.buffer.write(contents)
            else:
                write_export_output(args.scan_dir, args.export_output, args.export_format, contents)
        elif args.sarif_only:
            sarif = build_sarif_projection(args.scan_dir, args.source_root, args.schema_dir)
            if args.sarif_output is None:
                sys.stdout.buffer.write(_json_bytes(sarif))
            else:
                write_sarif_output(args.scan_dir, args.sarif_output, sarif)
        else:
            finalize_scan(args.scan_dir, args.schema_dir, args.source_root)
    except ContractError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
