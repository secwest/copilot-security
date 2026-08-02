"""Shared constants for the Copilot Security workbench."""

import argparse
import os
import tempfile
from pathlib import Path

MODES = ("diff", "standard", "deep")
DIFF_TARGET_KINDS = ("working_tree", "commit", "range")
PHASES = ("preflight", "threat_model", "discovery", "validation", "attack_path", "reporting")
PHASE_PROGRESS_UNITS = (
    "checks",
    "threat_surfaces",
    "review_receipts",
    "candidate_findings",
    "validated_findings",
    "report_artifacts",
)
FINDING_SEVERITIES = ("critical", "high", "medium", "low", "informational")
FINDING_STATUSES = ("open", "closed")
FINDING_CLOSE_REASONS = ("already_fixed", "wont_fix", "false_positive")
REMEDIATION_STATES = (
    "idle",
    "requested",
    "generated",
    "applied",
    "verifying",
    "verified",
    "failed",
    "superseded",
)
REMEDIATION_UPDATE_STATES = ("generated", "applied", "verifying", "verified", "failed")
REMEDIATION_PENDING_ACTIONS = ("generate", "apply", "verify")
EXPORT_FORMATS = ("csv", "json", "sarif")
ARTIFACTS = {
    "coverage": "coverage.json",
    "findings": "findings.json",
    "manifest": "scan-manifest.json",
    "markdownReport": "report.md",
}
SQLITE_RETRY_ATTEMPTS = 5
CLAIM_LEASE_SECONDS = 120
DELIVERED_ACTION_LEASE_SECONDS = 900
PATCH_PREVIEW_BYTES = 16_000
PATCH_ARTIFACT_MAX_BYTES = 2 * 1024 * 1024
FINDINGS_RESULT_LIMIT = 20
FINDINGS_PAGE_MAX = 20
FINDING_DETAILS_PREVIEW_BYTES = 16_000
FINDING_ROOT_CAUSE_PREVIEW_BYTES = 2_000
FINDING_VALIDATION_PREVIEW_BYTES = 3_000
FINDING_ATTACK_PATH_PREVIEW_BYTES = 4_000
FINDING_CODE_EVIDENCE_LIMIT = 4
FINDING_CODE_EVIDENCE_SNIPPET_BYTES = 1_500
FINDING_EVIDENCE_EXCERPT_BYTES = 8_000
FINDING_LOCATIONS_LIMIT = 8
FINDING_TITLE_BYTES = 512
FINDING_SUMMARY_BYTES = 2_000
FINDING_REMEDIATION_BYTES = 2_000
FINDING_LOCATION_PATH_BYTES = 2_048
FINDING_LOCATION_ROLE_BYTES = 128
FINDING_ABSOLUTE_PATH_BYTES = 4_096
FINDING_LEVEL_BYTES = 128
MAX_CAPABILITY_PREFLIGHT_INPUT_JSON_BYTES = 160_000
MAX_CAPABILITY_PREFLIGHT_PERSISTED_JSON_BYTES = 180_000
GIT_REPOSITORY_ENVIRONMENT = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
)
EMPTY_GIT_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _path_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def trusted_git_executable() -> str | None:
    """Resolve Git without allowing a repository or scanner state to supply it."""
    unsafe_roots: list[Path] = []
    for name in (
        "COPILOT_SECURITY_REPOSITORY",
        "COPILOT_SECURITY_HOME",
        "COPILOT_SECURITY_STATE_DIR",
        "COPILOT_SECURITY_SCAN_DIR",
    ):
        value = os.environ.get(name)
        if value:
            try:
                unsafe_roots.append(Path(value).expanduser().resolve(strict=False))
            except OSError:
                pass
    try:
        unsafe_roots.append(Path(tempfile.gettempdir()).resolve(strict=False))
    except OSError:
        pass

    configured = os.environ.get("COPILOT_SECURITY_GIT_PATH")
    candidates: list[Path] = []
    if configured and Path(configured).is_absolute():
        candidates.append(Path(configured))
    path_value = next(
        (value for name, value in os.environ.items() if name.upper() == "PATH"), ""
    )
    suffixes = (".exe", ".com") if os.name == "nt" else ("",)
    for entry in path_value.split(os.pathsep):
        if not entry or not Path(entry).is_absolute():
            continue
        for suffix in suffixes:
            candidates.append(Path(entry) / f"git{suffix}")

    seen: set[Path] = set()
    for candidate in candidates:
        try:
            canonical = candidate.resolve(strict=True)
        except OSError:
            continue
        if canonical in seen:
            continue
        seen.add(canonical)
        if any(_path_within(root, canonical) for root in unsafe_roots):
            continue
        if not canonical.is_file():
            continue
        if os.name != "nt" and not os.access(canonical, os.X_OK):
            continue
        return str(canonical)
    return None


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
