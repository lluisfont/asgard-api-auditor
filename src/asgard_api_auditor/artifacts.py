"""Validation and fail-safe publication of audit artifact sets."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from pathlib import Path

from .constants import OPENAPI_VERSION, PRIMARY_ARTIFACTS
from .redaction import contains_unredacted_secret_like_value

_FRONT_MATTER_VALUE = re.compile(r"^([A-Za-z0-9_-]+):\s*[\"']?([^\"']+?)[\"']?\s*$")


class ArtifactValidationError(ValueError):
    """Raised when an audit artifact set is incomplete or inconsistent."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _front_matter(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        raise ArtifactValidationError(f"Missing YAML front matter: {path.name}")
    values: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return values
        match = _FRONT_MATTER_VALUE.match(line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    raise ArtifactValidationError(f"Unclosed YAML front matter: {path.name}")


def validate_audit_set(directory: Path) -> dict[str, str]:
    """Validate required files, shared metadata, hashes and obvious secret leakage."""
    missing = [name for name in PRIMARY_ARTIFACTS if not (directory / name).is_file()]
    if missing:
        raise ArtifactValidationError(f"Missing primary artifacts: {', '.join(missing)}")

    findings_path = directory / "findings.json"
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    required_metadata = (
        "audit_id",
        "auditor_version",
        "repository",
        "source_ref",
        "source_commit",
    )
    metadata = {key: str(findings.get(key, "")) for key in required_metadata}
    if any(not value for value in metadata.values()):
        raise ArtifactValidationError("findings.json is missing shared audit metadata")

    knowledge_meta = _front_matter(directory / "api-knowledge.md")
    report_meta = _front_matter(directory / "audit-report.md")
    for key, expected in metadata.items():
        if knowledge_meta.get(key) != expected:
            raise ArtifactValidationError(f"api-knowledge.md metadata mismatch: {key}")
        if report_meta.get(key) != expected:
            raise ArtifactValidationError(f"audit-report.md metadata mismatch: {key}")

    openapi_text = (directory / "openapi.yaml").read_text(encoding="utf-8")
    if f"openapi: {OPENAPI_VERSION}" not in openapi_text:
        raise ArtifactValidationError("openapi.yaml does not use the approved OpenAPI version")
    if f'x-asgard-audit-id: "{metadata["audit_id"]}"' not in openapi_text:
        raise ArtifactValidationError("openapi.yaml audit_id mismatch")
    if f'x-asgard-source-commit: "{metadata["source_commit"]}"' not in openapi_text:
        raise ArtifactValidationError("openapi.yaml source_commit mismatch")

    artifacts = findings.get("artifacts", {})
    if isinstance(artifacts, dict):
        for name in ("openapi.yaml", "api-knowledge.md", "audit-report.md"):
            entry = artifacts.get(name)
            if isinstance(entry, dict) and entry.get("sha256"):
                actual = sha256_file(directory / name)
                if entry["sha256"] != actual:
                    raise ArtifactValidationError(f"Artifact hash mismatch: {name}")

    for name in PRIMARY_ARTIFACTS:
        text = (directory / name).read_text(encoding="utf-8", errors="replace")
        if contains_unredacted_secret_like_value(text):
            raise ArtifactValidationError(f"Potential unredacted secret in {name}")

    return metadata


def atomic_publish(staging_dir: Path, destination: Path) -> None:
    """Publish a validated audit set without losing the previous valid destination."""
    validate_audit_set(staging_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)

    token = uuid.uuid4().hex
    candidate = destination.parent / f".{destination.name}.new-{token}"
    backup = destination.parent / f".{destination.name}.previous-{token}"

    shutil.copytree(staging_dir, candidate)
    moved_previous = False
    try:
        if destination.exists():
            os.replace(destination, backup)
            moved_previous = True
        os.replace(candidate, destination)
        if moved_previous:
            shutil.rmtree(backup)
    except Exception:
        if candidate.exists():
            shutil.rmtree(candidate, ignore_errors=True)
        if moved_previous and backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise
