"""Deterministic technical inventory for an ASGARD repository."""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .constants import INVENTORY_SCOPE_VERSION, TECHNICAL_INVENTORY_SCHEMA_VERSION
from .inventory_catalog import (
    CODE_EXTENSIONS,
    CODE_SIGNATURES,
    CONFIG_EXTENSIONS,
    EXCLUDED_DIRS,
    EXISTING_SPEC_NAMES,
    LANGUAGE_BY_EXTENSION,
    MANIFEST_NAMES,
    MAX_TEXT_FILE_BYTES,
    SERVER_FRAMEWORKS,
)
from .inventory_git import (
    InventoryError,
    discover_submodules,
    repository_identity,
    verify_git_target,
)
from .inventory_manifests import dependency_detections, manifest_dependencies
from .models import (
    AuditTarget,
    Confidence,
    DetectorCategory,
    InventoryEvidence,
    TechnicalInventory,
    TechnologyDetection,
    TechnologyKind,
)
from .path_filters import is_excluded_path, normalize_exclude_paths


def _relative(repository: Path, path: Path) -> str:
    return path.relative_to(repository).as_posix()


def _line_for(text: str, match_start: int) -> int:
    return text.count("\n", 0, match_start) + 1


def _merge_detection(
    store: dict[tuple[TechnologyKind, str], dict[str, object]],
    kind: TechnologyKind,
    name: str,
    confidence: Confidence,
    evidence: InventoryEvidence,
) -> None:
    key = (kind, name)
    current = store.get(key)
    if current is None:
        store[key] = {"confidence": confidence, "evidence": [evidence]}
        return
    if confidence == "confirmed":
        current["confidence"] = "confirmed"
    evidences = current["evidence"]
    assert isinstance(evidences, list)
    if evidence not in evidences:
        evidences.append(evidence)


def _iter_repository_files(
    repository: Path,
    exclude_paths: tuple[str, ...] = (),
) -> tuple[list[Path], list[str], list[str]]:
    exclude_paths = normalize_exclude_paths(repository, exclude_paths)
    files: list[Path] = []
    excluded_roots: list[str] = []
    symlinks: list[str] = []
    for root, dirs, filenames in os.walk(repository, topdown=True, followlinks=False):
        root_path = Path(root)
        kept_dirs = []
        for dirname in sorted(dirs):
            path = root_path / dirname
            rel = _relative(repository, path)
            if path.is_symlink():
                symlinks.append(rel)
            elif dirname in EXCLUDED_DIRS or is_excluded_path(repository, path, exclude_paths):
                excluded_roots.append(rel)
            else:
                kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        for filename in sorted(filenames):
            path = root_path / filename
            rel = _relative(repository, path)
            if path.is_symlink():
                symlinks.append(rel)
            elif is_excluded_path(repository, path, exclude_paths):
                excluded_roots.append(rel)
            elif path.is_file():
                files.append(path)
    return files, sorted(set(excluded_roots)), sorted(set(symlinks))


def _language_detections(repository: Path, files: Iterable[Path]) -> list[TechnologyDetection]:
    by_language: dict[str, list[InventoryEvidence]] = defaultdict(list)
    for path in files:
        language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
        if language:
            by_language[language].append(
                InventoryEvidence(path=_relative(repository, path), kind="source")
            )
    return [
        TechnologyDetection(
            kind="language",
            name=language,
            confidence="confirmed",
            evidence=tuple(by_language[language][:20]),
        )
        for language in sorted(by_language)
    ]


def _to_detections(
    store: dict[tuple[TechnologyKind, str], dict[str, object]],
    kind: TechnologyKind,
) -> list[TechnologyDetection]:
    result = []
    for (item_kind, name), value in sorted(store.items()):
        if item_kind != kind:
            continue
        confidence = value["confidence"]
        evidence = value["evidence"]
        assert confidence in {"confirmed", "probable", "unverified"}
        assert isinstance(evidence, list)
        result.append(
            TechnologyDetection(
                kind=item_kind,
                name=name,
                confidence=confidence,  # type: ignore[arg-type]
                evidence=tuple(evidence),
            )
        )
    return result


def _code_detections(
    store: dict[tuple[TechnologyKind, str], dict[str, object]],
    repository: Path,
    path: Path,
    text: str,
) -> None:
    rel = _relative(repository, path)
    suffix = path.suffix.lower()
    for kind, name, pattern, extensions in CODE_SIGNATURES:
        if extensions is not None and suffix not in extensions:
            continue
        match = pattern.search(text)
        if not match:
            continue
        evidence_kind = "configuration" if name == "webhook" else "source"
        _merge_detection(
            store,
            kind,
            name,
            "probable",
            InventoryEvidence(
                path=rel,
                line=_line_for(text, match.start()),
                kind=evidence_kind,  # type: ignore[arg-type]
                note="code signature",
            ),
        )


def _detector_plan(
    frameworks: list[TechnologyDetection],
    http_clients: list[TechnologyDetection],
    integration_surfaces: list[TechnologyDetection],
    existing_specs: list[TechnologyDetection],
) -> tuple[list[DetectorCategory], list[str]]:
    categories: set[DetectorCategory] = {"inventory", "configuration"}
    hints: set[str] = set()
    if frameworks:
        categories.add("framework")
    for framework in frameworks:
        hints.add(f"framework:{framework.name}")
        if framework.name in SERVER_FRAMEWORKS:
            categories.add("exposed")
            hints.add(f"exposed:{framework.name}")
    if http_clients:
        categories.add("consumed")
    hints.update(f"consumed:{client.name}" for client in http_clients)
    if integration_surfaces:
        categories.add("integration")
    hints.update(f"integration:{surface.name}" for surface in integration_surfaces)
    if existing_specs:
        categories.add("existing_spec")
        hints.add("existing_spec:openapi-or-swagger")
    order: tuple[DetectorCategory, ...] = (
        "inventory",
        "framework",
        "configuration",
        "existing_spec",
        "exposed",
        "consumed",
        "integration",
    )
    return [item for item in order if item in categories], sorted(hints)


def inventory_repository(target: AuditTarget, *, allow_dirty: bool = False) -> TechnicalInventory:
    repository, source_commit, dirty = verify_git_target(target)
    repository_id, identity_source = repository_identity(repository, target.repository_id)
    if dirty and not allow_dirty:
        raise InventoryError(
            "Working tree is dirty. Commit/stash changes or use --allow-dirty for a diagnostic "
            "inventory, which will be marked incomplete."
        )

    exclude_paths = normalize_exclude_paths(repository, target.exclude_paths)
    files, excluded_roots, symlinks = _iter_repository_files(repository, exclude_paths)
    submodules = discover_submodules(repository)
    languages = _language_detections(repository, files)
    store: dict[tuple[TechnologyKind, str], dict[str, object]] = {}
    manifests: list[str] = []
    manifest_errors: list[str] = []
    skipped_oversize: list[str] = []
    text_files_inspected = 0
    spec_store: dict[tuple[TechnologyKind, str], dict[str, object]] = {}

    for path in files:
        rel = _relative(repository, path)
        is_manifest = path.name in MANIFEST_NAMES or path.name.endswith(".csproj")
        if is_manifest:
            manifests.append(rel)
            ecosystem, dependencies, error = manifest_dependencies(path)
            if error:
                manifest_errors.append(f"{rel}: {error}")
            elif ecosystem:
                for detection in dependency_detections(ecosystem, dependencies, rel):
                    _merge_detection(store, *detection)

        if EXISTING_SPEC_NAMES.match(path.name):
            _merge_detection(
                spec_store,
                "existing_spec",
                "openapi-or-swagger",
                "probable",
                InventoryEvidence(path=rel, kind="existing_spec", note="filename pattern"),
            )

        if path.suffix.lower() not in CODE_EXTENSIONS | CONFIG_EXTENSIONS and not is_manifest:
            continue
        try:
            if path.stat().st_size > MAX_TEXT_FILE_BYTES:
                skipped_oversize.append(rel)
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            manifest_errors.append(f"{rel}: text read failed: {exc}")
            continue
        text_files_inspected += 1
        if path.suffix.lower() in CODE_EXTENSIONS:
            _code_detections(store, repository, path, text)

    frameworks = _to_detections(store, "framework")
    http_clients = _to_detections(store, "http_client")
    integration_surfaces = _to_detections(store, "integration_surface")
    existing_specs = _to_detections(spec_store, "existing_spec")
    required_categories, detector_hints = _detector_plan(
        frameworks, http_clients, integration_surfaces, existing_specs
    )

    incomplete_reasons = []
    if dirty:
        incomplete_reasons.append("working tree is dirty")
    if symlinks:
        incomplete_reasons.append("symlink paths were not traversed")
    if skipped_oversize:
        incomplete_reasons.append("oversize text candidates were not inspected")
    if manifest_errors:
        incomplete_reasons.append("one or more candidate files/manifests could not be parsed")
    if submodules:
        incomplete_reasons.append("git submodules are not traversed in v0.3")

    notes = [
        "inventory_complete describes execution coverage of inventory scope v1.0, "
        "not proof that every possible technology pattern is known.",
        "Dependency-manifest matches are confirmed; source-code signatures are probable "
        "unless corroborated by a manifest.",
        "Documentation files are not searched for technology signatures to avoid false positives.",
        *incomplete_reasons,
    ]
    return TechnicalInventory(
        schema_version=TECHNICAL_INVENTORY_SCHEMA_VERSION,
        scope_version=INVENTORY_SCOPE_VERSION,
        auditor_version=__version__,
        repository=repository.name,
        repository_id=repository_id,
        repository_identity_source=identity_source,
        source_ref=target.ref,
        source_commit=source_commit,
        working_tree_dirty=dirty,
        inventory_complete=not incomplete_reasons,
        files_scanned=len(files),
        text_files_inspected=text_files_inspected,
        excluded_roots=excluded_roots,
        skipped_oversize_files=sorted(skipped_oversize),
        skipped_symlinks=symlinks,
        manifest_errors=sorted(manifest_errors),
        manifests=sorted(set(manifests)),
        submodules=submodules,
        languages=languages,
        frameworks=frameworks,
        http_clients=http_clients,
        integration_surfaces=integration_surfaces,
        existing_specs=existing_specs,
        required_detector_categories=required_categories,
        detector_hints=detector_hints,
        notes=notes,
    )


def inventory_to_dict(inventory: TechnicalInventory) -> dict[str, object]:
    return asdict(inventory)


__all__ = ["InventoryError", "inventory_repository", "inventory_to_dict"]
