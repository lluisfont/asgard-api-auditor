"""Manifest parsing for technical inventory."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from .inventory_catalog import (
    FRAMEWORK_DEPENDENCIES,
    HTTP_CLIENT_DEPENDENCIES,
    INTEGRATION_DEPENDENCIES,
)
from .models import Confidence, InventoryEvidence, TechnologyKind


def python_requirement_name(requirement: str) -> str:
    name = re.split(r"[<>=!~\[;\s]", requirement.strip(), maxsplit=1)[0]
    return name.replace("_", "-").lower()


def simple_yaml_dependency_keys(text: str) -> set[str]:
    deps: set[str] = set()
    active = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith((" ", "\t")):
            key = raw.split(":", 1)[0].strip()
            active = key in {"dependencies", "dev_dependencies", "dependency_overrides"}
            continue
        if active:
            match = re.match(r"^\s{2,}([A-Za-z0-9_.-]+)\s*:", raw)
            if match:
                deps.add(match.group(1).lower())
    return deps


def manifest_dependencies(path: Path) -> tuple[str | None, set[str], str | None]:
    name = path.name
    try:
        if name == "composer.json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            deps = set(payload.get("require", {})) | set(payload.get("require-dev", {}))
            return "composer", {str(dep).lower() for dep in deps}, None
        if name == "package.json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            deps: set[str] = set()
            for section in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ):
                value = payload.get(section, {})
                if isinstance(value, dict):
                    deps.update(str(dep).lower() for dep in value)
            return "npm", deps, None
        if name == "pyproject.toml":
            payload = tomllib.loads(path.read_text(encoding="utf-8"))
            deps: set[str] = set()
            project = payload.get("project", {})
            if isinstance(project, dict):
                deps.update(
                    python_requirement_name(str(dep))
                    for dep in project.get("dependencies", []) or []
                )
                optional = project.get("optional-dependencies", {})
                if isinstance(optional, dict):
                    for group in optional.values():
                        if isinstance(group, list):
                            deps.update(python_requirement_name(str(dep)) for dep in group)
            tool = payload.get("tool", {})
            if isinstance(tool, dict):
                poetry = tool.get("poetry", {})
                if isinstance(poetry, dict):
                    for section in ("dependencies", "dev-dependencies"):
                        value = poetry.get(section, {})
                        if isinstance(value, dict):
                            deps.update(
                                str(dep).lower() for dep in value if dep.lower() != "python"
                            )
            return "python", deps, None
        if name == "requirements.txt":
            deps = set()
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line and not line.startswith(("#", "-")):
                    deps.add(python_requirement_name(line))
            return "python", deps, None
        if name == "pubspec.yaml":
            return "dart", simple_yaml_dependency_keys(path.read_text(encoding="utf-8")), None
        if name == "pom.xml":
            root = ET.fromstring(path.read_text(encoding="utf-8"))
            deps = {
                element.text.strip().lower()
                for element in root.iter()
                if element.tag.endswith("artifactId") and element.text
            }
            return "java", deps, None
        if name in {"build.gradle", "build.gradle.kts"}:
            text = path.read_text(encoding="utf-8")
            return "java", {x.lower() for x in re.findall(r"['\"]([^'\"]+)['\"]", text)}, None
        if name.endswith(".csproj"):
            root = ET.fromstring(path.read_text(encoding="utf-8"))
            deps = set()
            for element in root.iter():
                if element.tag.endswith("PackageReference"):
                    include = element.attrib.get("Include") or element.attrib.get("Update")
                    if include:
                        deps.add(include.lower())
            return "dotnet", deps, None
        if name == "Gemfile":
            text = path.read_text(encoding="utf-8")
            deps = {
                m.group(1).lower()
                for m in re.finditer(r"\bgem\s+['\"]([^'\"]+)['\"]", text)
            }
            return "ruby", deps, None
        if name == "go.mod":
            deps = set()
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith(("module ", "go ", "//", ")")):
                    continue
                if line == "require (":
                    continue
                if line.startswith("require "):
                    line = line.removeprefix("require ").strip()
                deps.add(line.split()[0].lower())
            return "go", deps, None
        if name == "Package.swift":
            return "swift", set(), None
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        ET.ParseError,
    ) as exc:
        return None, set(), str(exc)
    return None, set(), None


def dependency_match(dep: str, candidate: str, ecosystem: str) -> bool:
    if ecosystem == "java":
        return candidate in dep
    if ecosystem == "dotnet":
        return dep == candidate or dep.startswith(candidate + ".")
    return dep == candidate


def dependency_detections(
    ecosystem: str,
    dependencies: set[str],
    manifest_path: str,
) -> list[tuple[TechnologyKind, str, Confidence, InventoryEvidence]]:
    evidence = InventoryEvidence(
        path=manifest_path,
        kind="manifest",
        note=f"{ecosystem} dependency",
    )
    result: list[tuple[TechnologyKind, str, Confidence, InventoryEvidence]] = []
    for candidate, name in FRAMEWORK_DEPENDENCIES.get(ecosystem, {}).items():
        if any(dependency_match(dep, candidate, ecosystem) for dep in dependencies):
            result.append(("framework", name, "confirmed", evidence))
    for candidate, name in HTTP_CLIENT_DEPENDENCIES.get(ecosystem, {}).items():
        if any(dependency_match(dep, candidate, ecosystem) for dep in dependencies):
            result.append(("http_client", name, "confirmed", evidence))
    for candidate, name in INTEGRATION_DEPENDENCIES.get(ecosystem, {}).items():
        if any(dependency_match(dep, candidate, ecosystem) for dep in dependencies):
            result.append(("integration_surface", name, "confirmed", evidence))
    return result
