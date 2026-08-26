"""Small JSON Schema validator for ASGARD audit contracts.

The auditor keeps runtime dependencies empty, so correlation performs the
contract checks it needs with a deliberately small Draft 2020-12 subset.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when a JSON document does not satisfy its schema."""


def load_json_schema(path: Path) -> dict[str, Any]:
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaValidationError(f"Unable to read JSON schema {path}: {exc}") from exc
    if not isinstance(schema, dict):
        raise SchemaValidationError(f"JSON schema {path} must be an object")
    return schema


def validate_json_schema(instance: object, schema: dict[str, Any], *, source: str) -> None:
    """Validate instance against the supported JSON Schema subset."""

    _validate(instance, schema, root=schema, path="$", source=source)


def _validate(
    instance: object,
    schema: dict[str, Any],
    *,
    root: dict[str, Any],
    path: str,
    source: str,
) -> None:
    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
            raise SchemaValidationError(f"{source}: unsupported schema reference at {path}: {ref!r}")
        target = root
        for part in ref[2:].split("/"):
            if not isinstance(target, dict) or part not in target:
                raise SchemaValidationError(f"{source}: unresolved schema reference at {path}: {ref}")
            target = target[part]
        if not isinstance(target, dict):
            raise SchemaValidationError(f"{source}: schema reference at {path} does not point to an object")
        _validate(instance, target, root=root, path=path, source=source)
        return

    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(
            f"{source}: {path} must be {schema['const']!r}, got {instance!r}"
        )
    if "enum" in schema:
        allowed = schema["enum"]
        if not isinstance(allowed, list) or instance not in allowed:
            raise SchemaValidationError(f"{source}: {path} has unsupported value {instance!r}")

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(instance, expected_type):
        raise SchemaValidationError(f"{source}: {path} must be {_type_label(expected_type)}")

    if isinstance(instance, dict):
        _validate_object(instance, schema, root=root, path=path, source=source)
    elif isinstance(instance, list):
        _validate_array(instance, schema, root=root, path=path, source=source)
    elif isinstance(instance, str):
        _validate_string(instance, schema, path=path, source=source)
    elif isinstance(instance, int) and not isinstance(instance, bool):
        _validate_integer(instance, schema, path=path, source=source)


def _validate_object(
    instance: dict[str, object],
    schema: dict[str, Any],
    *,
    root: dict[str, Any],
    path: str,
    source: str,
) -> None:
    required = schema.get("required", [])
    if required:
        if not isinstance(required, list):
            raise SchemaValidationError(f"{source}: schema required at {path} must be an array")
        missing = [key for key in required if isinstance(key, str) and key not in instance]
        if missing:
            raise SchemaValidationError(f"{source}: {path} misses required fields: {', '.join(missing)}")

    properties = schema.get("properties", {})
    if properties and not isinstance(properties, dict):
        raise SchemaValidationError(f"{source}: schema properties at {path} must be an object")

    additional = schema.get("additionalProperties", True)
    if additional is False:
        extra = sorted(key for key in instance if key not in properties)
        if extra:
            raise SchemaValidationError(
                f"{source}: {path} contains unsupported fields: {', '.join(extra)}"
            )

    for key, value in instance.items():
        property_schema = properties.get(key)
        if isinstance(property_schema, dict):
            _validate(value, property_schema, root=root, path=f"{path}.{key}", source=source)
        elif isinstance(additional, dict):
            _validate(value, additional, root=root, path=f"{path}.{key}", source=source)


def _validate_array(
    instance: list[object],
    schema: dict[str, Any],
    *,
    root: dict[str, Any],
    path: str,
    source: str,
) -> None:
    min_items = schema.get("minItems")
    if isinstance(min_items, int) and len(instance) < min_items:
        raise SchemaValidationError(f"{source}: {path} must contain at least {min_items} items")
    item_schema = schema.get("items")
    if isinstance(item_schema, dict):
        for index, item in enumerate(instance):
            _validate(item, item_schema, root=root, path=f"{path}[{index}]", source=source)


def _validate_string(
    instance: str,
    schema: dict[str, Any],
    *,
    path: str,
    source: str,
) -> None:
    min_length = schema.get("minLength")
    if isinstance(min_length, int) and len(instance) < min_length:
        raise SchemaValidationError(f"{source}: {path} must contain at least {min_length} characters")
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and re.search(pattern, instance) is None:
        raise SchemaValidationError(f"{source}: {path} does not match required pattern")
    if schema.get("format") == "date-time":
        value = instance.replace("Z", "+00:00")
        try:
            datetime.fromisoformat(value)
        except ValueError as exc:
            raise SchemaValidationError(f"{source}: {path} must be a valid date-time") from exc


def _validate_integer(
    instance: int,
    schema: dict[str, Any],
    *,
    path: str,
    source: str,
) -> None:
    minimum = schema.get("minimum")
    if isinstance(minimum, int | float) and instance < minimum:
        raise SchemaValidationError(f"{source}: {path} must be >= {minimum}")
    maximum = schema.get("maximum")
    if isinstance(maximum, int | float) and instance > maximum:
        raise SchemaValidationError(f"{source}: {path} must be <= {maximum}")


def _matches_type(instance: object, expected_type: object) -> bool:
    if isinstance(expected_type, list):
        return any(_matches_type(instance, item) for item in expected_type)
    if expected_type == "object":
        return isinstance(instance, dict)
    if expected_type == "array":
        return isinstance(instance, list)
    if expected_type == "string":
        return isinstance(instance, str)
    if expected_type == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected_type == "boolean":
        return isinstance(instance, bool)
    if expected_type == "null":
        return instance is None
    if expected_type == "number":
        return isinstance(instance, int | float) and not isinstance(instance, bool)
    raise SchemaValidationError(f"Unsupported JSON Schema type: {expected_type!r}")


def _type_label(expected_type: object) -> str:
    if isinstance(expected_type, list):
        return " or ".join(str(item) for item in expected_type)
    return str(expected_type)
