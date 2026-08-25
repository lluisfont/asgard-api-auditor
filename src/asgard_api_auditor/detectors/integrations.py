"""Integration-surface discovery that is deliberately separate from REST endpoints."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from ..discovery_types import DiscoveryIssue, IntegrationFinding
from ..discovery_utils import line_number, read_source, relative_path
from ..models import DetectorCoverage, Evidence

SOAP_DETECTOR_ID = "soap-integration"
SOAP_DETECTOR_VERSION = "1.0.0"


@dataclass(frozen=True)
class _PhpMethod:
    class_name: str
    name: str
    params: tuple[str, ...]
    body: str
    start: int
    body_start: int
    body_end: int
    path: Path
    text: str


@dataclass(frozen=True)
class _SoapClientSource:
    variable: str
    service_expression: str
    service_value: str | None
    contract_status: str
    offset: int
    path: Path
    text: str
    contract: dict[str, dict[str, str | None]]


@dataclass(frozen=True)
class _SoapOperation:
    operation: str
    offset: int
    path: Path
    text: str
    evidence: tuple[Evidence, ...] = ()


def _evidence(repository: Path, path: Path, text: str, offset: int, note: str) -> Evidence:
    return Evidence(
        path=relative_path(repository, path),
        line=line_number(text, offset),
        kind="integration",
        note=note,
    )


def _literal(expression: str) -> str | None:
    match = re.fullmatch(r"\s*(?P<quote>['\"])(?P<value>.*?)(?P=quote)\s*", expression, re.DOTALL)
    return match.group("value") if match else None


def _mask_php_comments(text: str) -> str:
    chars = list(text)
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(chars):
        char = chars[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "/" and index + 1 < len(chars) and chars[index + 1] == "/":
            while index < len(chars) and chars[index] != "\n":
                chars[index] = " "
                index += 1
            continue
        if char == "#":
            while index < len(chars) and chars[index] != "\n":
                chars[index] = " "
                index += 1
            continue
        if char == "/" and index + 1 < len(chars) and chars[index + 1] == "*":
            chars[index] = " "
            chars[index + 1] = " "
            index += 2
            while index + 1 < len(chars) and not (chars[index] == "*" and chars[index + 1] == "/"):
                if chars[index] != "\n":
                    chars[index] = " "
                index += 1
            if index + 1 < len(chars):
                chars[index] = " "
                chars[index + 1] = " "
                index += 2
            continue
        index += 1
    return "".join(chars)


def _matching_delimiter(text: str, open_offset: int, open_char: str, close_char: str) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(open_offset, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_arguments(arguments: str) -> list[str]:
    result: list[str] = []
    start = 0
    parens = brackets = braces = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(arguments):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            parens += 1
        elif char == ")":
            parens -= 1
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets -= 1
        elif char == "{":
            braces += 1
        elif char == "}":
            braces -= 1
        elif char == "," and parens == 0 and brackets == 0 and braces == 0:
            result.append(arguments[start:index].strip())
            start = index + 1
    tail = arguments[start:].strip()
    if tail:
        result.append(tail)
    return result


def _constant_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for match in re.finditer(
        r"\bdefine\s*\(\s*['\"](?P<name>[A-Za-z_]\w*)['\"]\s*,\s*"
        r"(?P<quote>['\"])(?P<value>.*?)(?P=quote)\s*\)",
        text,
        re.DOTALL,
    ):
        values[match.group("name")] = match.group("value")
    for match in re.finditer(
        r"\bconst\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<quote>['\"])(?P<value>.*?)(?P=quote)",
        text,
        re.DOTALL,
    ):
        values[match.group("name")] = match.group("value")
    return values


def _local_wsdl_path(repository: Path, current_file: Path, value: str) -> Path | None:
    if re.match(r"https?://", value, re.IGNORECASE):
        return None
    candidates = [
        (repository / value).resolve(),
        (current_file.parent / value).resolve(),
    ]
    for candidate in candidates:
        try:
            candidate.relative_to(repository.resolve())
        except ValueError:
            continue
        if candidate.is_file():
            return candidate
    return None


def _parse_wsdl(path: Path) -> dict[str, dict[str, str | None]]:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except (OSError, ET.ParseError, UnicodeDecodeError):
        return {}

    namespace = {"wsdl": "http://schemas.xmlsoap.org/wsdl/"}
    messages: set[str] = set()
    for message in root.findall("wsdl:message", namespace):
        name = message.attrib.get("name")
        if name:
            messages.add(name)

    port_type_ops: dict[str, tuple[str | None, str | None]] = {}
    for operation in root.findall(".//wsdl:portType/wsdl:operation", namespace):
        name = operation.attrib.get("name")
        if not name:
            continue
        input_message = operation.find("wsdl:input", namespace)
        output_message = operation.find("wsdl:output", namespace)
        port_type_ops[name] = (
            (input_message.attrib.get("message") if input_message is not None else None),
            (output_message.attrib.get("message") if output_message is not None else None),
        )

    binding_by_operation: dict[str, str | None] = {}
    for binding in root.findall("wsdl:binding", namespace):
        binding_name = binding.attrib.get("name")
        for operation in binding.findall("wsdl:operation", namespace):
            name = operation.attrib.get("name")
            if name:
                binding_by_operation[name] = binding_name

    service_name: str | None = None
    port_name: str | None = None
    for service in root.findall("wsdl:service", namespace):
        service_name = service.attrib.get("name")
        port = service.find("wsdl:port", namespace)
        if port is not None:
            port_name = port.attrib.get("name")
        break

    operations: dict[str, dict[str, str | None]] = {}
    for name, (input_message, output_message) in port_type_ops.items():
        operations[name] = {
            "service": service_name,
            "port": port_name,
            "binding": binding_by_operation.get(name),
            "input_message": input_message if _message_name(input_message) in messages else input_message,
            "output_message": output_message if _message_name(output_message) in messages else output_message,
        }
    return operations


def _message_name(value: str | None) -> str | None:
    if value is None:
        return None
    return value.rsplit(":", 1)[-1]


def _service_resolution(
    repository: Path,
    path: Path,
    text: str,
    expression: str,
) -> tuple[str | None, str, dict[str, dict[str, str | None]]]:
    literal = _literal(expression)
    value = literal or _constant_values(text).get(expression.strip())
    if value is None:
        return None, "expression_unresolved", {}

    local_wsdl = _local_wsdl_path(repository, path, value)
    if local_wsdl is not None:
        return value, "local_parsed", _parse_wsdl(local_wsdl)
    if re.match(r"https?://", value, re.IGNORECASE):
        return value, "external_not_snapshotted", {}
    return value, "local_missing", {}


def _php_methods(path: Path, text: str) -> dict[tuple[str, str], _PhpMethod]:
    masked = _mask_php_comments(text)
    methods: dict[tuple[str, str], _PhpMethod] = {}
    for class_match in re.finditer(r"\bclass\s+(?P<class>[A-Za-z_]\w*)[^{]*\{", masked):
        class_name = class_match.group("class")
        class_body_start = class_match.end()
        class_body_end = _matching_delimiter(masked, class_body_start - 1, "{", "}")
        if class_body_end is None:
            continue
        class_body = masked[class_body_start:class_body_end]
        for method_match in re.finditer(
            r"\b(?:public|protected|private)?\s*function\s+"
            r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{",
            class_body,
        ):
            body_start = class_body_start + method_match.end()
            body_end = _matching_delimiter(masked, body_start - 1, "{", "}")
            if body_end is None or body_end > class_body_end:
                continue
            params = tuple(
                match.group(0)
                for match in re.finditer(r"\$[A-Za-z_]\w*", method_match.group("params"))
            )
            methods[(class_name, method_match.group("name"))] = _PhpMethod(
                class_name=class_name,
                name=method_match.group("name"),
                params=params,
                body=masked[body_start:body_end],
                start=class_body_start + method_match.start(),
                body_start=body_start,
                body_end=body_end,
                path=path,
                text=text,
            )
    return methods


def _operation_scope(masked: str, offset: int) -> tuple[int, int, str]:
    function_ranges: list[tuple[int, int]] = []
    for match in re.finditer(r"\bfunction\s+[A-Za-z_]\w*\s*\([^)]*\)\s*\{", masked):
        body_start = match.end()
        body_end = _matching_delimiter(masked, body_start - 1, "{", "}")
        if body_end is None:
            continue
        if match.start() <= offset <= body_end:
            return body_start, body_end, masked
        function_ranges.append((match.start(), body_end))

    chars = list(masked)
    for start, end in function_ranges:
        for index in range(start, end + 1):
            if chars[index] != "\n":
                chars[index] = " "
    top_level = "".join(chars)
    return 0, len(top_level), top_level


def _object_assignments(text: str) -> dict[str, str]:
    masked = _mask_php_comments(text)
    return {
        match.group("var"): match.group("class")
        for match in re.finditer(
            r"(?P<var>\$[A-Za-z_]\w*)\s*=\s*new\s+(?P<class>[A-Za-z_]\w*)\s*\(",
            masked,
        )
        if match.group("class") != "SoapClient"
    }


def _soap_clients(repository: Path, path: Path, text: str) -> list[_SoapClientSource]:
    masked = _mask_php_comments(text)
    clients: list[_SoapClientSource] = []
    for match in re.finditer(
        r"(?P<handle>\$[A-Za-z_]\w*)\s*=\s*new\s+\\?SoapClient\s*\(",
        masked,
    ):
        close = _matching_delimiter(masked, match.end() - 1, "(", ")")
        if close is None:
            continue
        arguments = _split_arguments(masked[match.end():close])
        if not arguments:
            continue
        expression = arguments[0].strip()
        value, contract_status, contract = _service_resolution(repository, path, text, expression)
        clients.append(_SoapClientSource(
            variable=match.group("handle"),
            service_expression=expression,
            service_value=value,
            contract_status=contract_status,
            offset=match.start(),
            path=path,
            text=text,
            contract=contract,
        ))
    return clients


def _source_window(masked: str, source: _SoapClientSource) -> tuple[int, int, str]:
    scope_start, scope_end, scoped_text = _operation_scope(masked, source.offset)
    same_client_assignment = re.compile(
        rf"{re.escape(source.variable)}\s*=\s*new\s+\\?SoapClient\s*\("
    )
    next_assignment = None
    for match in same_client_assignment.finditer(scoped_text, scope_start, scope_end):
        if match.start() > source.offset:
            next_assignment = match.start()
            break
    return source.offset, next_assignment or scope_end, scoped_text


def _direct_operations(method: _PhpMethod, variable: str) -> list[_SoapOperation]:
    operations: list[_SoapOperation] = []
    escaped = re.escape(variable)
    soap_call = re.compile(rf"{escaped}->__soapCall\s*\(\s*(?P<operation>[^,\)]+)", re.DOTALL)
    for match in soap_call.finditer(method.body):
        operation = _literal(match.group("operation"))
        if operation is not None:
            operations.append(
                _SoapOperation(operation, method.body_start + match.start(), method.path, method.text)
            )

    direct_call = re.compile(rf"{escaped}->(?P<operation>[A-Za-z_]\w*)\s*\(", re.DOTALL)
    for match in direct_call.finditer(method.body):
        operation = match.group("operation")
        if operation == "__soapCall":
            continue
        operations.append(_SoapOperation(operation, method.body_start + match.start(), method.path, method.text))
    return operations


def _method_calls(text: str, *, base_offset: int = 0) -> list[tuple[str, str, list[str], int]]:
    masked = _mask_php_comments(text)
    calls: list[tuple[str, str, list[str], int]] = []
    for match in re.finditer(r"(?P<object>\$[A-Za-z_]\w*)->(?P<method>[A-Za-z_]\w*)\s*\(", masked):
        if match.group("method") in {"__soapCall"}:
            continue
        close = _matching_delimiter(masked, match.end() - 1, "(", ")")
        if close is None:
            continue
        calls.append((
            match.group("object"),
            match.group("method"),
            _split_arguments(masked[match.end():close]),
            base_offset + match.start(),
        ))
    return calls


def _propagated_operations(
    source: _SoapClientSource,
    object_classes: dict[str, str],
    methods: dict[tuple[str, str], _PhpMethod],
    caller_text: str,
    repository: Path,
    caller_path: Path,
    base_offset: int = 0,
) -> list[_SoapOperation]:
    operations: list[_SoapOperation] = []
    for object_var, method_name, args, call_offset in _method_calls(
        caller_text, base_offset=base_offset
    ):
        class_name = object_classes.get(object_var)
        if class_name is None:
            continue
        target = methods.get((class_name, method_name))
        if target is None:
            continue
        for index, argument in enumerate(args):
            if argument != source.variable or index >= len(target.params):
                continue
            param = target.params[index]
            for operation in _direct_operations(target, param):
                operations.append(
                    _SoapOperation(
                        operation=operation.operation,
                        offset=operation.offset,
                        path=operation.path,
                        text=operation.text,
                        evidence=(
                            _evidence(
                                repository,
                                caller_path,
                                source.text,
                                call_offset,
                                "SOAP client passed as argument",
                            ),
                            _evidence(repository, target.path, target.text, target.start, "SOAP client parameter receiver"),
                        ),
                    )
                )
    return operations


def _finding(
    repository: Path,
    source: _SoapClientSource,
    operation: _SoapOperation,
) -> IntegrationFinding:
    contract = source.contract.get(operation.operation, {})
    defined_in_wsdl = operation.operation in source.contract if source.contract else None
    return IntegrationFinding(
        type="soap",
        direction="consumed",
        confidence="confirmed",
        confidence_reason="SOAP operation call is traced to a proven SoapClient instance.",
        wsdl=source.service_value or source.service_expression,
        service_expression=source.service_expression,
        service_value=source.service_value,
        contract_status=source.contract_status,
        service=contract.get("service"),
        port=contract.get("port"),
        binding=contract.get("binding"),
        input_message=contract.get("input_message"),
        output_message=contract.get("output_message"),
        defined_in_wsdl=defined_in_wsdl,
        operation=operation.operation,
        evidence=[
            _evidence(repository, source.path, source.text, source.offset, "SOAP client creation"),
            _evidence(repository, source.path, source.text, source.offset, "SOAP service expression"),
            *operation.evidence,
            _evidence(repository, operation.path, operation.text, operation.offset, "SOAP operation"),
        ],
        notes=["SOAP is not represented as a REST endpoint."],
    )


def detect_soap_integrations(
    repository: Path,
    files: list[Path],
) -> tuple[list[IntegrationFinding], list[DiscoveryIssue], DetectorCoverage, bool, bool]:
    issues: list[DiscoveryIssue] = []
    php_files = [path for path in files if path.suffix.lower() == ".php"]
    source_by_path: dict[Path, str] = {}
    methods: dict[tuple[str, str], _PhpMethod] = {}

    for path in php_files:
        text = read_source(path)
        if text is None:
            continue
        source_by_path[path] = text
        methods.update(_php_methods(path, text))

    findings: dict[tuple[str, str, str], IntegrationFinding] = {}
    soap_clients_seen = 0
    for path, text in source_by_path.items():
        clients = _soap_clients(repository, path, text)
        if not clients:
            continue
        soap_clients_seen += len(clients)
        object_classes = _object_assignments(text)
        masked = _mask_php_comments(text)
        for source in clients:
            window_start, window_end, scoped_text = _source_window(masked, source)
            local_method = _PhpMethod(
                class_name="",
                name="",
                params=(),
                body=scoped_text[window_start:window_end],
                start=window_start,
                body_start=window_start,
                body_end=window_end,
                path=path,
                text=text,
            )
            window_text = scoped_text[window_start:window_end]
            operations = _direct_operations(local_method, source.variable)
            operations.extend(
                _propagated_operations(
                    source,
                    object_classes,
                    methods,
                    window_text,
                    repository,
                    path,
                    base_offset=window_start,
                )
            )
            if not operations:
                issues.append(
                    DiscoveryIssue(
                        code="soap_operation_unresolved",
                        message="SoapClient was found without a supported operation call.",
                        detector_id=SOAP_DETECTOR_ID,
                        evidence=(_evidence(repository, path, text, source.offset, "SOAP client"),),
                    )
                )
                continue
            for operation in operations:
                finding = _finding(repository, source, operation)
                findings.setdefault(
                    (finding.service_expression or finding.wsdl or "", finding.operation or "", finding.direction),
                    finding,
                )

    integrations = sorted(
        findings.values(),
        key=lambda item: (item.service_expression or item.wsdl or "", item.operation or ""),
    )
    soap_operations_complete = soap_clients_seen > 0 and not any(
        issue.code == "soap_operation_unresolved" for issue in issues
    )
    soap_contracts_complete = bool(integrations) and all(
        item.contract_status == "local_parsed" and item.defined_in_wsdl is not False
        for item in integrations
    )
    if not soap_contracts_complete:
        issues.append(
            DiscoveryIssue(
                code="soap_contract_extraction_partial",
                message=(
                    "SOAP operations are represented separately from REST endpoints, but one or more "
                    "SOAP contracts are not available as reproducible local WSDL snapshots."
                ),
                detector_id=SOAP_DETECTOR_ID,
            )
        )

    unsupported = {issue.code for issue in issues}
    coverage = DetectorCoverage(
        detector_id=SOAP_DETECTOR_ID,
        detector_version=SOAP_DETECTOR_VERSION,
        category="integration",
        status="supported" if soap_operations_complete and soap_contracts_complete else "partial",
        files_scanned=len(php_files),
        supported_patterns=(
            "PHP SoapClient operation calls",
            "SoapClient passed as same-repository class method argument",
            "local WSDL parsing",
        ),
        unsupported_patterns=tuple(sorted(unsupported)),
        notes=(
            "SOAP findings are emitted as integrations, never REST endpoints.",
            f"soap_operations_complete={str(soap_operations_complete).lower()}",
            f"soap_contracts_complete={str(soap_contracts_complete).lower()}",
        ),
    )
    return integrations, issues, coverage, soap_operations_complete, soap_contracts_complete
