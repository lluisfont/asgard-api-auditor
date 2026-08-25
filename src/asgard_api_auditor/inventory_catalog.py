"""Supported technical-inventory signatures and dependency mappings."""

from __future__ import annotations

import re

from .models import TechnologyKind

MAX_TEXT_FILE_BYTES = 2_000_000

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "build",
    "dist",
    ".dart_tool",
    ".next",
    "coverage",
    "htmlcov",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "output",
    ".audit-staging",
}

CODE_EXTENSIONS = {
    ".php", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue",
    ".dart", ".py", ".java", ".kt", ".kts", ".cs", ".go", ".rb", ".swift",
}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".xml", ".gradle", ".properties"}

LANGUAGE_BY_EXTENSION = {
    ".php": "php", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".vue": "vue-sfc", ".dart": "dart",
    ".py": "python", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp", ".go": "go", ".rb": "ruby", ".swift": "swift",
}

MANIFEST_NAMES = {
    "composer.json", "package.json", "pubspec.yaml", "pyproject.toml",
    "requirements.txt", "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "Gemfile", "Package.swift",
}

SERVER_FRAMEWORKS = {
    "laravel", "lumen", "symfony", "express", "nestjs", "fastify", "nextjs",
    "nuxt", "fastapi", "flask", "django", "spring-boot", "aspnet-core", "rails",
}

FRAMEWORK_DEPENDENCIES = {
    "composer": {
        "laravel/framework": "laravel",
        "laravel/lumen-framework": "lumen",
        "symfony/framework-bundle": "symfony",
        "symfony/http-kernel": "symfony",
    },
    "npm": {
        "vue": "vue", "nuxt": "nuxt", "react": "react", "next": "nextjs",
        "express": "express", "@nestjs/core": "nestjs", "fastify": "fastify",
    },
    "python": {"fastapi": "fastapi", "flask": "flask", "django": "django"},
    "dart": {"flutter": "flutter"},
    "java": {
        "spring-boot-starter-web": "spring-boot",
        "spring-boot-starter-webflux": "spring-boot",
    },
    "dotnet": {"microsoft.aspnetcore": "aspnet-core"},
    "ruby": {"rails": "rails"},
}

HTTP_CLIENT_DEPENDENCIES = {
    "composer": {"guzzlehttp/guzzle": "guzzle"},
    "npm": {"axios": "axios", "ky": "ky", "got": "got", "node-fetch": "fetch"},
    "python": {"requests": "requests", "httpx": "httpx", "aiohttp": "aiohttp"},
    "dart": {"dio": "dio", "http": "dart-http"},
    "java": {
        "okhttp": "okhttp", "spring-web": "spring-web-client",
        "spring-webflux": "spring-webclient",
    },
    "dotnet": {"microsoft.extensions.http": "dotnet-httpclient"},
}

INTEGRATION_DEPENDENCIES = {
    "npm": {
        "graphql": "graphql", "@apollo/client": "graphql", "@apollo/server": "graphql",
        "ws": "websocket", "socket.io": "websocket", "eventsource": "sse",
        "@grpc/grpc-js": "grpc",
    },
    "python": {
        "graphene": "graphql", "graphql-core": "graphql", "websockets": "websocket",
        "grpcio": "grpc", "zeep": "soap",
    },
    "dart": {"graphql": "graphql", "web_socket_channel": "websocket", "grpc": "grpc"},
    "java": {"grpc": "grpc"},
    "dotnet": {"grpc.net.client": "grpc"},
}

CODE_SIGNATURES: tuple[tuple[TechnologyKind, str, re.Pattern[str]], ...] = (
    ("framework", "laravel", re.compile(
        r"(?:Illuminate\\\\Routing|\bRoute::(?:get|post|put|patch|delete|options|any|match)\s*\()"
    )),
    ("framework", "symfony", re.compile(r"(?:Symfony\\\\Component\\\\Routing|#\[Route\s*\()")),
    (
        "framework",
        "express",
        re.compile(r"(?:from\s+['\"]express['\"]|require\(['\"]express['\"]\))"),
    ),
    ("framework", "nestjs", re.compile(r"(?:@nestjs/common|@Controller\s*\()")),
    ("framework", "fastapi", re.compile(r"(?:from\s+fastapi\s+import|FastAPI\s*\()")),
    ("framework", "flask", re.compile(r"(?:from\s+flask\s+import|Flask\s*\()")),
    ("framework", "django", re.compile(r"(?:from\s+django\.|\burlpatterns\s*=)")),
    ("framework", "spring-boot", re.compile(
        r"(?:@RestController\b|org\.springframework\.web\.bind\.annotation)"
    )),
    ("framework", "aspnet-core", re.compile(r"(?:\[ApiController\]|Microsoft\.AspNetCore)")),
    ("framework", "flutter", re.compile(r"import\s+['\"]package:flutter/")),
    ("http_client", "php-curl", re.compile(r"\bcurl_init\s*\(")),
    ("http_client", "guzzle", re.compile(r"(?:GuzzleHttp\\\\Client|GuzzleHttp\\\\Psr7)")),
    ("http_client", "laravel-http", re.compile(
        r"(?:Illuminate\\\\Support\\\\Facades\\\\Http|"
        r"\bHttp::(?:get|post|put|patch|delete|send)\s*\()"
    )),
    ("http_client", "axios", re.compile(r"(?:from\s+['\"]axios['\"]|require\(['\"]axios['\"]\))")),
    ("http_client", "fetch", re.compile(r"\bfetch\s*\(")),
    ("http_client", "dio", re.compile(r"import\s+['\"]package:dio/")),
    ("http_client", "dart-http", re.compile(r"import\s+['\"]package:http/")),
    ("http_client", "requests", re.compile(
        r"(?:^|\n)\s*(?:import\s+requests\b|from\s+requests\s+import)"
    )),
    ("http_client", "httpx", re.compile(r"(?:^|\n)\s*(?:import\s+httpx\b|from\s+httpx\s+import)")),
    ("http_client", "aiohttp", re.compile(
        r"(?:^|\n)\s*(?:import\s+aiohttp\b|from\s+aiohttp\s+import)"
    )),
    ("http_client", "okhttp", re.compile(r"\bOkHttpClient\b")),
    ("http_client", "spring-web-client", re.compile(r"\bRestTemplate\b")),
    ("http_client", "spring-webclient", re.compile(r"\bWebClient\b")),
    ("http_client", "dotnet-httpclient", re.compile(r"\bHttpClient\b")),
    ("integration_surface", "graphql", re.compile(
        r"(?:@apollo/|\bGraphQLSchema\b|package:graphql/)"
    )),
    ("integration_surface", "websocket", re.compile(
        r"(?:\bnew\s+WebSocket\s*\(|package:web_socket_channel/)"
    )),
    ("integration_surface", "grpc", re.compile(r"(?:\bgrpc\.|package:grpc/|io\.grpc\.)")),
    ("integration_surface", "soap", re.compile(r"(?:\bSoapClient\b|\bzeep\b|javax\.xml\.ws)")),
    ("integration_surface", "sse", re.compile(r"(?:\bEventSource\s*\(|text/event-stream)")),
    ("integration_surface", "webhook", re.compile(r"\b[A-Z0-9_]*WEBHOOK_URL\b")),
)

EXISTING_SPEC_NAMES = re.compile(
    r"^(?:openapi|swagger)(?:[._-].*)?\.(?:ya?ml|json)$", re.IGNORECASE
)
