#!/usr/bin/env python3
"""HalluciGuard v6.2 — Context-Aware, Zero-Noise AI Supply Chain, SAST & 20-Point Hygiene Scanner.

Zero-dependency security scanner built exclusively on Python 3.11+ standard libraries.
Strictly read-only by default (opt-in --patch with AST syntax validation), daemon-free,
mmap + SHA-256 file-hash cached, and MCP + CI/CD ready.

Modules:
  - Core Engine : AST Package & Slopsquatting Analysis (1.5s timeout, 24h cache + file-hash cache)
  - Module A    : Domain Squatting Guard (Whitelist + lightweight socket DNS)
  - Module B    : Hallucinated Library Method Detector (AST alias tracking)
  - Module C    : Context-Aware Shannon Entropy Secret Hunter & Unsafe Sinks
  - Module D    : Read-Only Safe Diff Suggestions (--suggest) & Opt-In --patch
  - Module E    : Zero-Noise LLM Prompt Injection & Nested ast.walk() Taint Analysis
  - Module F    : Daemon-Free Levenshtein Typosquatting / Zero-Day Shield
  - Module G    : Cyber-SOC Dark-Mode Interactive HTML Report (--report <file.html>)
  - Module H-K  : Insecure YAML, Setup.py Build Hooks, Weak Randomness, Path Traversal, LLM-to-Code RCE
  - Module L-P  : Dependency Confusion, Multi-Step Taint Tracking, Obfuscation, AI Agents, CI/CD YAML
  - Module Q-R-V: Git Pre-Commit Hook (--install-hook), MCP Server (--mcp-server), --init-config, AI Fix Prompt
  - Module W    : 20-Point Real-World Security & Code Hygiene Suite
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import ctypes
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import html
import ipaddress
import json
import math
import mmap
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


VERSION = "6.2.0"
CACHE_FILE_PATH = Path.home() / ".halluciguard_cache.json"
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
DEFAULT_MAX_WORKERS = 8
PYPI_JSON_URL_TEMPLATE = "https://pypi.org/pypi/{package}/json"
HTTP_TIMEOUT_SECONDS = 1.5

SKIP_DIRS = frozenset({
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "venv",
    ".venv",
    "env",
    ".env",
    "node_modules",
    "build",
    "dist",
    ".eggs",
    "site-packages",
})

# Table 1: Supply Chain Statuses
STATUS_SAFE = "SAFE"
STATUS_HALLUCINATED = "DANGER - Hallucinated Package"
STATUS_TYPOSQUAT = "DANGER - Typosquatting / Zero-Day Risk"
STATUS_SUSPICIOUS = "WARNING - Suspicious/Slopsquatting"
STATUS_DEP_CONFUSION = "WARNING - Dependency Confusion Risk"
STATUS_LOCAL_STDLIB = "LOCAL / STDLIB"
STATUS_ERROR = "ERROR / UNVERIFIED"

# Table 2: SAST, AI Hallucination & Module W Hygiene Severities
SEVERITY_DOMAIN_DANGER = "DANGER - Unregistered/Hallucinated Domain"
SEVERITY_PROMPT_DANGER = "DANGER - Embedded Prompt Injection / Jailbreak"
SEVERITY_PROMPT_WARNING = "WARNING - Unvalidated Prompt Sink / Injection Risk"
SEVERITY_METHOD_WARNING = "WARNING - Hallucinated Method"
SEVERITY_SECRET_WARNING = "WARNING - High-Entropy Hardcoded Secret"
SEVERITY_UNSAFE_WARNING = "WARNING - Unsafe Code Pattern"
SEVERITY_UNSAFE_INFO_WARNING = "INFO/WARNING - Unsafe Code Pattern"
SEVERITY_YAML_WARNING = "WARNING - Insecure YAML Load"
SEVERITY_BUILD_HOOK_DANGER = "DANGER - Malicious Build Hook / Setup Injection Risk"
SEVERITY_WEAK_RANDOM_WARNING = "WARNING - Cryptographically Weak Randomness"
SEVERITY_PATH_TRAVERSAL_WARNING = "WARNING - Path Traversal Sink"
SEVERITY_LLM_RCE_DANGER = "DANGER - LLM-to-Code RCE Risk"
SEVERITY_TAINT_FLOW_DANGER = "DANGER - Multi-Step Tainted Data Flow"
SEVERITY_OBFUSCATED_DANGER = "DANGER - Obfuscated Code / Hidden Import"
SEVERITY_AGENT_TOOL_WARNING = "WARNING - Unrestricted AI Agent Tool"
SEVERITY_CICD_DANGER = "DANGER - CI/CD Workflow Vulnerability"

# Module W Severities
SEVERITY_DESERIALIZATION_DANGER = "DANGER - Insecure Deserialization"
SEVERITY_PRIVATE_KEY_DANGER = "DANGER - Hardcoded Private Key"
SEVERITY_DB_STRING_DANGER = "DANGER - Hardcoded DB Connection String"
SEVERITY_SHELL_DANGER = "DANGER - Dangerous Shell Injection"
SEVERITY_TEMP_FILE_WARNING = "WARNING - Insecure Temp File"
SEVERITY_WEAK_CRYPTO_WARNING = "WARNING - Weak Cryptography"
SEVERITY_SQLI_DANGER = "DANGER - SQL Injection via String Formatting"
SEVERITY_CLOUD_TOKEN_DANGER = "DANGER - Hardcoded Cloud API Token"
SEVERITY_DEBUG_WARNING = "WARNING - Insecure Web Framework Debug"
SEVERITY_SSL_WARNING = "WARNING - Disabled SSL Verification"
SEVERITY_GLOBAL_STATE_WARNING = "WARNING - Global Mutable State Risk"
SEVERITY_REDIRECT_WARNING = "WARNING - Unvalidated Redirect"
SEVERITY_CORS_WARNING = "WARNING - Insecure CORS Wildcard"
SEVERITY_INTERNAL_IP_INFO = "INFO/WARNING - Hardcoded Internal IP"
SEVERITY_BARE_EXCEPT_WARNING = "WARNING - Silent Failure (Bare Except)"
SEVERITY_DEPRECATED_MOD_WARNING = "WARNING - Deprecated Stdlib Module"

# Module F: Popular PyPI packages for Levenshtein Typosquatting defense
TOP_PYPI_PACKAGES: tuple[str, ...] = (
    "requests",
    "numpy",
    "pandas",
    "fastapi",
    "flask",
    "django",
    "torch",
    "tensorflow",
    "openai",
    "anthropic",
    "cryptography",
    "pillow",
    "urllib3",
    "pydantic",
    "scipy",
    "matplotlib",
    "scikit-learn",
    "beautifulsoup4",
    "pyyaml",
    "sqlalchemy",
    "celery",
    "redis",
    "boto3",
    "pytest",
    "httpx",
    "aiohttp",
    "uvicorn",
    "gunicorn",
    "paramiko",
    "psutil",
    "click",
    "rich",
    "typer",
    "jinja2",
    "werkzeug",
    "marshmallow",
    "attrs",
    "lxml",
    "openpyxl",
    "pymongo",
    "psycopg2-binary",
    "python-dotenv",
    "pyjwt",
    "opencv-python",
    "transformers",
    "langchain",
    "tiktoken",
    "setuptools",
    "packaging",
    "certifi",
    "charset-normalizer",
    "idna",
)

# Built-in mapping dictionary: import module name -> canonical PyPI package name
IMPORT_TO_PACKAGE: dict[str, str] = {
    "cv2": "opencv-python",
    "PIL": "Pillow",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn",
    "yaml": "PyYAML",
    "dotenv": "python-dotenv",
    "jwt": "PyJWT",
    "git": "GitPython",
    "serial": "pyserial",
    "usb": "pyusb",
    "Crypto": "pycryptodome",
    "crypto": "pycryptodome",
    "Cryptodome": "pycryptodomex",
    "OpenSSL": "pyOpenSSL",
    "dateutil": "python-dateutil",
    "fitz": "PyMuPDF",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "telegram": "python-telegram-bot",
    "discord": "discord.py",
    "slugify": "python-slugify",
    "magic": "python-magic",
    "ldap": "python-ldap",
    "memcache": "python-memcached",
    "MySQLdb": "mysqlclient",
    "psycopg2": "psycopg2-binary",
    "nacl": "PyNaCl",
    "socks": "PySocks",
    "attr": "attrs",
    "gi": "PyGObject",
    "wx": "wxPython",
    "skimage": "scikit-image",
    "Bio": "biopython",
    "bio": "biopython",
    "google": "google-api-python-client",
    "win32api": "pywin32",
    "win32com": "pywin32",
    "win32con": "pywin32",
    "win32gui": "pywin32",
    "pythoncom": "pywin32",
    "pywintypes": "pywin32",
    "xdg": "pyxdg",
    "cairo": "pycairo",
    "dbus": "dbus-python",
    "Levenshtein": "python-Levenshtein",
    "jose": "python-jose",
    "multipart": "python-multipart",
    "aio_pika": "aio-pika",
    "websocket": "websocket-client",
    "socketio": "python-socketio",
    "engineio": "python-engineio",
    "zmq": "pyzmq",
    "grpc": "grpcio",
    "pydantic_settings": "pydantic-settings",
    "ruamel": "ruamel.yaml",
    "lxml": "lxml",
    "ujson": "ujson",
    "orjson": "orjson",
    "dns": "dnspython",
    "nmap": "python-nmap",
    "scapy": "scapy",
    "paramiko": "paramiko",
}

LOWER_IMPORT_TO_PACKAGE: dict[str, str] = {
    k.lower(): v for k, v in IMPORT_TO_PACKAGE.items()
}

# Module A: URL extraction regex (applied strictly on ast.Constant string literals)
URL_EXTRACT_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)

# Module W: High-confidence signature regexes constructed safely to avoid self-triggers
PRIVATE_KEY_RE = re.compile(
    "".join(["-----", "BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY", "-----"])
)
DB_CONN_RE = re.compile(
    "".join([
        r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://",
        r"[^\s:@/]+:[^\s@/]+@[^\s\"']+",
    ]),
    re.IGNORECASE,
)
CLOUD_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS Access Key", re.compile("".join([r"\b(?:AKIA|ASIA)", r"[0-9A-Z]{16}\b"]))),
    ("GitHub Classic PAT", re.compile("".join([r"\bghp_", r"[A-Za-z0-9]{36}\b"]))),
    ("GitHub Fine-Grained PAT", re.compile("".join([r"\bgithub_pat_", r"[A-Za-z0-9_]{22,}\b"]))),
    ("Slack Token", re.compile("".join([r"\bxox[baprs]-", r"[A-Za-z0-9-]{10,}\b"]))),
)
IPV4_RE = re.compile(r"(?<![.\d])\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b(?![.\d])")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
HEX_COLOR_RE = re.compile(r"^#[0-9a-f]{3,8}$", re.IGNORECASE)

# Module W Check 20: Deprecated / Removed Python Stdlib Modules
DEPRECATED_STDLIB_MODULES: dict[str, str] = {
    "imp": "Use importlib (removed in Python 3.12)",
    "cgi": "Use urllib.parse / email.message or modern framework (PEP 594)",
    "cgitb": "Use traceback / logging (PEP 594)",
    "crypt": "Use hashlib.scrypt / pbkdf2_hmac (PEP 594)",
    "pipes": "Use subprocess / shlex.quote (PEP 594)",
    "telnetlib": "Use SSH (paramiko) or socket/asyncio (PEP 594)",
    "uu": "Use base64 (PEP 594)",
    "aifc": "Use wave or external audio library (PEP 594)",
    "audioop": "Removed in Python 3.13 (PEP 594)",
    "chunk": "Use struct / io (PEP 594)",
    "imghdr": "Use file signatures / Pillow (PEP 594)",
    "mailcap": "Use mimetypes (PEP 594)",
    "msilib": "Removed in Python 3.13 (PEP 594)",
    "nis": "Removed in Python 3.13 (PEP 594)",
    "nntplib": "Removed in Python 3.13 (PEP 594)",
    "optparse": "Use argparse",
    "ossaudiodev": "Removed in Python 3.13 (PEP 594)",
    "sndhdr": "Removed in Python 3.13 (PEP 594)",
    "spwd": "Removed in Python 3.13 (PEP 594)",
    "sunau": "Removed in Python 3.13 (PEP 594)",
    "xdrlib": "Use struct (PEP 594)",
    "distutils": "Use setuptools / packaging (removed in Python 3.12)",
    "asynchat": "Use asyncio (removed in Python 3.12)",
    "asyncore": "Use asyncio (removed in Python 3.12)",
    "smtpd": "Use aiosmtpd / smtplib (removed in Python 3.12)",
}

# Module A: Standard / Safe Domain Whitelist
DOMAIN_WHITELIST = frozenset({
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "w3.org",
    "github.com",
    "githubusercontent.com",
    "pypi.org",
    "pythonhosted.org",
    "python.org",
    "schemas.xmlsoap.org",
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "json-schema.org",
    "ietf.org",
    "apache.org",
    "mozilla.org",
    "openai.com",
    "anthropic.com",
    "google.com",
    "googleapis.com",
    "microsoft.com",
    "amazonaws.com",
    "cloudflare.com",
    "httpbin.org",
})

WHITELISTED_TLDS = (".local", ".localhost", ".internal", ".test", ".example", ".invalid")

# Module B: Popular Library Hallucinated or Removed Methods
HALLUCINATED_METHODS: dict[str, dict[str, str]] = {
    "requests": {
        "get_json": "Use requests.get(...).json()",
        "post_json": "Use requests.post(..., json=...)",
        "fetch": "Use requests.get(...) or requests.request(...)",
        "download": "Use requests.get(..., stream=True)",
        "parse_json": "Use response.json()",
        "get_async": "Use httpx.AsyncClient or aiohttp (requests is synchronous)",
    },
    "json": {
        "loads_safe": "Use json.loads(...) with try/except json.JSONDecodeError",
        "load_safe": "Use json.load(...) with try/except json.JSONDecodeError",
        "dumps_pretty": "Use json.dumps(..., indent=2)",
        "parse": "Use json.loads(...)",
        "stringify": "Use json.dumps(...)",
        "validate": "Use json.loads(...) or jsonschema library",
    },
    "os": {
        "mkdir_p": "Use os.makedirs(..., exist_ok=True)",
        "rmdir_f": "Use shutil.rmtree(...)",
        "exists": "Use os.path.exists(...)",
        "read_file": "Use Path(...).read_text() or open(...)",
        "write_file": "Use Path(...).write_text() or open(...)",
    },
    "os.path": {
        "exists_fast": "Use os.path.exists(...) or Path(...).exists()",
        "is_empty": "Use os.path.getsize(...) == 0",
        "read_text": "Use pathlib.Path(...).read_text()",
        "extension": "Use os.path.splitext(...)[1]",
        "filename": "Use os.path.basename(...)",
    },
    "pandas": {
        "read_pdf": "Use tabula-py / pdfplumber to construct pd.DataFrame()",
        "read_docx": "Use python-docx to construct pd.DataFrame()",
        "to_dict_list": "Use df.to_dict(orient='records')",
        "append": "Use pandas.concat([...]) (df.append removed in pandas 2.0)",
        "iteritems": "Use df.items() (iteritems removed in pandas 2.0)",
        "read_json_safe": "Use pd.read_json(...) with try/except ValueError",
    },
    "datetime": {
        "parse": "Use datetime.fromisoformat(...) or datetime.strptime(...)",
        "from_string": "Use datetime.strptime(...)",
        "now_utc": "Use datetime.now(timezone.utc)",
        "utcnow_iso": "Use datetime.now(timezone.utc).isoformat()",
        "to_timestamp": "Use dt.timestamp()",
    },
    "datetime.datetime": {
        "parse": "Use datetime.fromisoformat(...) or datetime.strptime(...)",
        "from_string": "Use datetime.strptime(...)",
        "now_utc": "Use datetime.now(timezone.utc)",
        "utcnow_iso": "Use datetime.now(timezone.utc).isoformat()",
    },
    "hashlib": {
        "md5_hex": "Use hashlib.sha256(...).hexdigest()",
        "sha256_hex": "Use hashlib.sha256(...).hexdigest()",
        "sha512_hex": "Use hashlib.sha512(...).hexdigest()",
        "hash_password": "Use hashlib.pbkdf2_hmac(...) or hashlib.scrypt(...)",
        "hmac_sha256": "Use hmac.new(..., digestmod='sha256')",
    },
}

# Module C & J: Context-Aware Secret & Weak Randomness Keywords
SECRET_VAR_KEYWORDS = (
    "key",
    "secret",
    "token",
    "password",
    "passwd",
    "auth",
    "credential",
)

WEAK_RANDOM_VAR_KEYWORDS = SECRET_VAR_KEYWORDS + (
    "session",
    "otp",
    "pin",
    "nonce",
    "salt",
    "csrf",
)

WEAK_RANDOM_METHODS = frozenset({
    "random.randint",
    "random.choice",
    "random.choices",
    "random.random",
    "random.randrange",
    "random.getrandbits",
    "random.uniform",
    "random.sample",
})

SECRET_FALSE_VAR_SUBSTRINGS = (
    "tokenizer",
    "max_token",
    "token_count",
    "token_type",
    "token_id",
    "secret_name",
    "secret_path",
    "secret_file",
    "password_hash",
    "password_field",
    "token_url",
    "api_key_env",
    "api_key_name",
    "public_key",
    "key_list",
    "keys",
    "key_name",
    "key_path",
    "key_id",
    "author",
    "auth_mode",
    "auth_type",
    "auth_url",
    "subkey",
    "sub_key",
    "reg_key",
    "hotkey",
    "dict_key",
    "sort_key",
    "primary_key",
    "foreign_key",
    "cache_key",
)

SECRET_PLACEHOLDER_MARKERS = (
    "your_api_key",
    "your-api-key",
    "your_secret",
    "your_token",
    "your_password",
    "your_",
    "changeme",
    "change_me",
    "replace_me",
    "placeholder",
    "example",
    "sample",
    "dummy",
    "123456",
    "abcdef",
    "insert_",
    "enter_",
    "<your",
    "xxxx",
)

SUBPROCESS_SHELL_SINKS = frozenset({"Popen", "run", "call", "check_call", "check_output"})
SQL_KEYWORDS = ("select ", "insert ", "update ", "delete ", "drop ", "create ", "alter ", "replace ")

# Module E & K & M: Prompt Injection, LLM Outputs & Taint Tracking
PROMPT_VAR_NAMES = frozenset({
    "prompt",
    "system_prompt",
    "user_prompt",
    "llm_prompt",
    "ai_prompt",
    "chat_prompt",
    "system_instruction",
    "system_message",
    "prompt_template",
    "messages",
})

LLM_CALL_SUFFIXES = (
    "chat.completions.create",
    "completions.create",
    "responses.create",
    "messages.create",
    "generate_content",
    "generate_content_async",
    "ChatCompletion.create",
    "Completion.create",
)

LLM_DIRECT_CALLS = frozenset({
    "ollama.chat",
    "ollama.generate",
    "genai.generate_text",
})

LLM_PROMPT_ARG_NAMES = frozenset({
    "prompt",
    "messages",
    "contents",
    "system",
    "system_instruction",
    "input",
})

LLM_OUTPUT_VAR_HINTS = (
    "llm_output",
    "ai_output",
    "ai_code",
    "generated_code",
    "model_output",
    "completion_text",
    "llm_response",
    "ai_response",
)

LLM_OUTPUT_ATTR_CHAINS = (
    "response.text",
    "resp.text",
    "completion.choices",
    "response.choices",
    "message.content",
    "llm_response.text",
    "ai_response.text",
)

TAINT_INPUT_CALLS = frozenset({
    "input",
    "request.get_json",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "urllib.request.urlopen",
    "os.getenv",
})

TAINT_INPUT_PREFIXES = (
    "sys.argv",
    "os.environ",
    "request.args",
    "request.json",
    "request.form",
    "request.data",
    "request.values",
    "request.query_params",
    "request.body",
)

PROMPT_JAILBREAK_SIGNATURES = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "disregard all previous",
    "system override",
    "bypass safety",
    "reveal your system prompt",
    "you are now dan",
    "do anything now",
    "forget your instructions",
)

# Module I: Setup / Build Hook Dangerous Modules
BUILD_HOOK_FILENAMES = frozenset({"setup.py", "tasks.py"})
BUILD_HOOK_DANGEROUS_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "urllib.request.",
    "urllib.urlopen",
    "requests.",
    "socket.",
)

# Module N: Obfuscation Calls
OBFUSCATED_DECODE_CALLS = frozenset({
    "base64.b64decode",
    "base64.urlsafe_b64decode",
    "bytes.fromhex",
    "codecs.decode",
    "zlib.decompress",
    "marshal.loads",
})

# Module O: AI Agent Tool Decorators & Dangerous Operations
AGENT_TOOL_DECORATORS = frozenset({
    "tool",
    "function_tool",
    "mcp.tool",
    "agent.tool",
    "langchain.tools.tool",
})

AGENT_DANGEROUS_SINKS = (
    "os.remove",
    "os.unlink",
    "shutil.rmtree",
    "os.system",
    "subprocess.",
    "eval",
    "exec",
    "requests.post",
    "requests.put",
    "requests.delete",
    "urllib.request.urlopen",
)

AGENT_VALIDATION_WORDS = (
    "confirm",
    "approve",
    "allowlist",
    "whitelist",
    "validate",
    "sanitize",
    "permission",
    "is_allowed",
    "check_path",
    "safe_",
)

GUARDIGNORE_TEMPLATE = """# HalluciGuard Configuration and Ignore List (.guardignore)
# Specify one package name per line. Lines starting with '#' are comments.
# Add your internal private Artifactory/PyPI packages here:
#
# Example private packages:
# internal-core-lib
# company-auth-service
"""


class Ansi:
    """ANSI escape sequences compatible with Windows 11, macOS, and Linux."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"


def configure_terminal() -> bool:
    """Enable UTF-8 output and ANSI VT100 escape sequences on Windows 11+."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except OSError:
                continue

    if os.environ.get("NO_COLOR") is not None:
        return False

    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            for handle_id in (-11, -12):
                handle = kernel32.GetStdHandle(handle_id)
                if handle and handle != -1:
                    mode = ctypes.c_uint32()
                    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            return True

    return True


def canonicalize_name(name: str) -> str:
    """Normalize a Python package name according to PEP 503."""
    cleaned = name.strip().lower()
    out: list[str] = []
    prev_dash = False
    for ch in cleaned:
        if ch in ("-", "_", "."):
            if not prev_dash and out:
                out.append("-")
                prev_dash = True
        else:
            out.append(ch)
            prev_dash = False
    if out and out[-1] == "-":
        out.pop()
    return "".join(out)


def resolve_pypi_package_name(import_name: str) -> str:
    """Map an imported module name to its PyPI distribution name if known."""
    if import_name in IMPORT_TO_PACKAGE:
        return IMPORT_TO_PACKAGE[import_name]
    lower_name = import_name.lower()
    if lower_name in LOWER_IMPORT_TO_PACKAGE:
        return LOWER_IMPORT_TO_PACKAGE[lower_name]
    return import_name


def is_test_path(file_path: Path, rel_path: str) -> bool:
    """Detect whether a file is a test file or lives inside a test_* directory."""
    lower_name = file_path.name.lower()
    if lower_name.startswith("test_") or lower_name.endswith("_test.py"):
        return True
    parts = Path(rel_path).parts
    for part in parts[:-1]:
        lower_part = part.lower()
        if lower_part.startswith("test_") or lower_part in ("test", "tests"):
            return True
    return False


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings in pure Python."""
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    if len(s1) < len(s2):
        s1, s2 = s2, s1

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, start=1):
        current_row = [i]
        for j, c2 in enumerate(s2, start=1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (0 if c1 == c2 else 1)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_typosquatting(package_name: str) -> tuple[str, int] | None:
    """Check whether package_name is within 1-2 edits of a popular PyPI package."""
    raw_lower = package_name.strip().lower()
    canon = canonicalize_name(package_name)
    if not canon:
        return None

    top_canon_map = {canonicalize_name(p): p for p in TOP_PYPI_PACKAGES}
    if canon in top_canon_map:
        return None

    best_match: tuple[str, int] | None = None
    for top_canon, top_display in top_canon_map.items():
        dist_raw = levenshtein_distance(raw_lower, top_display.lower())
        dist_canon = levenshtein_distance(canon, top_canon)
        dist = min(dist_raw, dist_canon)
        if dist == 0:
            return None

        max_allowed = 2 if len(top_canon) >= 6 else 1
        if len(canon) < 4:
            continue
        if dist <= max_allowed:
            if best_match is None or dist < best_match[1]:
                best_match = (top_display, dist)

    return best_match


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per character) using math.log2."""
    if not data:
        return 0.0
    length = len(data)
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def get_suppressed_lines(source_code: str) -> set[int]:
    """Return 1-based line numbers suppressed with '# halluciguard:ignore' or '# noqa'."""
    suppressed: set[int] = set()
    for lineno, line in enumerate(source_code.splitlines(), start=1):
        lower = line.lower()
        if "# halluciguard:ignore" in lower or "# halluciguard: ignore" in lower or "# noqa" in lower:
            suppressed.add(lineno)
    return suppressed


def build_safe_diff(
    source_line: str,
    rule_id: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Generate a read-only safe code diff and mark whether it is auto-patchable."""
    original = source_line.strip()
    if not original:
        return None
    extra = extra or {}

    def _pack(before: str, after: str, auto_patchable: bool = False) -> dict[str, Any]:
        return {"before": before, "after": after, "auto_patchable": auto_patchable}

    if rule_id == "method:requests.get_json":
        updated = re.sub(r"\b(\w+)\.get_json\(([^)]*)\)", r"\1.get(\2).json()", original, count=1)
        return _pack(original, updated, auto_patchable=(updated != original))
    if rule_id == "method:requests.post_json":
        updated = original.replace(".post_json(", ".post(")
        return _pack(original, updated + "  # pass via json=... parameter")
    if rule_id == "method:requests.fetch":
        return _pack(original, original.replace(".fetch(", ".get("), auto_patchable=(".fetch(" in original))
    if rule_id in ("method:json.loads_safe", "method:json.parse"):
        fn_name = "loads_safe(" if "loads_safe(" in original else "parse("
        return _pack(original, original.replace(fn_name, "loads(") + "  # wrap with try/except json.JSONDecodeError")
    if rule_id == "method:json.load_safe":
        return _pack(original, original.replace("load_safe(", "load(") + "  # wrap with try/except json.JSONDecodeError")
    if rule_id == "method:json.stringify":
        return _pack(original, original.replace(".stringify(", ".dumps("), auto_patchable=(".stringify(" in original))
    if rule_id == "method:os.path.exists_fast":
        return _pack(original, original.replace("exists_fast(", "exists("), auto_patchable=("exists_fast(" in original))
    if rule_id == "method:os.mkdir_p":
        return _pack(original, original.replace("mkdir_p(", "makedirs(").rstrip(")") + ", exist_ok=True)")
    if rule_id == "method:pandas.read_pdf":
        return _pack(original, "# Use pdfplumber/tabula-py for PDF tables and construct pd.DataFrame(...)")
    if rule_id == "method:pandas.append":
        return _pack(original, "# pandas 2.0+: df = pd.concat([df, new_df], ignore_index=True)")
    if rule_id in ("method:datetime.parse", "method:datetime.datetime.parse"):
        return _pack(original, original.replace(".parse(", ".fromisoformat("), auto_patchable=(".parse(" in original))
    if rule_id == "method:hashlib.md5_hex":
        updated = re.sub(r"(\w+)\.md5_hex\(([^)]*)\)", r"\1.sha256(\2).hexdigest()", original, count=1)
        return _pack(original, updated, auto_patchable=(updated != original))
    if rule_id == "method:hashlib.sha256_hex":
        updated = re.sub(r"(\w+)\.sha256_hex\(([^)]*)\)", r"\1.sha256(\2).hexdigest()", original, count=1)
        return _pack(original, updated, auto_patchable=(updated != original))

    if rule_id == "unsafe:eval":
        return _pack(original, original.replace("eval(", "ast.literal_eval("))
    if rule_id == "unsafe:exec":
        return _pack(original, "# Use safe explicit function dispatch dict instead of dynamic exec()")
    if rule_id in ("unsafe:yaml.load", "yaml:insecure"):
        updated = original.replace(".unsafe_load(", ".safe_load(").replace(".load(", ".safe_load(")
        if updated == original:
            updated = re.sub(r"\b(?:unsafe_load|load)\(", "safe_load(", original, count=1)
        updated = re.sub(r",\s*Loader\s*=[^,)]+", "", updated)
        return _pack(original, updated, auto_patchable=(updated != original))
    if rule_id == "unsafe:shell_true":
        updated = re.sub(r"shell\s*=\s*True", "shell=False", original)
        return _pack(original, updated, auto_patchable=(updated != original))
    if rule_id == "unsafe:os.system":
        return _pack(original, 'subprocess.run(["cmd", "arg"], shell=False, check=True)')
    if rule_id in ("unsafe:pickle", "unsafe:marshal", "unsafe:shelve"):
        return _pack(original, "# Use json.loads(...) instead of pickle/marshal/shelve for untrusted data")
    if rule_id == "unsafe:md5":
        updated = re.sub(r"hashlib\.md5\b|\bmd5\b", "hashlib.sha256", original, count=1)
        return _pack(original, updated, auto_patchable=("hashlib.md5(" in original))
    if rule_id == "unsafe:sha1":
        updated = re.sub(r"hashlib\.sha1\b|\bsha1\b", "hashlib.sha256", original, count=1)
        return _pack(original, updated, auto_patchable=("hashlib.sha1(" in original))
    if rule_id == "temp:mktemp":
        updated = original.replace(".mktemp(", ".mkstemp(")
        return _pack(original, updated, auto_patchable=(".mktemp(" in original))
    if rule_id == "web:debug":
        updated = re.sub(r"\bdebug\s*=\s*True\b", "debug=False", original)
        updated = re.sub(r"\bDEBUG\s*=\s*True\b", "DEBUG = False", updated)
        return _pack(original, updated, auto_patchable=(updated != original))
    if rule_id == "ssl:verify_false":
        updated = re.sub(r"\bverify\s*=\s*False\b", "verify=True", original)
        updated = re.sub(r"\bssl\s*=\s*False\b", "ssl=True", updated)
        return _pack(original, updated, auto_patchable=(updated != original))
    if rule_id == "except:bare":
        updated = re.sub(r"^except\s*:", "except Exception:", original)
        return _pack(original, updated, auto_patchable=(updated != original))
    if rule_id == "cors:wildcard":
        return _pack(original, '# Specify explicit allowed origins instead of ["*"]: ["https://app.example.com"]')
    if rule_id == "global:mutable":
        return _pack(original, "# Use threading.Lock / asyncio.Lock or class state instead of global mutable state")
    if rule_id == "redirect:unvalidated":
        return _pack(original, "# Validate that target URL is in allowed hosts whitelist before redirect()")
    if rule_id == "ip:internal":
        return _pack(original, "# Configure internal IP via os.environ.get('SERVICE_HOST') instead of hardcoding")
    if rule_id == "stdlib:deprecated":
        return _pack(original, f"# Recommended modern alternative: {extra.get('replacement', 'modern stdlib')}")

    if rule_id == "random:weak":
        var_name = str(extra.get("var_name", "token"))
        return _pack(original, f"{var_name} = secrets.token_hex(32)  # Cryptographically secure random token")
    if rule_id == "path:traversal":
        return _pack(original, "safe_path = (BASE_DIR / Path(user_path).name).resolve(); assert safe_path.is_relative_to(BASE_DIR)")
    if rule_id == "llm:rce":
        return _pack(original, "# Never execute LLM output with eval()/exec(); validate against JSON schema (json.loads)")
    if rule_id == "taint:sql":
        return _pack(original, 'cursor.execute("SELECT * FROM items WHERE id = ?", (safe_param,))')
    if rule_id == "secret:hardcoded":
        var_name = str(extra.get("var_name", "SECRET_KEY"))
        masked = str(extra.get("masked", "****"))
        env_key = re.sub(r"[^A-Za-z0-9]+", "_", var_name).upper().strip("_") or "API_SECRET"
        return _pack(f'{var_name} = "{masked}"', f'{var_name} = os.environ.get("{env_key}", "")')
    if rule_id == "prompt:unvalidated":
        return _pack(original, '{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": sanitize_user_input(user_input)}')
    if rule_id == "prompt:jailbreak":
        return _pack(original, "# Remove embedded jailbreak/override command and maintain static system prompt")
    if rule_id == "obfuscated:code":
        return _pack(original, "# Use explicit static imports or safe registry instead of dynamic/obfuscated execution")
    if rule_id == "agent:unrestricted":
        return _pack(original, "# Add permission whitelist / user approval (require_approval) check at function entry")
    if rule_id == "build:hook":
        return _pack(original, "# Remove network/shell execution from setup.py; use declarative pyproject.toml")

    return None


@dataclass
class DiscoveredDependency:
    """Represents a raw dependency collected from AST or project manifests."""

    raw_name: str
    origin_kind: str
    source_locations: list[str] = field(default_factory=list)
    is_relative: bool = False
    importer_dirs: set[Path] = field(default_factory=set)
    has_exact_pin: bool = False

    def add_source(self, location: str, importer_dir: Path | None = None, exact_pin: bool = False) -> None:
        if location not in self.source_locations:
            self.source_locations.append(location)
        if importer_dir is not None:
            self.importer_dirs.add(importer_dir)
        if exact_pin:
            self.has_exact_pin = True


@dataclass
class ScanFinding:
    """Final supply chain security assessment for a dependency or module (Table 1)."""

    display_name: str
    pypi_name: str
    sources: list[str]
    status: str
    subtype: str
    detail: str
    cache_hit: bool = False
    age_days: float | None = None
    release_count: int | None = None
    warnings: list[str] = field(default_factory=list)
    typosquat_target: str | None = None
    typosquat_distance: int | None = None
    suggestion_diff: dict[str, Any] | None = None

    def to_dict(self, include_suggest: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "package": self.display_name,
            "pypi_name": self.pypi_name,
            "sources": self.sources,
            "status": self.status,
            "subtype": self.subtype,
            "detail": self.detail,
            "cache_hit": self.cache_hit,
            "age_days": round(self.age_days, 2) if self.age_days is not None else None,
            "release_count": self.release_count,
            "warnings": self.warnings,
            "typosquat_target": self.typosquat_target,
            "typosquat_distance": self.typosquat_distance,
        }
        if include_suggest and self.suggestion_diff is not None:
            payload["suggestion_diff"] = self.suggestion_diff
        return payload


@dataclass
class SastFinding:
    """Static code / AI hallucination / Module W hygiene finding (Table 2)."""

    file_line: str
    severity: str
    category: str
    details: str
    suggestion_diff: dict[str, Any] | None = None
    taint_chain: str | None = None
    rel_file: str = ""
    lineno: int = 0

    def to_dict(self, include_suggest: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "location": self.file_line,
            "severity": self.severity,
            "category": self.category,
            "details": self.details,
        }
        if self.taint_chain:
            payload["taint_chain"] = self.taint_chain
        if include_suggest and self.suggestion_diff is not None:
            payload["suggestion_diff"] = self.suggestion_diff
        return payload


@dataclass
class DomainCandidate:
    """Represents an extracted URL/domain found in an AST string literal."""

    domain: str
    url: str
    file_line: str


class SecurityASTVisitor(ast.NodeVisitor):
    """Unified AST visitor covering v2.0 through v6.0 (20-point Module W)."""

    def __init__(
        self,
        rel_path: str,
        file_name: str,
        source_lines: list[str],
        suppressed_lines: set[int],
        *,
        is_test_file: bool = False,
        check_domains: bool = False,
        check_methods: bool = False,
        check_secrets: bool = False,
        check_unsafe: bool = False,
        check_prompts: bool = False,
        check_obfuscation: bool = False,
        check_agents: bool = False,
    ) -> None:
        self.rel_path = rel_path
        self.file_name = file_name.lower()
        self.is_build_script = self.file_name in BUILD_HOOK_FILENAMES
        self.source_lines = source_lines
        self.suppressed_lines = suppressed_lines
        self.is_test_file = is_test_file
        self.check_domains = check_domains
        self.check_methods = check_methods
        self.check_secrets = check_secrets
        self.check_unsafe = check_unsafe
        self.check_prompts = check_prompts
        self.check_obfuscation = check_obfuscation
        self.check_agents = check_agents

        # Table 1 data
        self.imports: list[tuple[str, int, bool]] = []

        # Alias, concurrency & multi-step taint tracking
        self.module_aliases: dict[str, str] = {}
        self.symbol_aliases: dict[str, str] = {}
        self.uses_concurrency = False
        self._in_async_fn = False
        self.tainted_vars: dict[str, tuple[int, str, bool, bool]] = {}
        self.agent_tool_candidates: set[str] = set()
        self._function_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self._emitted_keys: set[tuple[str, str, str]] = set()

        # Table 2 data
        self.domain_candidates: list[DomainCandidate] = []
        self.sast_findings: list[SastFinding] = []

    def _is_suppressed(self, node: ast.AST) -> bool:
        lineno = getattr(node, "lineno", None)
        if lineno is None:
            return False
        end_lineno = getattr(node, "end_lineno", lineno) or lineno
        return any(ln in self.suppressed_lines for ln in range(lineno, end_lineno + 1))

    def _loc(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 0)
        return f"{self.rel_path}:{lineno}"

    def _line_text(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 0)
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def _emit_finding(self, finding: SastFinding, node: ast.AST | None = None) -> None:
        if node is not None and finding.lineno == 0:
            finding.lineno = getattr(node, "lineno", 0)
        if not finding.rel_file:
            finding.rel_file = self.rel_path
        key = (finding.file_line, finding.category, finding.details)
        if key not in self._emitted_keys:
            self._emitted_keys.add(key)
            self.sast_findings.append(finding)

    def _check_deprecated_stdlib(self, top_level: str, node: ast.AST) -> None:
        if not self.check_unsafe or self.is_test_file:
            return
        if top_level in DEPRECATED_STDLIB_MODULES:
            repl = DEPRECATED_STDLIB_MODULES[top_level]
            self._emit_finding(
                SastFinding(
                    file_line=self._loc(node),
                    severity=SEVERITY_DEPRECATED_MOD_WARNING,
                    category="Deprecated Stdlib",
                    details=f"Deprecated or removed standard module '{top_level}': {repl}",
                    suggestion_diff=build_safe_diff(self._line_text(node), "stdlib:deprecated", {"replacement": repl}),
                ),
                node,
            )

    def visit_Import(self, node: ast.Import) -> None:
        suppressed = self._is_suppressed(node)
        for alias in node.names:
            as_name = alias.asname or alias.name.split(".", 1)[0]
            self.module_aliases[as_name] = alias.name
            top_level = alias.name.split(".", 1)[0].strip()
            if top_level in ("threading", "asyncio", "concurrent", "multiprocessing"):
                self.uses_concurrency = True
            if not suppressed and top_level:
                self.imports.append((top_level, node.lineno, False))
                self._check_deprecated_stdlib(top_level, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        suppressed = self._is_suppressed(node)
        if node.level == 0 and node.module:
            top_mod = node.module.split(".", 1)[0].strip()
            if top_mod in ("threading", "asyncio", "concurrent", "multiprocessing"):
                self.uses_concurrency = True
            for alias in node.names:
                if alias.name == "*":
                    continue
                as_name = alias.asname or alias.name
                full_target = f"{node.module}.{alias.name}"
                self.symbol_aliases[as_name] = full_target
                self.module_aliases[as_name] = full_target

        if not suppressed:
            if node.level > 0:
                mod_name = node.module.split(".", 1)[0].strip() if node.module else ""
                if not mod_name and node.names:
                    mod_name = node.names[0].name.split(".", 1)[0].strip()
                display = ("." * node.level) + (mod_name or "")
                self.imports.append((display or ".", node.lineno, True))
            elif node.module:
                top_level = node.module.split(".", 1)[0].strip()
                if top_level:
                    self.imports.append((top_level, node.lineno, False))
                    self._check_deprecated_stdlib(top_level, node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, str) or self.is_test_file or self._is_suppressed(node):
            self.generic_visit(node)
            return

        val = node.value
        lower_val = val.lower()

        if self.check_domains and ("http://" in lower_val or "https://" in lower_val):
            for match in URL_EXTRACT_RE.finditer(val):
                raw_url = match.group(0).rstrip(".,;:!?'\"\\)}>]")
                domain = extract_checkable_domain(raw_url)
                if domain is not None:
                    self.domain_candidates.append(
                        DomainCandidate(domain=domain, url=raw_url, file_line=self._loc(node))
                    )

        # Module W Checks #2, #3, #10, #17 on String Literals
        if self.check_secrets or self.check_unsafe:
            if PRIVATE_KEY_RE.search(val):
                self._emit_finding(
                    SastFinding(
                        file_line=self._loc(node),
                        severity=SEVERITY_PRIVATE_KEY_DANGER,
                        category="Hardcoded Private Key",
                        details="Hardcoded private cryptographic key (PRIVATE KEY block) detected in source code!",
                    ),
                    node,
                )

            db_match = DB_CONN_RE.search(val)
            if db_match and not any(ph in lower_val for ph in ("<user>", "<pass>", "{user}", "{password}", "user:pass@")):
                self._emit_finding(
                    SastFinding(
                        file_line=self._loc(node),
                        severity=SEVERITY_DB_STRING_DANGER,
                        category="Hardcoded DB String",
                        details="Hardcoded database connection string containing plaintext credentials detected",
                    ),
                    node,
                )

            for token_label, token_re in CLOUD_TOKEN_PATTERNS:
                t_match = token_re.search(val)
                if t_match:
                    tok = t_match.group(0)
                    masked = f"{tok[:6]}****{tok[-4:]}"
                    self._emit_finding(
                        SastFinding(
                            file_line=self._loc(node),
                            severity=SEVERITY_CLOUD_TOKEN_DANGER,
                            category="Hardcoded Cloud Token",
                            details=f"Hardcoded {token_label} detected ({masked}) — Move to environment variables",
                        ),
                        node,
                    )

        if self.check_unsafe and len(val) <= 256:
            for ip_match in IPV4_RE.finditer(val):
                ip_str = ip_match.group(1)
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                if ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_unspecified:
                    self._emit_finding(
                        SastFinding(
                            file_line=self._loc(node),
                            severity=SEVERITY_INTERNAL_IP_INFO,
                            category="Hardcoded Internal IP",
                            details=f"Hardcoded internal/private network IP address ({ip_str}) — Move to configuration",
                            suggestion_diff=build_safe_diff(self._line_text(node), "ip:internal"),
                        ),
                        node,
                    )
                    break

        self.generic_visit(node)

    def _resolve_attr_chain(self, node: ast.AST) -> list[str] | None:
        parts: list[str] = []
        curr: ast.AST = node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
            parts.reverse()
            return parts
        return None

    def _resolve_full_callable(self, func_node: ast.AST) -> str | None:
        if isinstance(func_node, ast.Name):
            name = func_node.id
            return self.symbol_aliases.get(name, name)
        chain = self._resolve_attr_chain(func_node)
        if not chain:
            return None
        root = chain[0]
        resolved_root = self.module_aliases.get(root, self.symbol_aliases.get(root, root))
        if len(chain) == 1:
            return resolved_root
        return f"{resolved_root}.{'.'.join(chain[1:])}"

    def _is_sanitizer_call(self, call_node: ast.Call) -> bool:
        called = self._resolve_full_callable(call_node.func) or ""
        lower_fn = called.rsplit(".", 1)[-1].lower()
        return any(
            word in lower_fn
            for word in ("sanitize", "escape", "clean", "validate", "filter", "strip_tags", "bleach")
        )

    def _is_llm_api_call(self, resolved_callable: str) -> bool:
        if resolved_callable in LLM_DIRECT_CALLS:
            return True
        return any(resolved_callable.endswith(suffix) for suffix in LLM_CALL_SUFFIXES)

    def _matches_taint_source(self, full_name: str) -> bool:
        if full_name in TAINT_INPUT_CALLS or any(
            full_name.endswith("." + c) for c in TAINT_INPUT_CALLS if "." in c
        ):
            return True
        for pref in TAINT_INPUT_PREFIXES:
            if full_name == pref or full_name.startswith(pref + ".") or ("." + pref) in full_name:
                return True
        return False

    def _expr_taint_info(self, expr: ast.AST) -> tuple[int, str, bool, bool] | None:
        """Inspect expr for direct or propagated taint (origin_lineno, label, is_llm, is_multistep)."""
        if isinstance(expr, ast.Call):
            if self._is_sanitizer_call(expr):
                return None
            called = self._resolve_full_callable(expr.func) or ""
            lineno = getattr(expr, "lineno", 0)
            if self._is_llm_api_call(called):
                return (lineno, f"LLM output '{called}()'", True, False)
            if self._matches_taint_source(called):
                return (lineno, f"'{called}()'", False, False)

        if isinstance(expr, ast.Name):
            if expr.id in self.tainted_vars:
                return self.tainted_vars[expr.id]
            lower_id = expr.id.lower()
            if any(hint in lower_id for hint in LLM_OUTPUT_VAR_HINTS):
                return (getattr(expr, "lineno", 0), f"LLM output variable '{expr.id}'", True, False)

        if isinstance(expr, (ast.Attribute, ast.Subscript)):
            target_attr = expr.value if isinstance(expr, ast.Subscript) else expr
            chain = self._resolve_attr_chain(target_attr)
            if chain:
                resolved_prefix = self.module_aliases.get(chain[0], chain[0])
                full_joined = f"{resolved_prefix}.{'.'.join(chain[1:])}" if len(chain) > 1 else resolved_prefix
                lineno = getattr(expr, "lineno", 0)
                if self._matches_taint_source(full_joined):
                    return (lineno, f"external input '{full_joined}'", False, False)
                if any(full_joined.startswith(llm_attr) for llm_attr in LLM_OUTPUT_ATTR_CHAINS):
                    return (lineno, f"LLM response '{full_joined}'", True, False)
                if chain[0] in self.tainted_vars:
                    return self.tainted_vars[chain[0]]

        for child in ast.iter_child_nodes(expr):
            found = self._expr_taint_info(child)
            if found is not None:
                return found
        return None

    def _expr_is_dynamic_interpolation(self, expr: ast.AST) -> bool:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.JoinedStr):
                return True
            if isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.Add, ast.Mod)):
                if not isinstance(sub.left, ast.Constant) or not isinstance(sub.right, ast.Constant):
                    return True
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "format":
                return True
        return False

    def _expr_looks_like_sql(self, expr: ast.AST) -> bool:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                lower = sub.value.lower().lstrip()
                if any(kw in lower for kw in SQL_KEYWORDS):
                    return True
        return False

    def _find_jailbreak_signature(self, expr: ast.AST) -> str | None:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                lower_val = sub.value.lower()
                for sig in PROMPT_JAILBREAK_SIGNATURES:
                    if sig in lower_val:
                        return sig
        return None

    def _inspect_prompt_expression(
        self,
        expr: ast.AST,
        node: ast.AST,
        context_label: str,
        *,
        is_system_context: bool = False,
    ) -> None:
        sig = self._find_jailbreak_signature(expr)
        if sig:
            self._emit_finding(
                SastFinding(
                    file_line=self._loc(node),
                    severity=SEVERITY_PROMPT_DANGER,
                    category="Prompt Injection Risk",
                    details=f"Embedded prompt injection / override pattern detected in {context_label}: '{sig}'",
                    suggestion_diff=build_safe_diff(self._line_text(node), "prompt:jailbreak"),
                ),
                node,
            )
            return

        taint = self._expr_taint_info(expr)
        is_dynamic = self._expr_is_dynamic_interpolation(expr)

        if taint and (is_dynamic or is_system_context or isinstance(expr, (ast.Name, ast.Call, ast.Subscript, ast.Attribute))):
            src_line, src_label, _, is_multistep = taint
            sink_line = getattr(node, "lineno", 0)
            chain_txt = f"Line {src_line} -> Line {sink_line}" if src_line and sink_line != src_line else None
            if is_multistep and chain_txt:
                self._emit_finding(
                    SastFinding(
                        file_line=self._loc(node),
                        severity=SEVERITY_TAINT_FLOW_DANGER,
                        category="Tainted Data Flow",
                        details=f"Multi-step tainted data flow ({chain_txt}): unvalidated {src_label} flows into {context_label}",
                        suggestion_diff=build_safe_diff(self._line_text(node), "prompt:unvalidated"),
                        taint_chain=chain_txt,
                    ),
                    node,
                )
            else:
                self._emit_finding(
                    SastFinding(
                        file_line=self._loc(node),
                        severity=SEVERITY_PROMPT_WARNING,
                        category="Prompt Injection Risk",
                        details=f"Unvalidated {src_label} passed directly into {context_label} (Unvalidated Prompt Sink)",
                        suggestion_diff=build_safe_diff(self._line_text(node), "prompt:unvalidated"),
                        taint_chain=chain_txt,
                    ),
                    node,
                )
            return

        if is_system_context and is_dynamic:
            self._emit_finding(
                SastFinding(
                    file_line=self._loc(node),
                    severity=SEVERITY_PROMPT_WARNING,
                    category="Prompt Injection Risk",
                    details=f"Dynamic formatting (f-string / .format) applied to system prompt ({context_label})",
                    suggestion_diff=build_safe_diff(self._line_text(node), "prompt:unvalidated"),
                ),
                node,
            )

    def _inspect_llm_call_prompts(self, node: ast.Call, resolved_callable: str) -> None:
        """Traverse ALL nested ast.Dict/List/JoinedStr nodes via ast.walk() without duplicates."""
        if not self._is_llm_api_call(resolved_callable):
            return

        checked_ids: set[int] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Dict):
                role_val = None
                target_nodes: list[ast.AST] = []
                for k_node, v_node in zip(sub.keys, sub.values):
                    if isinstance(k_node, ast.Constant) and k_node.value == "role":
                        if isinstance(v_node, ast.Constant) and isinstance(v_node.value, str):
                            role_val = v_node.value.lower()
                    if isinstance(k_node, ast.Constant) and k_node.value in ("content", "text", "prompt"):
                        if v_node is not None:
                            target_nodes.append(v_node)
                for content_node in target_nodes:
                    self._inspect_prompt_expression(
                        content_node,
                        sub,
                        f"LLM {role_val or 'message'} content ({resolved_callable})",
                        is_system_context=(role_val == "system"),
                    )
                    checked_ids.update(id(x) for x in ast.walk(content_node))
                if target_nodes:
                    checked_ids.add(id(sub))

        def _inspect_unchecked_expr(expr: ast.AST, ctx: str, is_sys: bool) -> None:
            if id(expr) in checked_ids:
                return
            if isinstance(expr, (ast.List, ast.Tuple, ast.Dict)):
                for child in ast.iter_child_nodes(expr):
                    _inspect_unchecked_expr(child, ctx, is_sys)
                return
            target_node = expr if hasattr(expr, "lineno") else node
            self._inspect_prompt_expression(expr, target_node, ctx, is_system_context=is_sys)
            checked_ids.update(id(x) for x in ast.walk(expr))

        for arg in node.args:
            _inspect_unchecked_expr(arg, f"LLM invocation ({resolved_callable})", False)

        for kw in node.keywords:
            if not kw.arg or kw.arg not in LLM_PROMPT_ARG_NAMES:
                continue
            is_sys = kw.arg in ("system", "system_instruction")
            _inspect_unchecked_expr(kw.value, f"LLM '{kw.arg}' parameter ({resolved_callable})", is_sys)

    def _check_obfuscated_call(self, node: ast.Call, resolved_callable: str) -> bool:
        """Module N: Detect obfuscated imports and dynamic encoded execution."""
        loc = self._loc(node)
        line_text = self._line_text(node)

        if resolved_callable in ("__import__", "importlib.import_module"):
            if node.args and not (isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                self._emit_finding(
                    SastFinding(
                        file_line=loc,
                        severity=SEVERITY_OBFUSCATED_DANGER,
                        category="Obfuscated Code",
                        details=f"Obfuscated dynamic module import: non-literal/encoded expression in {resolved_callable}()",
                        suggestion_diff=build_safe_diff(line_text, "obfuscated:code"),
                    ),
                    node,
                )
                return True

        if resolved_callable in ("exec", "eval"):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    inner_fn = self._resolve_full_callable(sub.func) or ""
                    if inner_fn in OBFUSCATED_DECODE_CALLS or inner_fn == "compile":
                        self._emit_finding(
                            SastFinding(
                                file_line=loc,
                                severity=SEVERITY_OBFUSCATED_DANGER,
                                category="Obfuscated Code",
                                details=f"Obfuscated backdoor code execution pattern: {resolved_callable}({inner_fn}(...))",
                                suggestion_diff=build_safe_diff(line_text, "obfuscated:code"),
                            ),
                            node,
                        )
                        return True

        if resolved_callable == "getattr" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id in ("__builtins__", "builtins"):
                self._emit_finding(
                    SastFinding(
                        file_line=loc,
                        severity=SEVERITY_OBFUSCATED_DANGER,
                        category="Obfuscated Code",
                        details="Stealth builtin function resolution via getattr(__builtins__, ...) (Obfuscation)",
                        suggestion_diff=build_safe_diff(line_text, "obfuscated:code"),
                    ),
                    node,
                )
                return True

        return False

    def _check_build_hook_call(self, node: ast.Call, resolved_callable: str) -> None:
        """Module I: Detect subprocess/network execution in setup.py / tasks.py."""
        if not self.is_build_script:
            return
        if any(resolved_callable.startswith(pref) or resolved_callable == pref for pref in BUILD_HOOK_DANGEROUS_PREFIXES):
            self._emit_finding(
                SastFinding(
                    file_line=self._loc(node),
                    severity=SEVERITY_BUILD_HOOK_DANGER,
                    category="Malicious Build Hook",
                    details=f"External process execution or network call in build/setup script ({self.file_name}): {resolved_callable}()",
                    suggestion_diff=build_safe_diff(self._line_text(node), "build:hook"),
                ),
                node,
            )

    def _check_path_traversal_and_sql(self, node: ast.Call, resolved_callable: str) -> bool:
        """Module K, Module M & Module W Checks #9, #11: Path Traversal & SQL Injection."""
        loc = self._loc(node)
        line_text = self._line_text(node)
        sink_line = getattr(node, "lineno", 0)

        is_open_sink = resolved_callable in ("open", "io.open", "os.remove", "os.unlink")
        is_path_method = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("read_text", "read_bytes", "write_text", "write_bytes", "open")
            and isinstance(node.func.value, ast.Call)
            and (self._resolve_full_callable(node.func.value.func) or "").endswith("Path")
        )
        if is_open_sink and node.args:
            arg0 = node.args[0]
            taint = self._expr_taint_info(arg0)
            if taint:
                src_line, src_label, _, is_multistep = taint
                chain_txt = f"Line {src_line} -> Line {sink_line}" if src_line and src_line != sink_line else None
                sev = SEVERITY_TAINT_FLOW_DANGER if (is_multistep and chain_txt) else SEVERITY_PATH_TRAVERSAL_WARNING
                cat = "Tainted Data Flow" if (is_multistep and chain_txt) else "Path Traversal"
                self._emit_finding(
                    SastFinding(
                        file_line=loc,
                        severity=sev,
                        category=cat,
                        details=f"Unvalidated {src_label} flows directly into file access call ({resolved_callable}())",
                        suggestion_diff=build_safe_diff(line_text, "path:traversal"),
                        taint_chain=chain_txt,
                    ),
                    node,
                )
                return True
            if self._expr_is_dynamic_interpolation(arg0):
                self._emit_finding(
                    SastFinding(
                        file_line=loc,
                        severity=SEVERITY_PATH_TRAVERSAL_WARNING,
                        category="Path Traversal",
                        details=f"Dynamic path concatenation ({resolved_callable}()) — Path Traversal risk",
                        suggestion_diff=build_safe_diff(line_text, "path:traversal"),
                    ),
                    node,
                )
                return True

        if is_path_method and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            path_call = node.func.value
            if path_call.args:
                taint = self._expr_taint_info(path_call.args[0])
                if taint:
                    src_line, src_label, _, is_multistep = taint
                    chain_txt = f"Line {src_line} -> Line {sink_line}" if src_line and src_line != sink_line else None
                    sev = SEVERITY_TAINT_FLOW_DANGER if (is_multistep and chain_txt) else SEVERITY_PATH_TRAVERSAL_WARNING
                    cat = "Tainted Data Flow" if (is_multistep and chain_txt) else "Path Traversal"
                    self._emit_finding(
                        SastFinding(
                            file_line=loc,
                            severity=sev,
                            category=cat,
                            details=f"Path Traversal risk: {src_label} passed directly into Path(...).{node.func.attr}()",
                            suggestion_diff=build_safe_diff(line_text, "path:traversal"),
                            taint_chain=chain_txt,
                        ),
                        node,
                    )
                    return True

        # Check #9: SQL Injection via String Formatting (direct OR tainted)
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany"):
            if node.args:
                sql_arg = node.args[0]
                taint = self._expr_taint_info(sql_arg)
                is_dyn = self._expr_is_dynamic_interpolation(sql_arg)
                if taint and is_dyn:
                    src_line, src_label, _, _ = taint
                    chain_txt = f"Line {src_line} -> Line {sink_line}" if src_line and src_line != sink_line else None
                    self._emit_finding(
                        SastFinding(
                            file_line=loc,
                            severity=SEVERITY_TAINT_FLOW_DANGER,
                            category="Tainted Data Flow",
                            details=f"Multi-step SQL Injection risk ({chain_txt or loc}): {src_label} formatted into unparameterized SQL query",
                            suggestion_diff=build_safe_diff(line_text, "taint:sql"),
                            taint_chain=chain_txt,
                        ),
                        node,
                    )
                    return True
                if is_dyn and self._expr_looks_like_sql(sql_arg):
                    self._emit_finding(
                        SastFinding(
                            file_line=loc,
                            severity=SEVERITY_SQLI_DANGER,
                            category="SQL Injection",
                            details="SQL query constructed via string formatting (f-string / % / + / .format) — Use parameterized queries (?)",
                            suggestion_diff=build_safe_diff(line_text, "taint:sql"),
                        ),
                        node,
                    )
                    return True

        return False

    def visit_Call(self, node: ast.Call) -> None:
        if not self._is_suppressed(node):
            resolved = self._resolve_full_callable(node.func)

            if self.check_agents:
                for kw in node.keywords:
                    if kw.arg == "tools" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Name):
                                self.agent_tool_candidates.add(elt.id)

            if not self.is_test_file and self.check_unsafe and resolved is None:
                self._check_path_traversal_and_sql(node, "")

            if resolved:
                if self.check_unsafe:
                    self._check_build_hook_call(node, resolved)

                if not self.is_test_file:
                    if self.check_obfuscation and self._check_obfuscated_call(node, resolved):
                        self.generic_visit(node)
                        return

                    if self.check_methods:
                        self._check_hallucinated_method(node, resolved)

                    if self.check_unsafe:
                        handled_taint = self._check_path_traversal_and_sql(node, resolved)
                        if not handled_taint:
                            self._check_unsafe_call(node, resolved)

                    if self.check_prompts:
                        self._inspect_llm_call_prompts(node, resolved)

                    if self.check_secrets:
                        for kw in node.keywords:
                            if kw.arg and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                self._inspect_secret_candidate(kw.arg, kw.value.value, node)

        self.generic_visit(node)

    def _check_hallucinated_method(self, node: ast.Call, resolved_callable: str) -> None:
        if "." not in resolved_callable:
            return
        module_part, method_name = resolved_callable.rsplit(".", 1)
        rules = HALLUCINATED_METHODS.get(module_part)
        if rules and method_name in rules:
            suggestion = rules[method_name]
            rule_id = f"method:{module_part}.{method_name}"
            self._emit_finding(
                SastFinding(
                    file_line=self._loc(node),
                    severity=SEVERITY_METHOD_WARNING,
                    category="Hallucinated Method",
                    details=f"'{resolved_callable}()' does not exist in module '{module_part}'. Suggestion: {suggestion}",
                    suggestion_diff=build_safe_diff(self._line_text(node), rule_id),
                ),
                node,
            )

    def _yaml_uses_safe_loader(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "Loader":
                loader_name = self._resolve_full_callable(kw.value) or ""
                if loader_name.endswith(("SafeLoader", "CSafeLoader", "BaseLoader")):
                    return True
        if len(node.args) >= 2:
            loader_name = self._resolve_full_callable(node.args[1]) or ""
            if loader_name.endswith(("SafeLoader", "CSafeLoader", "BaseLoader")):
                return True
        return False

    def _check_unsafe_call(self, node: ast.Call, resolved_callable: str) -> None:
        loc = self._loc(node)
        line_text = self._line_text(node)
        sink_line = getattr(node, "lineno", 0)

        # Check #19 + Module K + Module M: eval / exec
        if resolved_callable in ("eval", "exec"):
            if node.args:
                taint = self._expr_taint_info(node.args[0])
                if taint:
                    src_line, src_label, is_llm, is_multistep = taint
                    chain_txt = f"Line {src_line} -> Line {sink_line}" if src_line and src_line != sink_line else None
                    if is_llm:
                        self._emit_finding(
                            SastFinding(
                                file_line=loc,
                                severity=SEVERITY_LLM_RCE_DANGER,
                                category="LLM-to-Code RCE",
                                details=f"AI-generated output ({src_label}) executed directly via {resolved_callable}()!",
                                suggestion_diff=build_safe_diff(line_text, "llm:rce"),
                                taint_chain=chain_txt,
                            ),
                            node,
                        )
                        return
                    if is_multistep and chain_txt:
                        self._emit_finding(
                            SastFinding(
                                file_line=loc,
                                severity=SEVERITY_TAINT_FLOW_DANGER,
                                category="Tainted Data Flow",
                                details=f"Multi-step tainted data flow ({chain_txt}): {src_label} -> {resolved_callable}()",
                                suggestion_diff=build_safe_diff(line_text, f"unsafe:{resolved_callable}"),
                                taint_chain=chain_txt,
                            ),
                            node,
                        )
                        return

            self._emit_finding(
                SastFinding(
                    file_line=loc,
                    severity=SEVERITY_UNSAFE_WARNING,
                    category="Unsafe Code Pattern",
                    details=f"Dynamic code execution ({resolved_callable}()) — Remote Code Execution (RCE) risk",
                    suggestion_diff=build_safe_diff(line_text, f"unsafe:{resolved_callable}"),
                ),
                node,
            )
            return

        # Check #7 / Module H: Insecure YAML Load
        if resolved_callable == "yaml.unsafe_load" or (
            resolved_callable == "yaml.load" and not self._yaml_uses_safe_loader(node)
        ):
            self._emit_finding(
                SastFinding(
                    file_line=loc,
                    severity=SEVERITY_YAML_WARNING,
                    category="Insecure YAML Load",
                    details=f"Insecure YAML loading ({resolved_callable}() without SafeLoader) — Remote Code Execution risk",
                    suggestion_diff=build_safe_diff(line_text, "yaml:insecure"),
                ),
                node,
            )
            return

        # Check #1: Insecure Deserialization (pickle, cPickle, _pickle, marshal, shelve)
        if resolved_callable in (
            "pickle.loads",
            "pickle.load",
            "cPickle.loads",
            "cPickle.load",
            "_pickle.loads",
            "_pickle.load",
            "marshal.loads",
            "marshal.load",
            "shelve.open",
        ):
            kind = "pickle"
            if resolved_callable.startswith("marshal"):
                kind = "marshal"
            elif resolved_callable.startswith("shelve"):
                kind = "shelve"
            self._emit_finding(
                SastFinding(
                    file_line=loc,
                    severity=SEVERITY_DESERIALIZATION_DANGER,
                    category="Insecure Deserialization",
                    details=f"Insecure deserialization ({resolved_callable}()) — Remote Code Execution risk on untrusted data",
                    suggestion_diff=build_safe_diff(line_text, f"unsafe:{kind}"),
                ),
                node,
            )
            return

        # Check #5: Insecure Temp Files (tempfile.mktemp)
        if resolved_callable == "tempfile.mktemp":
            self._emit_finding(
                SastFinding(
                    file_line=loc,
                    severity=SEVERITY_TEMP_FILE_WARNING,
                    category="Insecure Temp File",
                    details="Insecure temporary file creation (tempfile.mktemp()) — Race condition (TOCTOU) risk",
                    suggestion_diff=build_safe_diff(line_text, "temp:mktemp"),
                ),
                node,
            )
            return

        # Check #4: Dangerous Shell Injection (os.system / os.popen / subprocess shell=True)
        if resolved_callable in ("os.system", "os.popen"):
            if node.args:
                taint = self._expr_taint_info(node.args[0])
                if taint and taint[3]:
                    src_line, src_label, _, _ = taint
                    chain_txt = f"Line {src_line} -> Line {sink_line}"
                    self._emit_finding(
                        SastFinding(
                            file_line=loc,
                            severity=SEVERITY_TAINT_FLOW_DANGER,
                            category="Tainted Data Flow",
                            details=f"Multi-step Command Injection ({chain_txt}): {src_label} -> {resolved_callable}()",
                            suggestion_diff=build_safe_diff(line_text, "unsafe:os.system"),
                            taint_chain=chain_txt,
                        ),
                        node,
                    )
                    return
            self._emit_finding(
                SastFinding(
                    file_line=loc,
                    severity=SEVERITY_SHELL_DANGER,
                    category="Shell Injection",
                    details=f"Insecure OS command invocation ({resolved_callable}()) — Command Injection risk",
                    suggestion_diff=build_safe_diff(line_text, "unsafe:os.system"),
                ),
                node,
            )
            return

        if resolved_callable.startswith("subprocess."):
            fn_name = resolved_callable.split(".", 1)[1]
            if fn_name in SUBPROCESS_SHELL_SINKS:
                has_shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                taint = self._expr_taint_info(node.args[0]) if node.args else None
                if taint and taint[3]:
                    src_line, src_label, _, _ = taint
                    chain_txt = f"Line {src_line} -> Line {sink_line}"
                    self._emit_finding(
                        SastFinding(
                            file_line=loc,
                            severity=SEVERITY_TAINT_FLOW_DANGER,
                            category="Tainted Data Flow",
                            details=f"Multi-step Command Injection ({chain_txt}): {src_label} -> {resolved_callable}()",
                            suggestion_diff=build_safe_diff(line_text, "unsafe:shell_true"),
                            taint_chain=chain_txt,
                        ),
                        node,
                    )
                    return
                if has_shell_true:
                    self._emit_finding(
                        SastFinding(
                            file_line=loc,
                            severity=SEVERITY_SHELL_DANGER,
                            category="Shell Injection",
                            details=f"Insecure subprocess call ({resolved_callable}(..., shell=True)) — Command Injection risk",
                            suggestion_diff=build_safe_diff(line_text, "unsafe:shell_true"),
                        ),
                        node,
                    )
                    return

        # Check #6: Weak Cryptography (md5, sha1, crypt.crypt)
        if resolved_callable in ("hashlib.md5", "hashlib.sha1", "crypt.crypt"):
            algo = resolved_callable.split(".", 1)[1]
            self._emit_finding(
                SastFinding(
                    file_line=loc,
                    severity=SEVERITY_WEAK_CRYPTO_WARNING,
                    category="Weak Cryptography",
                    details=f"Weak cryptographic algorithm ({resolved_callable}()) — Use SHA-256+ or argon2/scrypt",
                    suggestion_diff=build_safe_diff(line_text, f"unsafe:{algo}"),
                ),
                node,
            )
            return

        # Check #12: Insecure Web Framework Debug (app.run(debug=True), uvicorn.run(debug=True))
        if resolved_callable.endswith(".run") or resolved_callable == "uvicorn.run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._emit_finding(
                        SastFinding(
                            file_line=loc,
                            severity=SEVERITY_DEBUG_WARNING,
                            category="Web Debug Enabled",
                            details=f"Dangerous debug mode enabled in production ({resolved_callable}(..., debug=True)) — Information disclosure / RCE risk",
                            suggestion_diff=build_safe_diff(line_text, "web:debug"),
                        ),
                        node,
                    )
                    return

        # Check #13: Disabled SSL Verification
        if resolved_callable == "ssl._create_unverified_context":
            self._emit_finding(
                SastFinding(
                    file_line=loc,
                    severity=SEVERITY_SSL_WARNING,
                    category="Disabled SSL",
                    details="TLS/SSL certificate validation disabled via ssl._create_unverified_context() (MitM risk)",
                    suggestion_diff=build_safe_diff(line_text, "ssl:verify_false"),
                ),
                node,
            )
            return
        if resolved_callable.startswith(("requests.", "httpx.", "aiohttp.")):
            for kw in node.keywords:
                if kw.arg in ("verify", "ssl") and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self._emit_finding(
                        SastFinding(
                            file_line=loc,
                            severity=SEVERITY_SSL_WARNING,
                            category="Disabled SSL",
                            details=f"SSL certificate verification disabled ({resolved_callable}(..., {kw.arg}=False)) (MitM risk)",
                            suggestion_diff=build_safe_diff(line_text, "ssl:verify_false"),
                        ),
                        node,
                    )
                    return

        # Check #15: Unvalidated Redirects
        if resolved_callable in (
            "redirect",
            "flask.redirect",
            "django.shortcuts.redirect",
            "HttpResponseRedirect",
            "RedirectResponse",
            "starlette.responses.RedirectResponse",
            "fastapi.responses.RedirectResponse",
        ):
            target_arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "url"), None)
            if target_arg is not None:
                taint = self._expr_taint_info(target_arg)
                is_literal = isinstance(target_arg, ast.Constant) and isinstance(target_arg.value, str)
                is_url_for = isinstance(target_arg, ast.Call) and (self._resolve_full_callable(target_arg.func) or "").endswith("url_for")
                if taint or (not is_literal and not is_url_for):
                    self._emit_finding(
                        SastFinding(
                            file_line=loc,
                            severity=SEVERITY_REDIRECT_WARNING,
                            category="Unvalidated Redirect",
                            details=f"Unvalidated redirection ({resolved_callable}()) — Open Redirect vulnerability",
                            suggestion_diff=build_safe_diff(line_text, "redirect:unvalidated"),
                        ),
                        node,
                    )
                    return

        # Check #16: Insecure CORS Wildcard
        if resolved_callable.endswith("CORS") or resolved_callable.endswith("add_middleware"):
            for kw in node.keywords:
                if kw.arg in ("origins", "allow_origins"):
                    has_wildcard = False
                    if isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                        has_wildcard = True
                    elif isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        has_wildcard = any(isinstance(e, ast.Constant) and e.value == "*" for e in kw.value.elts)
                    if has_wildcard:
                        self._emit_finding(
                            SastFinding(
                                file_line=loc,
                                severity=SEVERITY_CORS_WARNING,
                                category="Insecure CORS",
                                details=f"Wildcard CORS policy ({kw.arg}='*') permits unrestricted cross-origin access",
                                suggestion_diff=build_safe_diff(line_text, "cors:wildcard"),
                            ),
                            node,
                        )
                        return

    def _extract_target_name(self, target: ast.AST) -> str | None:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        if isinstance(target, ast.Subscript):
            if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                return target.slice.value
        return None

    def _inspect_secret_candidate(self, var_name: str, value: str, node: ast.AST) -> None:
        """Context-Aware Secret Scanner: requires sensitive keyword, excludes UUID/color/path."""
        lower_var = var_name.lower()
        if any(bad in lower_var for bad in SECRET_FALSE_VAR_SUBSTRINGS):
            return
        if not any(kw in lower_var for kw in SECRET_VAR_KEYWORDS):
            return

        candidate = value.strip()
        if len(candidate) <= 16:
            return
        if any(ch.isspace() for ch in candidate):
            return
        if UUID_RE.match(candidate) or HEX_COLOR_RE.match(candidate):
            return
        lower_val = candidate.lower()
        if "\\" in candidate or lower_val.startswith(("http://", "https://", "file://", "/", "./", "../")):
            return
        if any(marker in lower_val for marker in SECRET_PLACEHOLDER_MARKERS):
            return

        entropy = calculate_shannon_entropy(candidate)
        if entropy <= 3.5:
            return

        masked = f"{candidate[:4]}****{candidate[-4:]}"
        self._emit_finding(
            SastFinding(
                file_line=self._loc(node),
                severity=SEVERITY_SECRET_WARNING,
                category="Hardcoded Secret",
                details=(
                    f"High-entropy hardcoded secret detected in '{var_name}' "
                    f"(Entropy: {entropy:.2f}, Length: {len(candidate)}, Preview: {masked})"
                ),
                suggestion_diff=build_safe_diff(
                    self._line_text(node),
                    "secret:hardcoded",
                    extra={"var_name": var_name, "masked": masked},
                ),
            ),
            node,
        )

    def _check_weak_randomness(self, var_name: str, value_expr: ast.AST, node: ast.AST) -> None:
        """Module J / Check #8: Detect random.* calls used for secrets, tokens, keys, or passwords."""
        lower_var = var_name.lower()
        if any(bad in lower_var for bad in SECRET_FALSE_VAR_SUBSTRINGS):
            return
        if not any(kw in lower_var for kw in WEAK_RANDOM_VAR_KEYWORDS):
            return

        for sub in ast.walk(value_expr):
            if isinstance(sub, ast.Call):
                called = self._resolve_full_callable(sub.func) or ""
                if called in WEAK_RANDOM_METHODS:
                    self._emit_finding(
                        SastFinding(
                            file_line=self._loc(node),
                            severity=SEVERITY_WEAK_RANDOM_WARNING,
                            category="Weak Randomness",
                            details=f"Cryptographically weak pseudo-random generator '{called}()' used for security variable '{var_name}'",
                            suggestion_diff=build_safe_diff(
                                self._line_text(node),
                                "random:weak",
                                extra={"var_name": var_name},
                            ),
                        ),
                        node,
                    )
                    return

    def _propagate_assignment_taint(self, target_names: list[str], value_expr: ast.AST, lineno: int) -> None:
        """Module M: Propagate taint across multi-step variable assignments."""
        taint = self._expr_taint_info(value_expr)
        if taint is None:
            for name in target_names:
                self.tainted_vars.pop(name, None)
            return

        src_line, src_label, is_llm, _ = taint
        is_multistep = src_line != lineno
        for name in target_names:
            self.tainted_vars[name] = (src_line or lineno, src_label, is_llm, is_multistep)

    def _handle_assignment(self, target_nodes: list[ast.AST], value_expr: ast.AST, node: ast.AST) -> None:
        target_names = [t.id for t in target_nodes if isinstance(t, ast.Name)]
        if not self.is_test_file:
            self._propagate_assignment_taint(target_names, value_expr, getattr(node, "lineno", 0))

        if self._is_suppressed(node) or self.is_test_file:
            return

        for target in target_nodes:
            var_name = self._extract_target_name(target)
            if not var_name:
                continue

            if self.check_secrets and isinstance(value_expr, ast.Constant) and isinstance(value_expr.value, str):
                self._inspect_secret_candidate(var_name, value_expr.value, node)

            if self.check_unsafe:
                self._check_weak_randomness(var_name, value_expr, node)

                # Check #12: DEBUG = True
                if var_name == "DEBUG" and isinstance(value_expr, ast.Constant) and value_expr.value is True:
                    self._emit_finding(
                        SastFinding(
                            file_line=self._loc(node),
                            severity=SEVERITY_DEBUG_WARNING,
                            category="Web Debug Enabled",
                            details="DEBUG = True active — Information disclosure and RCE risk in production",
                            suggestion_diff=build_safe_diff(self._line_text(node), "web:debug"),
                        ),
                        node,
                    )

                # Check #16: CORS_ALLOW_ALL_ORIGINS = True
                if var_name in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL") and isinstance(value_expr, ast.Constant) and value_expr.value is True:
                    self._emit_finding(
                        SastFinding(
                            file_line=self._loc(node),
                            severity=SEVERITY_CORS_WARNING,
                            category="Insecure CORS",
                            details=f"Wildcard CORS enabled via {var_name} = True — Unrestricted cross-origin access",
                            suggestion_diff=build_safe_diff(self._line_text(node), "cors:wildcard"),
                        ),
                        node,
                    )

            if self.check_prompts and var_name.lower() in PROMPT_VAR_NAMES:
                self._inspect_prompt_expression(
                    value_expr,
                    node,
                    f"variable '{var_name}'",
                    is_system_context=("system" in var_name.lower()),
                )

    def visit_Assign(self, node: ast.Assign) -> None:
        self._handle_assignment(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._handle_assignment([node.target], node.value, node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Check #18: Silent Failures (Bare except:)."""
        if self.check_unsafe and not self.is_test_file and not self._is_suppressed(node):
            if node.type is None:
                self._emit_finding(
                    SastFinding(
                        file_line=self._loc(node),
                        severity=SEVERITY_BARE_EXCEPT_WARNING,
                        category="Bare Except",
                        details="Bare 'except:' clause silently catches all exceptions including SystemExit and KeyboardInterrupt",
                        suggestion_diff=build_safe_diff(self._line_text(node), "except:bare"),
                    ),
                    node,
                )
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        """Check #14: Global Mutable State Risks inside async/threaded contexts."""
        if self.check_unsafe and not self.is_test_file and not self._is_suppressed(node):
            if self._in_async_fn or self.uses_concurrency:
                vars_str = ", ".join(node.names)
                self._emit_finding(
                    SastFinding(
                        file_line=self._loc(node),
                        severity=SEVERITY_GLOBAL_STATE_WARNING,
                        category="Global Mutable State",
                        details=f"Global mutable state modification ('global {vars_str}') in async context — Race Condition risk",
                        suggestion_diff=build_safe_diff(self._line_text(node), "global:mutable"),
                    ),
                    node,
                )
        self.generic_visit(node)

    def _is_agent_tool_decorated(self, fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in fn_node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            resolved = self._resolve_full_callable(target) or ""
            lower_dec = resolved.lower()
            if lower_dec in AGENT_TOOL_DECORATORS or lower_dec.endswith(".tool") or lower_dec.endswith("function_tool"):
                return True
        return False

    def _inspect_agent_tool_function(self, fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if self._is_suppressed(fn_node) or self.is_test_file:
            return

        dangerous_calls: list[str] = []
        has_validation = False
        for sub in ast.walk(fn_node):
            if isinstance(sub, ast.Raise):
                has_validation = True
            if isinstance(sub, ast.Call):
                called = self._resolve_full_callable(sub.func) or ""
                lower_fn = called.lower()
                if any(w in lower_fn for w in AGENT_VALIDATION_WORDS):
                    has_validation = True
                if any(called.startswith(d) or called == d for d in AGENT_DANGEROUS_SINKS):
                    if not self._is_suppressed(sub):
                        dangerous_calls.append(called)
                if called == "open" and len(sub.args) >= 2:
                    mode_arg = sub.args[1]
                    if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                        if any(m in mode_arg.value for m in ("w", "a", "+")):
                            dangerous_calls.append("open(..., write)")
            if isinstance(sub, ast.Name) and any(w in sub.id.lower() for w in AGENT_VALIDATION_WORDS):
                has_validation = True

        if dangerous_calls and not has_validation:
            unique_calls = ", ".join(sorted(set(dangerous_calls)))
            self._emit_finding(
                SastFinding(
                    file_line=self._loc(fn_node),
                    severity=SEVERITY_AGENT_TOOL_WARNING,
                    category="AI Agent Tool Risk",
                    details=f"AI Agent tool '{fn_node.name}()' performs dangerous operations without validation or approval: {unique_calls}",
                    suggestion_diff=build_safe_diff(self._line_text(fn_node), "agent:unrestricted"),
                ),
                fn_node,
            )

    def _visit_function_node(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._function_defs[node.name] = node
        saved_taint = dict(self.tainted_vars)
        prev_async = self._in_async_fn
        self._in_async_fn = isinstance(node, ast.AsyncFunctionDef)
        self.generic_visit(node)
        self._in_async_fn = prev_async
        self.tainted_vars = saved_taint

        if self.check_agents and self._is_agent_tool_decorated(node):
            self._inspect_agent_tool_function(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_node(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_node(node)

    def finalize(self) -> None:
        """Inspect functions referenced in tools=[...] after full module AST traversal."""
        if self.check_agents and self.agent_tool_candidates:
            for fn_name in sorted(self.agent_tool_candidates):
                fn_node = self._function_defs.get(fn_name)
                if fn_node is not None and not self._is_agent_tool_decorated(fn_node):
                    self._inspect_agent_tool_function(fn_node)


def is_whitelisted_domain(hostname: str) -> bool:
    """Return True if hostname is local, private IP, schema URL, or on the safe whitelist."""
    host = hostname.strip().lower().rstrip(".")
    if not host:
        return True
    if host in DOMAIN_WHITELIST:
        return True
    if host.endswith(WHITELISTED_TLDS):
        return True
    if host == "schemas" or host.startswith("schemas.") or ".schemas." in host:
        return True
    for safe_domain in DOMAIN_WHITELIST:
        if host.endswith("." + safe_domain):
            return True

    try:
        ip_obj = ipaddress.ip_address(host)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
            or ip_obj.is_multicast
        ):
            return True
    except ValueError:
        return False

    return False


def extract_checkable_domain(url: str) -> str | None:
    """Extract and validate an external hostname from a URL for DNS checks."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    hostname = parsed.hostname
    if not hostname:
        return None
    if any(ch in hostname for ch in ("{", "}", "$", "*", " ", "\t")):
        return None
    if "." not in hostname and hostname.lower() != "localhost":
        return None
    if is_whitelisted_domain(hostname):
        return None
    return hostname.lower().rstrip(".")


def check_domains_dns(
    candidates: list[DomainCandidate],
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> list[SastFinding]:
    """Verify domain DNS existence via lightweight socket.gethostbyname()."""
    if not candidates:
        return []

    unique_domains = sorted({c.domain for c in candidates})
    unresolved: dict[str, bool] = {}

    def _probe_dns(domain: str) -> tuple[str, bool]:
        try:
            socket.gethostbyname(domain)
            return domain, True
        except socket.gaierror:
            return domain, False

    worker_count = max(1, min(max_workers, len(unique_domains), 8))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(_probe_dns, d) for d in unique_domains]
        for fut in concurrent.futures.as_completed(futures):
            domain, resolved = fut.result()
            unresolved[domain] = resolved

    findings: list[SastFinding] = []
    seen_pairs: set[tuple[str, str]] = set()
    for cand in candidates:
        if not unresolved.get(cand.domain, True):
            dedup_key = (cand.file_line, cand.domain)
            if dedup_key in seen_pairs:
                continue
            seen_pairs.add(dedup_key)
            findings.append(
                SastFinding(
                    file_line=cand.file_line,
                    severity=SEVERITY_DOMAIN_DANGER,
                    category="Domain Squatting",
                    details=(
                        f"Domain could not be resolved via DNS (socket.gaierror): '{cand.domain}' "
                        f"({cand.url}) — Susceptible to domain squatting / takeover!"
                    ),
                )
            )
    return findings


def read_text_with_hash(file_path: Path) -> tuple[str, str]:
    """Read file via zero-copy mmap and return (decoded_text, sha256_hex)."""
    size = file_path.stat().st_size
    if size == 0:
        return "", hashlib.sha256(b"").hexdigest()
    with file_path.open("rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            raw = mm[:]
    digest = hashlib.sha256(raw).hexdigest()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace"), digest
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="replace"), digest
    try:
        return raw.decode("utf-8"), digest
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace"), digest


def read_text_gracefully(file_path: Path) -> str:
    """Read text using mmap for standard UTF-8 files with fallback encoding support."""
    text, _ = read_text_with_hash(file_path)
    return text


def scan_cicd_workflows(workflow_files: list[Path], base_dir: Path) -> list[SastFinding]:
    """Module P: Inspect .github/workflows/*.yml files for remote script piping and injection."""
    findings: list[SastFinding] = []
    curl_pipe_re = re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(ba)?sh\b", re.IGNORECASE)
    unsafe_ctx_re = re.compile(
        r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|discussion|review|pages)|head_ref)[^}]*\}\}",
        re.IGNORECASE,
    )

    for wf_path in workflow_files:
        try:
            content = read_text_gracefully(wf_path)
        except OSError:
            continue

        rel_label = _relative_display_path(wf_path, base_dir)
        lines = content.splitlines()
        has_pr_target = False
        pr_target_line = 0
        has_checkout = False
        checkout_line = 0
        in_run_block = False
        run_indent = 0

        for lineno, line in enumerate(lines, start=1):
            lower = line.lower()
            if "# halluciguard:ignore" in lower or "# noqa" in lower:
                continue

            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            if "pull_request_target" in stripped and not stripped.startswith("#"):
                has_pr_target = True
                pr_target_line = lineno

            if "actions/checkout" in stripped and not stripped.startswith("#"):
                has_checkout = True
                checkout_line = lineno

            if curl_pipe_re.search(line) and not stripped.startswith("#"):
                findings.append(
                    SastFinding(
                        file_line=f"{rel_label}:{lineno}",
                        severity=SEVERITY_CICD_DANGER,
                        category="CI/CD Security",
                        details="Unverified remote script execution via pipe (curl/wget | bash/sh) detected",
                    )
                )

            if stripped.startswith("run:") or stripped.startswith("- run:"):
                in_run_block = True
                run_indent = indent
                if unsafe_ctx_re.search(line):
                    findings.append(
                        SastFinding(
                            file_line=f"{rel_label}:{lineno}",
                            severity=SEVERITY_CICD_DANGER,
                            category="CI/CD Security",
                            details="Untrusted ${{ github.* }} context expression in GitHub Actions run: step — Script Injection risk",
                        )
                    )
                continue

            if in_run_block:
                if stripped and indent <= run_indent and not stripped.startswith("#"):
                    in_run_block = False
                elif unsafe_ctx_re.search(line):
                    findings.append(
                        SastFinding(
                            file_line=f"{rel_label}:{lineno}",
                            severity=SEVERITY_CICD_DANGER,
                            category="CI/CD Security",
                            details="Untrusted ${{ github.* }} context expression in GitHub Actions run: step — Script Injection risk",
                        )
                    )

        if has_pr_target and has_checkout:
            findings.append(
                SastFinding(
                    file_line=f"{rel_label}:{checkout_line or pr_target_line}",
                    severity=SEVERITY_CICD_DANGER,
                    category="CI/CD Security",
                    details="Combined pull_request_target trigger and actions/checkout — Untrusted pull request code execution risk",
                )
            )

    return findings


def parse_pep508_package_info(spec: str) -> tuple[str | None, bool]:
    """Extract (package_name, has_exact_pin) from a PEP 508 dependency string."""
    cleaned = spec.strip()
    if not cleaned or cleaned.startswith("#"):
        return None, False

    hash_idx = cleaned.find(" #")
    if hash_idx != -1:
        cleaned = cleaned[:hash_idx].strip()
    tab_hash_idx = cleaned.find("\t#")
    if tab_hash_idx != -1:
        cleaned = cleaned[:tab_hash_idx].strip()

    if not cleaned or cleaned.startswith("-"):
        return None, False

    lower_cleaned = cleaned.lower()
    if lower_cleaned.startswith(("http://", "https://", "git+", "hg+", "svn+", "bzr+", "file:")):
        return None, False

    has_exact_pin = "==" in cleaned
    delimiters = (";", "@", "[", "=", "<", ">", "!", "~", " ", "\t")
    cut_idx = len(cleaned)
    for delim in delimiters:
        idx = cleaned.find(delim)
        if idx != -1 and idx < cut_idx:
            cut_idx = idx

    candidate = cleaned[:cut_idx].strip()
    if not candidate:
        return None, False

    for ch in candidate:
        if not (ch.isalnum() or ch in ("-", "_", ".")):
            return None, False

    if not candidate[0].isalnum():
        return None, False

    return candidate, has_exact_pin


def parse_pep508_package_name(spec: str) -> str | None:
    """Extract the bare distribution name from a PEP 508 dependency string."""
    pkg, _ = parse_pep508_package_info(spec)
    return pkg


def _relative_display_path(file_path: Path, base_dir: Path) -> str:
    try:
        return str(file_path.resolve().relative_to(base_dir.resolve()))
    except ValueError:
        return file_path.name


def parse_requirements_file(
    req_path: Path,
    base_dir: Path,
    deps: dict[tuple[str, str], DiscoveredDependency],
    visited_files: set[Path] | None = None,
) -> None:
    """Parse requirements.txt (including -r nested files)."""
    if visited_files is None:
        visited_files = set()

    resolved = req_path.resolve()
    if resolved in visited_files or not req_path.is_file():
        return
    visited_files.add(resolved)

    content = read_text_gracefully(req_path)
    lines = content.splitlines()
    rel_label = _relative_display_path(req_path, base_dir)

    logical_lines: list[tuple[int, str]] = []
    buffer = ""
    start_line = 1
    for lineno, raw_line in enumerate(lines, start=1):
        stripped = raw_line.rstrip()
        if not buffer:
            start_line = lineno
        if stripped.endswith("\\"):
            buffer += stripped[:-1].strip() + " "
        else:
            buffer += stripped
            logical_lines.append((start_line, buffer))
            buffer = ""
    if buffer:
        logical_lines.append((start_line, buffer))

    for lineno, line in logical_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith(("-r ", "--requirement ")):
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                req_ref = parts[1].split("#", 1)[0].strip()
                if req_ref:
                    nested_target = (req_path.parent / req_ref).resolve()
                    parse_requirements_file(nested_target, base_dir, deps, visited_files)
            continue

        pkg_name, exact_pin = parse_pep508_package_info(stripped)
        if pkg_name:
            key = ("manifest", canonicalize_name(pkg_name))
            entry = deps.setdefault(
                key,
                DiscoveredDependency(raw_name=pkg_name, origin_kind="requirements"),
            )
            entry.add_source(f"{rel_label}:{lineno}", exact_pin=exact_pin)


def parse_pyproject_file(
    pyproject_path: Path,
    base_dir: Path,
    deps: dict[tuple[str, str], DiscoveredDependency],
) -> None:
    """Parse pyproject.toml using Python's built-in tomllib."""
    if not pyproject_path.is_file():
        return

    try:
        data = tomllib.loads(read_text_gracefully(pyproject_path))
    except (tomllib.TOMLDecodeError, OSError):
        return

    rel_label = _relative_display_path(pyproject_path, base_dir)

    def _register_spec(spec: Any, section_label: str) -> None:
        if not isinstance(spec, str):
            return
        pkg_name, exact_pin = parse_pep508_package_info(spec)
        if pkg_name:
            key = ("manifest", canonicalize_name(pkg_name))
            entry = deps.setdefault(
                key,
                DiscoveredDependency(raw_name=pkg_name, origin_kind="pyproject"),
            )
            entry.add_source(f"{rel_label} ({section_label})", exact_pin=exact_pin)

    def _register_poetry_table(table: Any, section_label: str) -> None:
        if not isinstance(table, dict):
            return
        for pkg_name, ver_spec in table.items():
            if not isinstance(pkg_name, str):
                continue
            if canonicalize_name(pkg_name) == "python":
                continue
            parsed = parse_pep508_package_name(pkg_name)
            if parsed:
                exact_pin = isinstance(ver_spec, str) and "==" in ver_spec
                key = ("manifest", canonicalize_name(parsed))
                entry = deps.setdefault(
                    key,
                    DiscoveredDependency(raw_name=parsed, origin_kind="pyproject"),
                )
                entry.add_source(f"{rel_label} ({section_label})", exact_pin=exact_pin)

    project = data.get("project")
    if isinstance(project, dict):
        for spec in project.get("dependencies", []) or []:
            _register_spec(spec, "project.dependencies")

        opt_deps = project.get("optional-dependencies")
        if isinstance(opt_deps, dict):
            for group_name, specs in opt_deps.items():
                if isinstance(specs, list):
                    for spec in specs:
                        _register_spec(spec, f"optional:{group_name}")

    dep_groups = data.get("dependency-groups")
    if isinstance(dep_groups, dict):
        for group_name, items in dep_groups.items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, str):
                        _register_spec(item, f"dependency-groups.{group_name}")

    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            _register_poetry_table(poetry.get("dependencies"), "tool.poetry.dependencies")
            _register_poetry_table(poetry.get("dev-dependencies"), "tool.poetry.dev-dependencies")
            groups = poetry.get("group")
            if isinstance(groups, dict):
                for group_name, group_obj in groups.items():
                    if isinstance(group_obj, dict):
                        _register_poetry_table(
                            group_obj.get("dependencies"),
                            f"tool.poetry.group.{group_name}",
                        )


def collect_target_files(
    target: Path,
) -> tuple[Path, list[Path], list[Path], list[Path], list[Path]]:
    """Collect .py, requirements*.txt, pyproject.toml, and .github/workflows/*.yml files."""
    if target.is_file():
        base_dir = target.parent.resolve()
        py_files = [target.resolve()] if target.suffix == ".py" else []
        req_files: list[Path] = []
        pyproject_files: list[Path] = []
        workflow_files: list[Path] = []
        lower_name = target.name.lower()
        if lower_name.endswith(".txt") and "requirements" in lower_name:
            req_files.append(target.resolve())
        elif lower_name == "pyproject.toml":
            pyproject_files.append(target.resolve())
        elif lower_name.endswith((".yml", ".yaml")) and ".github" in target.parts:
            workflow_files.append(target.resolve())
        return base_dir, py_files, req_files, pyproject_files, workflow_files

    base_dir = target.resolve()
    py_files = []
    req_files = []
    pyproject_files = []
    workflow_files = []

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = sorted(
            d for d in dirs if d not in SKIP_DIRS and (not d.startswith(".") or d == ".github")
        )
        root_path = Path(root)
        in_workflows = root_path.name == "workflows" and root_path.parent.name == ".github"
        for filename in sorted(files):
            file_path = root_path / filename
            lower_name = filename.lower()
            if in_workflows and lower_name.endswith((".yml", ".yaml")):
                workflow_files.append(file_path)
            elif lower_name.endswith(".py"):
                py_files.append(file_path)
            elif lower_name == "pyproject.toml":
                pyproject_files.append(file_path)
            elif lower_name == "requirements.txt" or (
                lower_name.startswith("requirements") and lower_name.endswith(".txt")
            ):
                req_files.append(file_path)

    return base_dir, py_files, req_files, pyproject_files, workflow_files


def scan_python_file(
    py_path: Path,
    base_dir: Path,
    deps: dict[tuple[str, str], DiscoveredDependency],
    syntax_errors: list[str],
    *,
    check_domains: bool = False,
    check_methods: bool = False,
    check_secrets: bool = False,
    check_unsafe: bool = False,
    check_prompts: bool = False,
    check_obfuscation: bool = False,
    check_agents: bool = False,
    domain_candidates: list[DomainCandidate] | None = None,
    sast_findings: list[SastFinding] | None = None,
    ast_cache: dict[str, Any] | None = None,
) -> bool:
    """Parse a Python file via AST + mmap SHA-256 cache. Returns True if ast_cache was updated."""
    rel_path = _relative_display_path(py_path, base_dir)
    try:
        source_code, file_hash = read_text_with_hash(py_path)
    except OSError as exc:
        syntax_errors.append(f"{rel_path} ({exc})")
        return False

    flags_sig = (
        f"{VERSION}:{int(check_domains)}{int(check_methods)}{int(check_secrets)}"
        f"{int(check_unsafe)}{int(check_prompts)}{int(check_obfuscation)}{int(check_agents)}"
    )
    cache_key = f"{py_path.resolve()}::{flags_sig}"
    importer_dir = py_path.parent.resolve()

    if ast_cache is not None:
        cached = ast_cache.get(cache_key)
        if isinstance(cached, dict) and cached.get("sha256") == file_hash:
            for mod_name, lineno, is_relative in cached.get("imports", []):
                key = ("ast_relative" if is_relative else "ast", mod_name)
                entry = deps.setdefault(
                    key,
                    DiscoveredDependency(raw_name=mod_name, origin_kind="ast", is_relative=is_relative),
                )
                entry.add_source(f"{rel_path}:{lineno}", importer_dir=importer_dir)
            if domain_candidates is not None:
                for dc in cached.get("domains", []):
                    domain_candidates.append(DomainCandidate(**dc))
            if sast_findings is not None:
                for sf in cached.get("sast", []):
                    sast_findings.append(SastFinding(**sf))
            return False

    try:
        tree = ast.parse(source_code, filename=str(py_path))
    except SyntaxError as exc:
        syntax_errors.append(f"{rel_path}:{exc.lineno or '?'} ({exc.msg})")
        return False

    source_lines = source_code.splitlines()
    suppressed_lines = get_suppressed_lines(source_code)
    test_flag = is_test_path(py_path, rel_path)

    visitor = SecurityASTVisitor(
        rel_path=rel_path,
        file_name=py_path.name,
        source_lines=source_lines,
        suppressed_lines=suppressed_lines,
        is_test_file=test_flag,
        check_domains=check_domains,
        check_methods=check_methods,
        check_secrets=check_secrets,
        check_unsafe=check_unsafe,
        check_prompts=check_prompts,
        check_obfuscation=check_obfuscation,
        check_agents=check_agents,
    )
    visitor.visit(tree)
    visitor.finalize()

    for mod_name, lineno, is_relative in visitor.imports:
        key = ("ast_relative" if is_relative else "ast", mod_name)
        entry = deps.setdefault(
            key,
            DiscoveredDependency(raw_name=mod_name, origin_kind="ast", is_relative=is_relative),
        )
        entry.add_source(f"{rel_path}:{lineno}", importer_dir=importer_dir)

    if domain_candidates is not None and visitor.domain_candidates:
        domain_candidates.extend(visitor.domain_candidates)
    if sast_findings is not None and visitor.sast_findings:
        sast_findings.extend(visitor.sast_findings)

    if ast_cache is not None:
        ast_cache[cache_key] = {
            "sha256": file_hash,
            "imports": visitor.imports,
            "domains": [
                {"domain": d.domain, "url": d.url, "file_line": d.file_line}
                for d in visitor.domain_candidates
            ],
            "sast": [
                {
                    "file_line": s.file_line,
                    "severity": s.severity,
                    "category": s.category,
                    "details": s.details,
                    "suggestion_diff": s.suggestion_diff,
                    "taint_chain": s.taint_chain,
                    "rel_file": s.rel_file,
                    "lineno": s.lineno,
                }
                for s in visitor.sast_findings
            ],
        }
        return True

    return False


def load_ignore_set(base_dir: Path, cli_ignore: str | None) -> set[str]:
    """Load ignored package names from .guardignore and --ignore CLI flag."""
    ignored: set[str] = set()

    def _add_ignore_token(token: str) -> None:
        cleaned = token.strip()
        if not cleaned or cleaned.startswith("#"):
            return
        norm = canonicalize_name(cleaned)
        if norm:
            ignored.add(norm)
        mapped = resolve_pypi_package_name(cleaned)
        mapped_norm = canonicalize_name(mapped)
        if mapped_norm:
            ignored.add(mapped_norm)

    ignore_candidates = [base_dir / ".guardignore"]
    cwd_ignore = Path.cwd().resolve() / ".guardignore"
    if cwd_ignore != ignore_candidates[0]:
        ignore_candidates.append(cwd_ignore)

    for ignore_file in ignore_candidates:
        if ignore_file.is_file():
            for line in read_text_gracefully(ignore_file).splitlines():
                hash_idx = line.find("#")
                if hash_idx != -1:
                    line = line[:hash_idx]
                for part in line.split(","):
                    _add_ignore_token(part)

    if cli_ignore:
        for part in cli_ignore.split(","):
            _add_ignore_token(part)

    return ignored


def get_stdlib_modules() -> frozenset[str]:
    """Return all known Python standard library and built-in module names."""
    stdlib = set(sys.builtin_module_names)
    stdlib.add("__future__")
    if hasattr(sys, "stdlib_module_names"):
        stdlib.update(sys.stdlib_module_names)
    return frozenset(stdlib)


def is_local_module(
    module_name: str,
    base_dir: Path,
    importer_dirs: set[Path],
) -> bool:
    """Detect whether an imported module exists locally in the target project."""
    search_roots: list[Path] = [base_dir]
    src_dir = base_dir / "src"
    if src_dir.is_dir():
        search_roots.append(src_dir)
    for d in importer_dirs:
        if d not in search_roots:
            search_roots.append(d)

    for root in search_roots:
        if (root / f"{module_name}.py").is_file():
            return True
        pkg_dir = root / module_name
        if pkg_dir.is_dir():
            if (pkg_dir / "__init__.py").is_file():
                return True
            try:
                if any(p.suffix == ".py" for p in pkg_dir.iterdir()):
                    return True
            except OSError:
                continue
    return False


def discover_local_module_names(base_dir: Path) -> set[str]:
    """Discover local .py module and package names in base_dir and base_dir/src."""
    local_names: set[str] = set()
    roots = [base_dir]
    if (base_dir / "src").is_dir():
        roots.append(base_dir / "src")
    for root in roots:
        try:
            for item in root.iterdir():
                if item.is_file() and item.suffix == ".py" and item.stem not in ("setup", "tasks"):
                    if not item.stem.startswith("test_"):
                        local_names.add(canonicalize_name(item.stem))
                elif item.is_dir() and not item.name.startswith(".") and item.name not in SKIP_DIRS:
                    if (item / "__init__.py").is_file():
                        local_names.add(canonicalize_name(item.name))
        except OSError:
            continue
    return local_names


def load_cache(cache_path: Path | None = None) -> dict[str, Any]:
    """Load the local JSON cache if available and valid."""
    target_cache = CACHE_FILE_PATH if cache_path is None else cache_path
    if not target_cache.is_file():
        return {}
    try:
        data = json.loads(target_cache.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


def save_cache(cache_data: dict[str, Any], cache_path: Path | None = None) -> None:
    """Persist the local JSON cache atomically where possible."""
    target_cache = CACHE_FILE_PATH if cache_path is None else cache_path
    try:
        target_cache.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target_cache.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")
        tmp_path.replace(target_cache)
    except OSError:
        return


def clear_cache(cache_path: Path | None = None) -> bool:
    """Delete the local cache file. Returns True if a file existed and was removed."""
    target_cache = CACHE_FILE_PATH if cache_path is None else cache_path
    if target_cache.is_file():
        target_cache.unlink()
        return True
    return False


def parse_pypi_iso_timestamp(ts_str: str) -> datetime | None:
    """Parse PyPI ISO-8601 timestamp string into a UTC-aware datetime."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    cleaned = ts_str.strip()
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_pypi_metrics(
    payload: dict[str, Any],
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Extract release age, release counts, and metadata completeness from PyPI JSON."""
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)

    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    releases = payload.get("releases") if isinstance(payload.get("releases"), dict) else {}

    non_empty_releases = 0
    upload_dates: list[datetime] = []

    for files in releases.values():
        if isinstance(files, list) and len(files) > 0:
            non_empty_releases += 1
            for file_entry in files:
                if not isinstance(file_entry, dict):
                    continue
                ts = (
                    file_entry.get("upload_time_iso_8601")
                    or file_entry.get("upload_time")
                )
                dt = parse_pypi_iso_timestamp(ts)
                if dt is not None:
                    upload_dates.append(dt)

    if not upload_dates and isinstance(payload.get("urls"), list):
        for file_entry in payload["urls"]:
            if not isinstance(file_entry, dict):
                continue
            ts = file_entry.get("upload_time_iso_8601") or file_entry.get("upload_time")
            dt = parse_pypi_iso_timestamp(ts)
            if dt is not None:
                upload_dates.append(dt)

    earliest_dt = min(upload_dates) if upload_dates else None
    age_days: float | None = None
    if earliest_dt is not None:
        age_days = max(0.0, (now_utc - earliest_dt).total_seconds() / 86400.0)

    def _non_empty_meta(val: Any) -> bool:
        if not isinstance(val, str):
            return False
        stripped = val.strip()
        return bool(stripped) and stripped.upper() != "UNKNOWN"

    has_author = any(
        _non_empty_meta(info.get(k))
        for k in ("author", "author_email", "maintainer", "maintainer_email")
    )
    has_description = any(
        _non_empty_meta(info.get(k))
        for k in ("summary", "description")
    )

    canonical_name = info.get("name")
    return {
        "exists": True,
        "name": canonical_name if isinstance(canonical_name, str) and canonical_name else None,
        "age_days": age_days,
        "earliest_release": earliest_dt.isoformat() if earliest_dt else None,
        "release_count": non_empty_releases,
        "has_author": has_author,
        "has_description": has_description,
    }


def classify_pypi_metadata(
    meta: dict[str, Any],
    *,
    typosquat_match: tuple[str, int] | None = None,
) -> tuple[str, str, list[str]]:
    """Classify a PyPI lookup record incorporating Slopsquatting and Typosquatting checks."""
    status_type = meta.get("status_type")
    exists = bool(meta.get("exists", False))
    age_days: float | None = meta.get("age_days")
    release_count: int = int(meta.get("release_count") or 0)
    has_author: bool = bool(meta.get("has_author"))
    has_description: bool = bool(meta.get("has_description"))

    if typosquat_match is not None:
        target_pkg, dist = typosquat_match
        is_young_or_sparse = (
            not exists
            or status_type == "error"
            or age_days is None
            or age_days < 90.0
            or release_count <= 3
            or not has_author
            or not has_description
        )
        if is_young_or_sparse:
            if not exists and status_type == "not_found":
                reason = "Not yet on PyPI (404)"
            elif status_type == "error":
                reason = "Offline / network error"
            else:
                age_txt = f"{int(age_days)} days old" if age_days is not None else "? days old"
                reason = f"New/sparse profile on PyPI ({age_txt}, {release_count} releases)"
            detail = (
                f"Close to popular package '{target_pkg}' ({dist} chars, Levenshtein={dist}) "
                f"— {reason}"
            )
            return STATUS_TYPOSQUAT, detail, [detail]

    if status_type == "error":
        err = meta.get("error", "Unknown network error")
        return STATUS_ERROR, f"PyPI query failed: {err}", [err]

    if not exists:
        return (
            STATUS_HALLUCINATED,
            "NOT on PyPI (404) — AI hallucination / Slopsquatting risk!",
            ["Package not found on PyPI (404 Not Found)."],
        )

    warnings: list[str] = []
    if age_days is None:
        warnings.append("Upload date undetermined")
    elif age_days <= 14.0:
        warnings.append(f"Created within last 14 days ({int(age_days)} days old)")
    elif age_days < 30.0:
        warnings.append(f"Package is younger than 30 days ({int(age_days)} days old)")

    if release_count <= 1:
        warnings.append(f"Single/low release count ({release_count} releases)")

    if not has_author:
        warnings.append("Author/maintainer field is empty")

    if not has_description:
        warnings.append("Description/summary field is empty")

    age_text = f"{int(age_days)} days" if age_days is not None else "? days"
    if warnings:
        detail = f"Suspicious signals: {', '.join(warnings)} ({release_count} releases, {age_text})"
        return STATUS_SUSPICIOUS, detail, warnings

    detail = f"Verified ({age_text} old, {release_count} releases, valid metadata)"
    return STATUS_SAFE, detail, []


def fetch_pypi_package(package_name: str) -> dict[str, Any]:
    """Query the PyPI JSON API for a single package using stdlib urllib.request (1.5s timeout)."""
    encoded = urllib.parse.quote(package_name, safe="-_.")
    url = PYPI_JSON_URL_TEMPLATE.format(package=encoded)
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": f"HalluciGuard/{VERSION} (Supply Chain Security Scanner)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            raw_body = resp.read().decode("utf-8", errors="replace")
            payload = json.loads(raw_body)
            metrics = extract_pypi_metrics(payload)
            metrics["status_type"] = "found"
            metrics["checked_at"] = time.time()
            return metrics
    except urllib.error.HTTPError as exc:
        code = exc.code
        try:
            exc.close()
        except Exception:
            code = exc.code
        if code == 404:
            return {
                "exists": False,
                "status_type": "not_found",
                "checked_at": time.time(),
            }
        return {
            "exists": False,
            "status_type": "error",
            "error": f"HTTP {code}",
        }
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {
            "exists": False,
            "status_type": "error",
            "error": str(exc),
        }


def resolve_pypi_batch(
    package_names: list[str],
    cache_path: Path | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    ttl_seconds: int = CACHE_TTL_SECONDS,
) -> dict[str, tuple[dict[str, Any], bool]]:
    """Resolve package metadata using the 24h local cache and ThreadPoolExecutor."""
    target_cache = CACHE_FILE_PATH if cache_path is None else cache_path
    now_ts = time.time()
    cache_data = load_cache(target_cache)
    results: dict[str, tuple[dict[str, Any], bool]] = {}
    to_fetch: dict[str, str] = {}

    for pkg_name in package_names:
        canon = canonicalize_name(pkg_name)
        cached_entry = cache_data.get(canon)
        if isinstance(cached_entry, dict):
            checked_at = cached_entry.get("checked_at")
            status_type = cached_entry.get("status_type")
            if (
                isinstance(checked_at, (int, float))
                and status_type in ("found", "not_found")
                and (now_ts - checked_at) < ttl_seconds
            ):
                results[canon] = (cached_entry, True)
                continue
        to_fetch.setdefault(canon, pkg_name)

    if to_fetch:
        worker_count = max(1, min(max_workers, len(to_fetch), 8))
        cache_dirty = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(fetch_pypi_package, query_name): canon
                for canon, query_name in to_fetch.items()
            }
            for future in concurrent.futures.as_completed(future_map):
                canon = future_map[future]
                try:
                    meta = future.result()
                except Exception as exc:
                    meta = {
                        "exists": False,
                        "status_type": "error",
                        "error": str(exc),
                    }
                results[canon] = (meta, False)
                if meta.get("status_type") in ("found", "not_found"):
                    cache_data[canon] = meta
                    cache_dirty = True

        if cache_dirty:
            save_cache(cache_data, target_cache)

    return results


def calculate_security_posture_score(
    findings: list[ScanFinding],
    sast_findings: list[SastFinding],
) -> int:
    """Compute a 0-100 Security Posture Score (100 = clean)."""
    score = 100
    for f in findings:
        if "DANGER" in f.status:
            score -= 18
        elif "WARNING" in f.status:
            score -= 8
    for sf in sast_findings:
        if "DANGER" in sf.severity:
            score -= 15
        elif "INFO/WARNING" in sf.severity:
            score -= 3
        elif "WARNING" in sf.severity:
            score -= 7
    return max(0, min(100, score))


def apply_safe_patches(base_dir: Path, sast_findings: list[SastFinding]) -> list[str]:
    """Opt-in --patch: apply only syntax-verified self-contained line fixes."""
    patches_by_file: dict[Path, dict[int, tuple[str, str]]] = {}
    for sf in sast_findings:
        if not sf.suggestion_diff or not sf.suggestion_diff.get("auto_patchable"):
            continue
        if not sf.rel_file or sf.lineno <= 0:
            continue
        target_file = (base_dir / sf.rel_file).resolve()
        if not target_file.is_file():
            continue
        patches_by_file.setdefault(target_file, {})[sf.lineno] = (
            sf.suggestion_diff["before"],
            sf.suggestion_diff["after"],
        )

    patched_files: list[str] = []
    for file_path, line_map in patches_by_file.items():
        try:
            raw_text = read_text_gracefully(file_path)
        except OSError:
            continue

        newline = "\r\n" if "\r\n" in raw_text else "\n"
        had_trailing_nl = raw_text.endswith(("\r\n", "\n"))
        lines = raw_text.splitlines()
        changed = False

        for lineno, (before_stripped, after_stripped) in line_map.items():
            idx = lineno - 1
            if 0 <= idx < len(lines):
                current_line = lines[idx]
                leading_ws = current_line[: len(current_line) - len(current_line.lstrip())]
                if current_line.strip() == before_stripped:
                    lines[idx] = f"{leading_ws}{after_stripped}"
                    changed = True

        if not changed:
            continue

        new_text = newline.join(lines) + (newline if had_trailing_nl else "")
        try:
            ast.parse(new_text, filename=str(file_path))
        except SyntaxError:
            continue

        try:
            file_path.write_text(new_text, encoding="utf-8")
            patched_files.append(_relative_display_path(file_path, base_dir))
        except OSError:
            continue

    return patched_files


def scan_target(
    target_path: Path,
    ignore_arg: str | None = None,
    cache_path: Path | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    *,
    check_domains: bool = False,
    check_methods: bool = False,
    check_secrets: bool = False,
    check_unsafe: bool = False,
    check_prompts: bool = False,
    check_typos: bool = True,
    check_confusion: bool = False,
    check_obfuscation: bool = False,
    check_agents: bool = False,
    check_cicd: bool = False,
    include_suggest: bool = False,
) -> dict[str, Any]:
    """Run a complete HalluciGuard v6.0 scan on a file or directory."""
    target_cache = CACHE_FILE_PATH if cache_path is None else cache_path
    start_ns = time.perf_counter_ns()
    base_dir, py_files, req_files, pyproject_files, workflow_files = collect_target_files(target_path)
    ignored_names = load_ignore_set(base_dir, ignore_arg)
    stdlib_modules = get_stdlib_modules()
    local_project_modules = discover_local_module_names(base_dir) if check_confusion else set()

    cache_root = load_cache(target_cache)
    ast_cache = cache_root.get("__ast_cache__")
    if not isinstance(ast_cache, dict):
        ast_cache = {}
        cache_root["__ast_cache__"] = ast_cache
    ast_cache_dirty = False

    raw_deps: dict[tuple[str, str], DiscoveredDependency] = {}
    syntax_errors: list[str] = []
    domain_candidates: list[DomainCandidate] = []
    sast_findings: list[SastFinding] = []

    for py_file in py_files:
        updated = scan_python_file(
            py_file,
            base_dir,
            raw_deps,
            syntax_errors,
            check_domains=check_domains,
            check_methods=check_methods,
            check_secrets=check_secrets,
            check_unsafe=check_unsafe,
            check_prompts=check_prompts,
            check_obfuscation=check_obfuscation,
            check_agents=check_agents,
            domain_candidates=domain_candidates,
            sast_findings=sast_findings,
            ast_cache=ast_cache,
        )
        if updated:
            ast_cache_dirty = True

    if ast_cache_dirty:
        save_cache(cache_root, target_cache)

    for req_file in req_files:
        parse_requirements_file(req_file, base_dir, raw_deps)
    for pyproject_file in pyproject_files:
        parse_pyproject_file(pyproject_file, base_dir, raw_deps)

    if check_domains and domain_candidates:
        sast_findings.extend(check_domains_dns(domain_candidates, max_workers=max_workers))

    if check_cicd and workflow_files:
        sast_findings.extend(scan_cicd_workflows(workflow_files, base_dir))

    local_and_stdlib_findings: list[ScanFinding] = []
    pypi_targets: dict[str, dict[str, Any]] = {}
    local_confusion_candidates: dict[str, DiscoveredDependency] = {}
    manifest_canon_map: dict[str, DiscoveredDependency] = {}
    ignored_count = 0

    for dep_key, dep in raw_deps.items():
        if dep_key[0] == "manifest":
            manifest_canon_map[dep_key[1]] = dep

    for dep in raw_deps.values():
        raw_name = dep.raw_name

        if dep.is_relative:
            local_and_stdlib_findings.append(
                ScanFinding(
                    display_name=raw_name,
                    pypi_name="-",
                    sources=dep.source_locations,
                    status=STATUS_LOCAL_STDLIB,
                    subtype="LOCAL",
                    detail="Relative local Python module",
                )
            )
            continue

        mapped_name = (
            resolve_pypi_package_name(raw_name)
            if dep.origin_kind == "ast"
            else raw_name
        )
        raw_canon = canonicalize_name(raw_name)
        mapped_canon = canonicalize_name(mapped_name)

        if raw_canon in ignored_names or mapped_canon in ignored_names:
            ignored_count += 1
            continue

        if dep.origin_kind == "ast":
            if raw_name in stdlib_modules:
                local_and_stdlib_findings.append(
                    ScanFinding(
                        display_name=raw_name,
                        pypi_name="-",
                        sources=dep.source_locations,
                        status=STATUS_LOCAL_STDLIB,
                        subtype="STDLIB",
                        detail="Python standard library (stdlib)",
                    )
                )
                continue

            if is_local_module(raw_name, base_dir, dep.importer_dirs):
                if check_confusion and raw_canon not in ignored_names:
                    local_confusion_candidates[raw_canon] = dep
                else:
                    local_and_stdlib_findings.append(
                        ScanFinding(
                            display_name=raw_name,
                            pypi_name="-",
                            sources=dep.source_locations,
                            status=STATUS_LOCAL_STDLIB,
                            subtype="LOCAL",
                            detail="Local project module / package",
                        )
                    )
                continue

        bucket = pypi_targets.setdefault(
            mapped_canon,
            {
                "query_name": mapped_name,
                "display_names": [],
                "sources": [],
                "origin_kind": dep.origin_kind,
                "has_exact_pin": dep.has_exact_pin,
            },
        )
        if dep.has_exact_pin:
            bucket["has_exact_pin"] = True
        if raw_name not in bucket["display_names"]:
            bucket["display_names"].append(raw_name)
        for src in dep.source_locations:
            if src not in bucket["sources"]:
                bucket["sources"].append(src)

    all_query_names = [info["query_name"] for info in pypi_targets.values()]
    for lc_dep in local_confusion_candidates.values():
        all_query_names.append(lc_dep.raw_name)

    pypi_results = resolve_pypi_batch(
        all_query_names,
        cache_path=target_cache,
        max_workers=max_workers,
    )

    for lc_canon, lc_dep in local_confusion_candidates.items():
        meta, cache_hit = pypi_results.get(lc_canon, ({"exists": False, "status_type": "not_found"}, False))
        manifest_match = manifest_canon_map.get(lc_canon)
        unpinned_manifest = manifest_match is not None and not manifest_match.has_exact_pin
        public_collision = bool(meta.get("exists", False))

        if public_collision or unpinned_manifest:
            reasons: list[str] = []
            if public_collision:
                reasons.append("public PyPI package exists with identical name")
            if unpinned_manifest:
                reasons.append("unpinned in requirements/pyproject (missing ==)")
            local_and_stdlib_findings.append(
                ScanFinding(
                    display_name=lc_dep.raw_name,
                    pypi_name=meta.get("name") or lc_dep.raw_name,
                    sources=lc_dep.source_locations,
                    status=STATUS_DEP_CONFUSION,
                    subtype="CONFUSION",
                    detail=f"Dependency Confusion risk: Local module ({', '.join(reasons)})",
                    cache_hit=cache_hit,
                    warnings=reasons,
                    suggestion_diff={
                        "before": f"{lc_dep.raw_name}  # Unpinned version or private index not configured",
                        "after": f"--index-url https://private.pypi.internal/simple\n{lc_dep.raw_name}==1.0.0",
                        "auto_patchable": False,
                    },
                )
            )
        else:
            local_and_stdlib_findings.append(
                ScanFinding(
                    display_name=lc_dep.raw_name,
                    pypi_name="-",
                    sources=lc_dep.source_locations,
                    status=STATUS_LOCAL_STDLIB,
                    subtype="LOCAL",
                    detail="Local project module / package",
                )
            )

    external_findings: list[ScanFinding] = []
    for canon_key, info in pypi_targets.items():
        meta, cache_hit = pypi_results[canon_key]

        if (
            check_confusion
            and canon_key in local_project_modules
            and not info["has_exact_pin"]
        ):
            external_findings.append(
                ScanFinding(
                    display_name=", ".join(info["display_names"]),
                    pypi_name=meta.get("name") or info["query_name"],
                    sources=info["sources"],
                    status=STATUS_DEP_CONFUSION,
                    subtype="CONFUSION",
                    detail="Dependency Confusion risk: Dependency with identical name to local module is unpinned",
                    cache_hit=cache_hit,
                    age_days=meta.get("age_days"),
                    release_count=meta.get("release_count"),
                    warnings=["Local module name collides with public PyPI package"],
                    suggestion_diff={
                        "before": info["display_names"][0],
                        "after": f"--index-url https://private.pypi.internal/simple  # or {info['display_names'][0]}==<version>",
                        "auto_patchable": False,
                    },
                )
            )
            continue

        typo_match = detect_typosquatting(info["query_name"]) if check_typos else None
        status, detail, warnings = classify_pypi_metadata(meta, typosquat_match=typo_match)
        official_name = meta.get("name") or info["query_name"]
        display_label = ", ".join(info["display_names"])

        pkg_diff: dict[str, Any] | None = None
        if status == STATUS_TYPOSQUAT and typo_match is not None:
            pkg_diff = {
                "before": f"import {info['display_names'][0]}",
                "after": f"import {typo_match[0]}  # Verified popular package",
                "auto_patchable": False,
            }
        elif status == STATUS_HALLUCINATED:
            pkg_diff = {
                "before": f"import {info['display_names'][0]}",
                "after": "# Package not found on PyPI; remove or verify correct package name",
                "auto_patchable": False,
            }

        external_findings.append(
            ScanFinding(
                display_name=display_label,
                pypi_name=official_name,
                sources=info["sources"],
                status=status,
                subtype="ERROR" if status == STATUS_ERROR else "PYPI",
                detail=detail,
                cache_hit=cache_hit,
                age_days=meta.get("age_days"),
                release_count=meta.get("release_count"),
                warnings=warnings,
                typosquat_target=typo_match[0] if typo_match else None,
                typosquat_distance=typo_match[1] if typo_match else None,
                suggestion_diff=pkg_diff,
            )
        )

    status_priority = {
        STATUS_TYPOSQUAT: 0,
        STATUS_HALLUCINATED: 1,
        STATUS_DEP_CONFUSION: 2,
        STATUS_SUSPICIOUS: 3,
        STATUS_ERROR: 4,
        STATUS_SAFE: 5,
        STATUS_LOCAL_STDLIB: 6,
    }
    all_findings = external_findings + local_and_stdlib_findings
    all_findings.sort(key=lambda item: (status_priority.get(item.status, 9), item.display_name.lower()))

    sast_findings.sort(
        key=lambda item: (
            0 if "DANGER" in item.severity else (1 if "INFO/WARNING" not in item.severity else 2),
            item.file_line,
        )
    )

    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
    counts = {
        "safe": sum(1 for f in all_findings if f.status == STATUS_SAFE),
        "hallucinated": sum(1 for f in all_findings if f.status == STATUS_HALLUCINATED),
        "typosquatting": sum(1 for f in all_findings if f.status == STATUS_TYPOSQUAT),
        "dependency_confusion": sum(1 for f in all_findings if f.status == STATUS_DEP_CONFUSION),
        "suspicious": sum(1 for f in all_findings if f.status == STATUS_SUSPICIOUS),
        "local_stdlib": sum(1 for f in all_findings if f.status == STATUS_LOCAL_STDLIB),
        "error": sum(1 for f in all_findings if f.status == STATUS_ERROR),
        "ignored": ignored_count,
        "cache_hits": sum(1 for f in all_findings if f.cache_hit),
    }

    sast_counts = {
        "total": len(sast_findings),
        "danger": sum(1 for s in sast_findings if "DANGER" in s.severity),
        "warning": sum(1 for s in sast_findings if "WARNING" in s.severity),
        "domain_squatting": sum(1 for s in sast_findings if s.category == "Domain Squatting"),
        "hallucinated_methods": sum(1 for s in sast_findings if s.category == "Hallucinated Method"),
        "hardcoded_secrets": sum(1 for s in sast_findings if s.category in ("Hardcoded Secret", "Hardcoded Private Key", "Hardcoded DB String", "Hardcoded Cloud Token")),
        "unsafe_patterns": sum(1 for s in sast_findings if s.category not in ("Domain Squatting", "Hallucinated Method", "Hardcoded Secret", "Hardcoded Private Key", "Hardcoded DB String", "Hardcoded Cloud Token", "Prompt Injection Risk", "Tainted Data Flow", "Obfuscated Code", "AI Agent Tool Risk", "CI/CD Security")),
        "prompt_injections": sum(1 for s in sast_findings if s.category == "Prompt Injection Risk"),
        "tainted_flows": sum(1 for s in sast_findings if s.category == "Tainted Data Flow"),
        "obfuscated": sum(1 for s in sast_findings if s.category == "Obfuscated Code"),
        "agent_tools": sum(1 for s in sast_findings if s.category == "AI Agent Tool Risk"),
        "cicd_issues": sum(1 for s in sast_findings if s.category == "CI/CD Security"),
    }

    posture_score = calculate_security_posture_score(all_findings, sast_findings)
    sast_enabled = (
        check_domains
        or check_methods
        or check_secrets
        or check_unsafe
        or check_prompts
        or check_obfuscation
        or check_agents
        or check_cicd
    )

    return {
        "tool": "HalluciGuard",
        "version": VERSION,
        "target": str(target_path.resolve()),
        "base_dir": str(base_dir),
        "security_posture_score": posture_score,
        "enabled_modules": {
            "supply_chain": True,
            "typosquatting": check_typos,
            "confusion": check_confusion,
            "domains": check_domains,
            "methods": check_methods,
            "secrets": check_secrets,
            "unsafe": check_unsafe,
            "prompts": check_prompts,
            "obfuscation": check_obfuscation,
            "agents": check_agents,
            "cicd": check_cicd,
            "suggest": include_suggest,
        },
        "files_scanned": {
            "python": len(py_files),
            "requirements": len(req_files),
            "pyproject": len(pyproject_files),
            "workflows": len(workflow_files),
        },
        "elapsed_ms": round(elapsed_ms, 2),
        "summary": counts,
        "sast_summary": sast_counts,
        "syntax_errors": syntax_errors,
        "findings": [f.to_dict(include_suggest=include_suggest) for f in all_findings],
        "sast_findings": [s.to_dict(include_suggest=include_suggest) for s in sast_findings],
        "_raw_findings": all_findings,
        "_raw_sast_findings": sast_findings,
        "_sast_enabled": sast_enabled,
    }


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _colorize(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{color}{text}{Ansi.RESET}"


def build_ai_fix_prompt(report: dict[str, Any]) -> str | None:
    """Build a copy-ready AI Remediation Prompt Template when findings are present."""
    findings: list[ScanFinding] = report["_raw_findings"]
    sast_findings: list[SastFinding] = report["_raw_sast_findings"]

    risky_pkgs = [
        f
        for f in findings
        if f.status in (STATUS_HALLUCINATED, STATUS_TYPOSQUAT, STATUS_SUSPICIOUS, STATUS_DEP_CONFUSION)
    ]
    if not risky_pkgs and not sast_findings:
        return None

    items: list[str] = [
        f"Please safely resolve the following HalluciGuard v{VERSION} security findings without breaking existing functionality:"
    ]
    idx = 1
    for pkg in risky_pkgs:
        locs = ", ".join(pkg.sources[:3])
        items.append(f"{idx}. [{pkg.status}] Package '{pkg.display_name}' ({locs}) -> {pkg.detail}")
        if pkg.suggestion_diff:
            items.append(f"   Recommended: {pkg.suggestion_diff['after']}")
        idx += 1

    for sf in sast_findings:
        items.append(f"{idx}. [{sf.severity}] {sf.file_line} ({sf.category}) -> {sf.details}")
        if sf.suggestion_diff:
            items.append(f"   Safe Fix: {sf.suggestion_diff['after']}")
        idx += 1

    items.append("For each remediation, provide only the changed lines in clean diff format along with a brief explanation.")
    return "\n".join(items)


def render_table_report(
    report: dict[str, Any],
    use_color: bool,
    *,
    include_suggest: bool = False,
    patched_files: list[str] | None = None,
) -> str:
    """Render minimalist Cyber-SOC ANSI-colored security audit report + AI Fix Prompt box."""
    lines: list[str] = []
    findings: list[ScanFinding] = report["_raw_findings"]
    sast_findings: list[SastFinding] = report["_raw_sast_findings"]
    sast_enabled: bool = report["_sast_enabled"]
    summary = report["summary"]
    sast_summary = report["sast_summary"]
    files_scanned = report["files_scanned"]
    enabled = report["enabled_modules"]
    posture = report["security_posture_score"]

    active_mods = ["Supply Chain"]
    if enabled["typosquatting"]:
        active_mods.append("Typosquatting")
    if enabled["confusion"]:
        active_mods.append("Dep.Confusion")
    if enabled["domains"]:
        active_mods.append("Domains")
    if enabled["methods"]:
        active_mods.append("Methods")
    if enabled["secrets"]:
        active_mods.append("Context-Secrets")
    if enabled["unsafe"]:
        active_mods.append("20-Point Hygiene/SAST/Taint")
    if enabled["prompts"]:
        active_mods.append("Prompt-Injection")
    if enabled["obfuscation"]:
        active_mods.append("Obfuscation")
    if enabled["agents"]:
        active_mods.append("AI-Agents")
    if enabled["cicd"]:
        active_mods.append("CI/CD")
    if include_suggest:
        active_mods.append("Safe-Diff")

    banner = (
        f"\n"
        f"  _   _       _ _            _  ____                     _ \n"
        f" | | | | __ _| | |_   _  ___(_)/ ___|_   _  __ _ _ __ __| |\n"
        f" | |_| |/ _` | | | | | |/ __| | |  _| | | |/ _` | '__/ _` |\n"
        f" |  _  | (_| | | | |_| | (__| | |_| | |_| | (_| | | | (_| |\n"
        f" |_| |_|\\__,_|_|_|\\__,_|\\___|_|\\____|\\__,_|\\__,_|_|  \\__,_|\n"
    )
    lines.append(_colorize(banner, Ansi.CYAN + Ansi.BOLD, use_color))
    lines.append(
        _colorize(
            f" HalluciGuard v{VERSION} | Zero-Noise Supply Chain, 20-Point SAST & MCP Guard",
            Ansi.BOLD + Ansi.WHITE,
            use_color,
        )
    )
    lines.append(_colorize("─" * 126, Ansi.GRAY, use_color))
    lines.append(f" Target Path     : {report['target']}")
    lines.append(f" Active Modules : {', '.join(active_mods)}")
    lines.append(
        f" Files Scanned  : {files_scanned['python']} Python (.py), "
        f"{files_scanned['requirements']} requirements, "
        f"{files_scanned['pyproject']} pyproject.toml, "
        f"{files_scanned['workflows']} workflow (.yml)"
    )
    score_color = Ansi.GREEN if posture >= 80 else (Ansi.YELLOW if posture >= 50 else Ansi.RED + Ansi.BOLD)
    lines.append(
        f" Latency / Cache: {report['elapsed_ms']} ms | "
        f"Cache Hits: {summary['cache_hits']} | "
        f"Ignored: {summary['ignored']} | "
        f"Security Score: {_colorize(f'{posture}/100', score_color, use_color)}"
    )

    if patched_files:
        lines.append(
            _colorize(
                f" [PATCH] Safe automated remediation applied to files: {', '.join(patched_files)}",
                Ansi.GREEN + Ansi.BOLD,
                use_color,
            )
        )

    if report["syntax_errors"]:
        lines.append(
            _colorize(
                f" Syntax Error Skipped Files: {', '.join(report['syntax_errors'])}",
                Ansi.YELLOW,
                use_color,
            )
        )

    lines.append("")
    lines.append(_colorize(" [1] Supply Chain & Package Analysis", Ansi.BOLD + Ansi.CYAN, use_color))
    lines.append(_colorize("─" * 126, Ansi.GRAY, use_color))

    if not findings:
        lines.append(_colorize(" No imports or dependencies discovered.", Ansi.GRAY, use_color))
    else:
        w_pkg = 18
        w_pypi = 18
        w_src = 22
        w_stat = 42
        w_det = 24

        header = (
            f" {'Package / Module':<{w_pkg}} │ "
            f"{'PyPI Match':<{w_pypi}} │ "
            f"{'Source':<{w_src}} │ "
            f"{'Status':<{w_stat}} │ "
            f"{'Security Telemetry'}"
        )
        sep = (
            f"─{'─' * w_pkg}─┼─"
            f"{'─' * w_pypi}─┼─"
            f"{'─' * w_src}─┼─"
            f"{'─' * w_stat}─┼─"
            f"{'─' * w_det}"
        )
        lines.append(_colorize(header, Ansi.BOLD, use_color))
        lines.append(_colorize(sep, Ansi.GRAY, use_color))

        status_colors = {
            STATUS_SAFE: Ansi.GREEN,
            STATUS_HALLUCINATED: Ansi.RED + Ansi.BOLD,
            STATUS_TYPOSQUAT: Ansi.RED + Ansi.BOLD,
            STATUS_DEP_CONFUSION: Ansi.YELLOW + Ansi.BOLD,
            STATUS_SUSPICIOUS: Ansi.YELLOW,
            STATUS_LOCAL_STDLIB: Ansi.BLUE,
            STATUS_ERROR: Ansi.GRAY,
        }

        for f in findings:
            pkg_col = _truncate(f.display_name, w_pkg)
            pypi_col = _truncate(f.pypi_name, w_pypi)
            src_joined = ", ".join(f.sources[:2])
            if len(f.sources) > 2:
                src_joined += f" (+{len(f.sources) - 2})"
            src_col = _truncate(src_joined, w_src)

            badge_raw = f"[{f.status}]"
            badge_padded = f"{_truncate(badge_raw, w_stat):<{w_stat}}"
            colored_badge = _colorize(badge_padded, status_colors.get(f.status, Ansi.WHITE), use_color)

            cache_tag = " [CACHE]" if f.cache_hit else ""
            detail_col = f"{f.detail}{cache_tag}"

            lines.append(
                f" {pkg_col:<{w_pkg}} │ "
                f"{pypi_col:<{w_pypi}} │ "
                f"{src_col:<{w_src}} │ "
                f"{colored_badge} │ "
                f"{detail_col}"
            )
            if include_suggest and f.suggestion_diff is not None:
                lines.append(_colorize("   [Recommended Safe Diff]", Ansi.CYAN, use_color))
                lines.append(_colorize(f"   - {f.suggestion_diff['before']}", Ansi.RED, use_color))
                lines.append(_colorize(f"   + {f.suggestion_diff['after']}", Ansi.GREEN, use_color))

    lines.append(_colorize("─" * 126, Ansi.GRAY, use_color))

    lines.append("")
    lines.append(_colorize(" [2] Static Code, 20-Point Hygiene & AI Hallucination Findings", Ansi.BOLD + Ansi.CYAN, use_color))
    lines.append(_colorize("─" * 126, Ansi.GRAY, use_color))

    if not sast_enabled:
        lines.append(
            _colorize(
                " Static analysis modules disabled (Zero-Noise mode). Use --deep for 20-point SAST & hygiene checks.",
                Ansi.GRAY,
                use_color,
            )
        )
    elif not sast_findings:
        lines.append(
            _colorize(
                " [OK] No suspicious code patterns detected in active SAST, hygiene, or hallucination scanners.",
                Ansi.GREEN,
                use_color,
            )
        )
    else:
        w_loc = 26
        w_sev = 48
        w_cat = 24
        w_sdet = 24

        s_header = (
            f" {'File:Line':<{w_loc}} │ "
            f"{'Severity':<{w_sev}} │ "
            f"{'Category':<{w_cat}} │ "
            f"{'Details'}"
        )
        s_sep = (
            f"─{'─' * w_loc}─┼─"
            f"{'─' * w_sev}─┼─"
            f"{'─' * w_cat}─┼─"
            f"{'─' * w_sdet}"
        )
        lines.append(_colorize(s_header, Ansi.BOLD, use_color))
        lines.append(_colorize(s_sep, Ansi.GRAY, use_color))

        for sf in sast_findings:
            loc_col = _truncate(sf.file_line, w_loc)
            sev_raw = f"[{sf.severity}]"
            sev_padded = f"{_truncate(sev_raw, w_sev):<{w_sev}}"
            if "DANGER" in sf.severity:
                sev_color = Ansi.RED + Ansi.BOLD
            elif "INFO/WARNING" in sf.severity:
                sev_color = Ansi.CYAN
            else:
                sev_color = Ansi.YELLOW
            sev_col = _colorize(sev_padded, sev_color, use_color)
            cat_col = _truncate(sf.category, w_cat)
            lines.append(
                f" {loc_col:<{w_loc}} │ "
                f"{sev_col} │ "
                f"{cat_col:<{w_cat}} │ "
                f"{sf.details}"
            )
            if include_suggest and sf.suggestion_diff is not None:
                lines.append(_colorize("   [Recommended Safe Diff]", Ansi.CYAN, use_color))
                lines.append(_colorize(f"   - {sf.suggestion_diff['before']}", Ansi.RED, use_color))
                lines.append(_colorize(f"   + {sf.suggestion_diff['after']}", Ansi.GREEN, use_color))

    lines.append(_colorize("─" * 126, Ansi.GRAY, use_color))

    summary_parts = [
        _colorize(f"SAFE: {summary['safe']}", Ansi.GREEN, use_color),
        _colorize(f"HALLUCINATED: {summary['hallucinated']}", Ansi.RED + Ansi.BOLD, use_color),
        _colorize(f"TYPOSQUAT: {summary['typosquatting']}", Ansi.RED + Ansi.BOLD, use_color),
        _colorize(f"CONFUSION: {summary['dependency_confusion']}", Ansi.YELLOW + Ansi.BOLD, use_color),
        _colorize(f"SUSPICIOUS: {summary['suspicious']}", Ansi.YELLOW, use_color),
        _colorize(f"LOCAL/STDLIB: {summary['local_stdlib']}", Ansi.BLUE, use_color),
    ]
    if sast_enabled:
        summary_parts.append(_colorize(f"SAST/HYGIENE: {sast_summary['total']}", Ansi.CYAN + Ansi.BOLD, use_color))
    if summary["error"] > 0:
        summary_parts.append(_colorize(f"ERROR: {summary['error']}", Ansi.GRAY, use_color))

    lines.append(" Summary: " + "  |  ".join(summary_parts))

    total_risks = (
        summary["hallucinated"]
        + summary["typosquatting"]
        + summary["dependency_confusion"]
        + summary["suspicious"]
        + sast_summary["total"]
    )
    if total_risks > 0:
        lines.append(
            _colorize(
                f" [!] WARNING: Total {total_risks} supply chain or SAST security findings detected!",
                Ansi.RED + Ansi.BOLD,
                use_color,
            )
        )
    elif summary["error"] > 0:
        lines.append(
            _colorize(
                " [!] WARNING: Some packages could not be verified on PyPI due to network/connectivity errors.",
                Ansi.YELLOW,
                use_color,
            )
        )
    else:
        lines.append(
            _colorize(
                " [OK] No critical supply chain, AI hallucination, or insecure code risks detected.",
                Ansi.GREEN,
                use_color,
            )
        )

    ai_prompt = build_ai_fix_prompt(report)
    if ai_prompt:
        lines.append("")
        lines.append(_colorize("┌─ AI Remediation Prompt Template (Copy for ChatGPT / Claude) " + "─" * 61 + "┐", Ansi.CYAN + Ansi.BOLD, use_color))
        for p_line in ai_prompt.splitlines():
            lines.append(_colorize(f"│ {p_line}", Ansi.WHITE, use_color))
        lines.append(_colorize("└" + "─" * 124 + "┘", Ansi.CYAN + Ansi.BOLD, use_color))

    lines.append("")
    return "\n".join(lines)


def generate_html_report(report: dict[str, Any], *, include_suggest: bool = False) -> str:
    """Generate a Cyber-SOC Terminal UI dark-mode interactive HTML security report (0 CDN)."""
    summary = report["summary"]
    sast_summary = report["sast_summary"]
    findings: list[ScanFinding] = report["_raw_findings"]
    sast_findings: list[SastFinding] = report["_raw_sast_findings"]
    posture = report["security_posture_score"]
    esc = html.escape

    def _badge_class(label: str) -> str:
        upper = label.upper()
        if "DANGER" in upper:
            return "badge-danger"
        if "WARNING" in upper:
            return "badge-warning"
        if "SAFE" in upper:
            return "badge-safe"
        if "LOCAL" in upper or "STDLIB" in upper:
            return "badge-local"
        return "badge-muted"

    def _diff_html(diff: dict[str, Any] | None) -> str:
        if not include_suggest or not diff:
            return ""
        encoded_after = esc(str(diff["after"]), quote=True)
        return (
            '<div class="diff-box">'
            '<div class="diff-head">'
            '<span class="diff-title">SAFE DIFF PATCH</span>'
            f'<button type="button" class="copy-btn" data-copy="{encoded_after}">Copy Safe Code</button>'
            "</div>"
            f'<div class="diff-del">- {esc(str(diff["before"]))}</div>'
            f'<div class="diff-add">+ {esc(str(diff["after"]))}</div>'
            "</div>"
        )

    pkg_rows: list[str] = []
    for f in findings:
        bcls = _badge_class(f.status)
        sev_tag = (
            "danger"
            if "DANGER" in f.status
            else ("warning" if "WARNING" in f.status else ("safe" if f.status == STATUS_SAFE else "local"))
        )
        src_text = ", ".join(f.sources)
        diff_block = _diff_html(f.suggestion_diff)
        pkg_rows.append(
            f'<tr class="report-row" data-filter="{sev_tag}">'
            f"<td><code>{esc(f.display_name)}</code></td>"
            f"<td><code>{esc(f.pypi_name)}</code></td>"
            f"<td><span class='src-pill'>{esc(src_text)}</span></td>"
            f'<td><span class="badge {bcls}">{esc(f.status)}</span></td>'
            f"<td>{esc(f.detail)}{diff_block}</td>"
            "</tr>"
        )

    sast_rows: list[str] = []
    for sf in sast_findings:
        bcls = _badge_class(sf.severity)
        sev_tag = "danger" if "DANGER" in sf.severity else "warning"
        taint_badge = (
            f'<div class="taint-chain">TAINT FLOW: <code>{esc(sf.taint_chain)}</code></div>'
            if sf.taint_chain
            else ""
        )
        diff_block = _diff_html(sf.suggestion_diff)
        sast_rows.append(
            f'<tr class="report-row" data-filter="{sev_tag} sast">'
            f"<td><code>{esc(sf.file_line)}</code></td>"
            f'<td><span class="badge {bcls}">{esc(sf.severity)}</span></td>'
            f"<td><span class='cat-pill'>{esc(sf.category)}</span></td>"
            f"<td>{esc(sf.details)}{taint_badge}{diff_block}</td>"
            "</tr>"
        )

    pkg_body = "\n".join(pkg_rows) if pkg_rows else '<tr><td colspan="5" class="empty">NO DEPENDENCIES DISCOVERED</td></tr>'
    sast_body = (
        "\n".join(sast_rows)
        if sast_rows
        else '<tr><td colspan="4" class="empty">ZERO SAST / HYGIENE FINDINGS DETECTED</td></tr>'
    )

    danger_total = (
        summary["hallucinated"]
        + summary["typosquatting"]
        + sum(1 for s in sast_findings if "DANGER" in s.severity)
    )
    warning_total = (
        summary["suspicious"]
        + summary["dependency_confusion"]
        + sum(1 for s in sast_findings if "WARNING" in s.severity)
    )
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    score_cls = "safe" if posture >= 80 else ("warning" if posture >= 50 else "danger")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HalluciGuard v{esc(VERSION)} // Cyber-SOC Security Console</title>
<style>
  :root {{
    --bg: #090a0f;
    --panel: #0f121a;
    --panel-2: #141926;
    --border: #1f293d;
    --text: #dce6f5;
    --muted: #7a8ba8;
    --neon-green: #00ff66;
    --neon-amber: #ffb700;
    --neon-red: #ff3366;
    --neon-cyan: #00e5ff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font-family: "JetBrains Mono", "Fira Code", Consolas, ui-monospace, monospace;
    font-size: 13px;
    line-height: 1.55;
  }}
  .container {{ max-width: 1380px; margin: 0 auto; }}
  header {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-left: 4px solid var(--neon-cyan);
    padding: 20px 24px;
    margin-bottom: 18px;
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
  }}
  header h1 {{
    margin: 0 0 6px;
    font-size: 1.35rem;
    color: var(--neon-cyan);
    letter-spacing: 0.04em;
  }}
  .meta {{ color: var(--muted); font-size: 0.82rem; display: flex; flex-wrap: wrap; gap: 16px; }}
  .posture-box {{
    border: 1px solid var(--border);
    background: var(--panel-2);
    padding: 12px 18px;
    text-align: center;
    min-width: 170px;
  }}
  .posture-label {{ font-size: 0.72rem; color: var(--muted); letter-spacing: 0.08em; }}
  .posture-val {{ font-size: 1.85rem; font-weight: 800; }}
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
    gap: 12px;
    margin-bottom: 18px;
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 14px 16px;
  }}
  .card .label {{ font-size: 0.74rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }}
  .card .val {{ font-size: 1.65rem; font-weight: 700; margin-top: 4px; }}
  .danger {{ color: var(--neon-red); }}
  .warning {{ color: var(--neon-amber); }}
  .safe {{ color: var(--neon-green); }}
  .cyan {{ color: var(--neon-cyan); }}
  .toolbar {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }}
  .filters {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .btn {{
    background: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 7px 13px;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.82rem;
    font-weight: 700;
  }}
  .btn.active, .btn:hover {{ border-color: var(--neon-cyan); color: var(--neon-cyan); }}
  .search {{
    background: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 7px 12px;
    min-width: 280px;
    font-family: inherit;
    font-size: 0.85rem;
  }}
  section {{
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 16px 18px;
    margin-bottom: 18px;
    overflow-x: auto;
  }}
  section h2 {{
    margin: 0 0 12px;
    font-size: 1rem;
    color: var(--neon-green);
    letter-spacing: 0.05em;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ background: var(--panel-2); color: var(--neon-cyan); font-size: 0.78rem; text-transform: uppercase; }}
  code {{ color: #ffffff; }}
  .src-pill, .cat-pill {{ color: var(--muted); font-size: 0.82rem; }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    font-size: 0.75rem;
    font-weight: 700;
    border: 1px solid transparent;
    white-space: nowrap;
  }}
  .badge-danger {{ color: var(--neon-red); border-color: var(--neon-red); background: rgba(255, 51, 102, 0.1); }}
  .badge-warning {{ color: var(--neon-amber); border-color: var(--neon-amber); background: rgba(255, 183, 0, 0.1); }}
  .badge-safe {{ color: var(--neon-green); border-color: var(--neon-green); background: rgba(0, 255, 102, 0.08); }}
  .badge-local {{ color: var(--neon-cyan); border-color: var(--neon-cyan); background: rgba(0, 229, 255, 0.08); }}
  .badge-muted {{ color: var(--muted); border-color: var(--border); }}
  .taint-chain {{
    margin-top: 6px;
    padding: 4px 8px;
    background: rgba(255, 51, 102, 0.08);
    border-left: 3px solid var(--neon-red);
    color: var(--neon-red);
    font-size: 0.78rem;
  }}
  .diff-box {{
    margin-top: 8px;
    background: #050609;
    border: 1px solid var(--border);
    padding: 8px 10px;
  }}
  .diff-head {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px; }}
  .diff-title {{ color: var(--neon-cyan); font-size: 0.74rem; font-weight: 700; }}
  .copy-btn {{
    background: var(--panel-2);
    color: var(--neon-green);
    border: 1px solid var(--neon-green);
    padding: 2px 8px;
    font-family: inherit;
    font-size: 0.72rem;
    cursor: pointer;
  }}
  .diff-del {{ color: var(--neon-red); white-space: pre-wrap; }}
  .diff-add {{ color: var(--neon-green); white-space: pre-wrap; }}
  .empty {{ color: var(--muted); text-align: center; padding: 16px; }}
  .hidden {{ display: none; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>HALLUCIGUARD v{esc(VERSION)} // CYBER-SOC SECURITY CONSOLE</h1>
      <div class="meta">
        <span>TARGET: <code>{esc(report['target'])}</code></span>
        <span>TIMESTAMP: {esc(generated_at)}</span>
        <span>LATENCY: {esc(str(report['elapsed_ms']))} ms</span>
        <span>CACHE HITS: {esc(str(summary['cache_hits']))}</span>
      </div>
    </div>
    <div class="posture-box">
      <div class="posture-label">SECURITY POSTURE</div>
      <div class="posture-val {score_cls}">{posture}/100</div>
    </div>
  </header>

  <div class="cards">
    <div class="card"><div class="label">CRITICAL (DANGER)</div><div class="val danger">{danger_total}</div></div>
    <div class="card"><div class="label">WARNING</div><div class="val warning">{warning_total}</div></div>
    <div class="card"><div class="label">SAFE PACKAGES</div><div class="val safe">{summary['safe']}</div></div>
    <div class="card"><div class="label">SAST &amp; HYGIENE</div><div class="val cyan">{sast_summary['total']}</div></div>
    <div class="card"><div class="label">LOCAL / STDLIB</div><div class="val">{summary['local_stdlib']}</div></div>
  </div>

  <div class="toolbar">
    <div class="filters">
      <button class="btn active" data-mode="all">ALL</button>
      <button class="btn" data-mode="danger">DANGER</button>
      <button class="btn" data-mode="warning">WARNING</button>
      <button class="btn" data-mode="safe">SAFE</button>
      <button class="btn" data-mode="sast">SAST / HYGIENE</button>
    </div>
    <input id="searchBox" class="search" type="text" placeholder="Filter package, file, taint chain...">
  </div>

  <section>
    <h2>[01] SUPPLY CHAIN &amp; DEPENDENCY MATRIX</h2>
    <table>
      <thead>
        <tr>
          <th>Package / Module</th>
          <th>PyPI Target</th>
          <th>Source</th>
          <th>Status</th>
          <th>Telemetry &amp; Patch</th>
        </tr>
      </thead>
      <tbody>{pkg_body}</tbody>
    </table>
  </section>

  <section>
    <h2>[02] STATIC ANALYSIS, 20-POINT HYGIENE &amp; AI AGENT AUDIT</h2>
    <table>
      <thead>
        <tr>
          <th>File:Line</th>
          <th>Severity</th>
          <th>Category</th>
          <th>Details &amp; Remediation</th>
        </tr>
      </thead>
      <tbody>{sast_body}</tbody>
    </table>
  </section>
</div>
<script>
  (function() {{
    const buttons = document.querySelectorAll('.btn[data-mode]');
    const searchBox = document.getElementById('searchBox');
    let currentMode = 'all';

    function applyFilter() {{
      const q = (searchBox.value || '').toLowerCase().trim();
      document.querySelectorAll('tr.report-row').forEach((row) => {{
        const tags = (row.getAttribute('data-filter') || '').split(' ');
        const modeOk = currentMode === 'all' || tags.includes(currentMode);
        const textOk = !q || row.textContent.toLowerCase().includes(q);
        row.classList.toggle('hidden', !(modeOk && textOk));
      }});
    }}

    buttons.forEach((btn) => {{
      btn.addEventListener('click', () => {{
        buttons.forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        currentMode = btn.getAttribute('data-mode') || 'all';
        applyFilter();
      }});
    }});

    searchBox.addEventListener('input', applyFilter);

    document.querySelectorAll('.copy-btn').forEach((btn) => {{
      btn.addEventListener('click', () => {{
        const txt = btn.getAttribute('data-copy') || '';
        if (navigator.clipboard && navigator.clipboard.writeText) {{
          navigator.clipboard.writeText(txt).then(() => {{
            btn.textContent = 'Copied!';
            setTimeout(() => {{ btn.textContent = 'Copy Safe Code'; }}, 1400);
          }});
        }} else {{
          btn.textContent = 'Ready';
        }}
      }});
    }});
  }})();
</script>
</body>
</html>
"""


def init_guardignore_config(target_dir: Path | None = None) -> tuple[Path, bool]:
    """Generate a starter .guardignore configuration file if missing."""
    root = Path.cwd().resolve() if target_dir is None else target_dir.resolve()
    if root.is_file():
        root = root.parent
    cfg_path = root / ".guardignore"
    if cfg_path.exists():
        return cfg_path, False
    cfg_path.write_text(GUARDIGNORE_TEMPLATE, encoding="utf-8")
    return cfg_path, True


def install_git_precommit_hook(repo_root: Path | None = None) -> tuple[Path, bool, str]:
    """Module Q: Install a lightweight HalluciGuard Git pre-commit hook."""
    root = Path.cwd().resolve() if repo_root is None else repo_root.resolve()
    git_dir = root / ".git"
    if not git_dir.is_dir():
        return root / ".git" / "hooks" / "pre-commit", False, "Error: .git directory not found."

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    script_abs = str(Path(__file__).resolve()).replace("\\", "/")

    hook_script = f"""#!/usr/bin/env python3
\"\"\"HalluciGuard v{VERSION} Git Pre-Commit Security Hook.\"\"\"
import json
import subprocess
import sys
from pathlib import Path

HALLUCIGUARD_SCRIPT = Path({script_abs!r})

def main() -> int:
    proc = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return 0

    staged = [line.strip() for line in proc.stdout.splitlines() if line.strip().endswith(".py")]
    for py_file in staged:
        res = subprocess.run(
            [sys.executable, str(HALLUCIGUARD_SCRIPT), "scan", py_file, "--deep", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0 or not res.stdout.strip():
            continue
        try:
            data = json.loads(res.stdout)
        except json.JSONDecodeError:
            continue
        summary = data.get("summary", {{}})
        sast_sum = data.get("sast_summary", {{}})
        danger_cnt = (
            summary.get("hallucinated", 0)
            + summary.get("typosquatting", 0)
            + sast_sum.get("danger", 0)
        )
        if danger_cnt > 0:
            print(f"[HalluciGuard] COMMIT BLOCKED: {{py_file}} has {{danger_cnt}} [DANGER] findings!", file=sys.stderr)
            return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""
    hook_path.write_text(hook_script, encoding="utf-8")
    try:
        current_mode = hook_path.stat().st_mode
        hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        return hook_path, True, "Pre-commit hook installed successfully."
    return hook_path, True, "Pre-commit hook installed successfully."


def strip_jsonc_comments(text: str) -> str:
    """Strip // line comments, /* */ block comments, and trailing commas from JSONC text."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    escaped = False

    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in ("\r", "\n"):
                i += 1
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue

        out.append(ch)
        i += 1

    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def install_windows_context_menu(script_path: Path | None = None) -> tuple[bool, str]:
    """Register Windows Explorer folder and background right-click context menus for HalluciGuard."""
    if sys.platform != "win32" and os.name != "nt":
        return False, "Error: --install-menu is only supported on Windows operating systems (win32). On Linux/macOS, use the CLI or editor task integration (--setup-editor)."

    import winreg

    target_script = Path(__file__).resolve() if script_path is None else script_path.resolve()
    python_exe = Path(sys.executable).resolve()
    # Flags precede "%V" so a trailing backslash on drive roots (e.g. "C:\") cannot swallow flags.
    command_value = f'cmd.exe /k ""{python_exe}" "{target_script}" scan --deep --suggest "%V""'

    def _write_menu(root_hive: Any, base_subkey: str) -> None:
        with winreg.CreateKey(root_hive, base_subkey) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "Scan with HalluciGuard")
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f"{python_exe},0")
        with winreg.CreateKey(root_hive, f"{base_subkey}\\command") as cmd_key:
            winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, command_value)

    hkcu_keys = (
        r"Software\Classes\Directory\shell\HalluciGuardScan",
        r"Software\Classes\Directory\Background\shell\HalluciGuardScan",
    )
    try:
        for subkey in hkcu_keys:
            _write_menu(winreg.HKEY_CURRENT_USER, subkey)
        return (
            True,
            r"User-level Windows Explorer context menu successfully registered: "
            r"HKEY_CURRENT_USER\Software\Classes\Directory\shell\HalluciGuardScan "
            r"(and Directory\Background)",
        )
    except OSError as exc:
        return False, f"Registry error: {exc}"


def setup_editor_tasks(
    workspace_dir: Path | None = None,
    script_path: Path | None = None,
) -> tuple[Path, bool]:
    """Create or update .vscode/tasks.json (JSONC-safe) for VS Code / Cursor workspace scanning."""
    root = Path.cwd().resolve() if workspace_dir is None else workspace_dir.resolve()
    if root.is_file():
        root = root.parent
    target_script = Path(__file__).resolve() if script_path is None else script_path.resolve()

    vscode_dir = root / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    tasks_path = vscode_dir / "tasks.json"

    new_task: dict[str, Any] = {
        "label": "HalluciGuard: Scan Workspace (Deep + Safe Diff)",
        "type": "shell",
        "command": sys.executable,
        "args": [
            str(target_script),
            "scan",
            "--deep",
            "--suggest",
            "${workspaceFolder}",
        ],
        "group": {
            "kind": "build",
            "isDefault": True,
        },
        "presentation": {
            "reveal": "always",
            "panel": "dedicated",
            "clear": True,
        },
        "problemMatcher": [],
    }

    payload: dict[str, Any] = {"version": "2.0.0", "tasks": [new_task]}
    created = not tasks_path.exists()

    if tasks_path.is_file():
        try:
            existing = json.loads(strip_jsonc_comments(read_text_gracefully(tasks_path)))
            if isinstance(existing, dict):
                existing_tasks = existing.get("tasks")
                if isinstance(existing_tasks, list):
                    filtered = [
                        t
                        for t in existing_tasks
                        if not (isinstance(t, dict) and str(t.get("label", "")).startswith("HalluciGuard"))
                    ]
                    has_default_build = any(
                        isinstance(t, dict)
                        and isinstance(t.get("group"), dict)
                        and t["group"].get("kind") == "build"
                        and t["group"].get("isDefault") is True
                        for t in filtered
                    )
                    if has_default_build:
                        new_task["group"] = "build"
                    filtered.append(new_task)
                    existing["version"] = existing.get("version") or "2.0.0"
                    existing["tasks"] = filtered
                    payload = existing
        except (OSError, json.JSONDecodeError):
            payload = {"version": "2.0.0", "tasks": [new_task]}

    tasks_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return tasks_path, created


def mcp_check_package(package_name: str, cache_path: Path | None = None) -> dict[str, Any]:
    """Evaluate a single package name for MCP tool calls."""
    cleaned = package_name.strip()
    if not cleaned:
        return {"package": cleaned, "status": "INVALID", "safe": False, "advice": "Please provide a valid package name."}

    stdlib = get_stdlib_modules()
    if cleaned in stdlib:
        return {
            "package": cleaned,
            "pypi_name": "-",
            "status": STATUS_LOCAL_STDLIB,
            "safe": True,
            "advice": "Python standard library module — safe to use.",
        }

    mapped = resolve_pypi_package_name(cleaned)
    typo = detect_typosquatting(mapped)
    results = resolve_pypi_batch([mapped], cache_path=cache_path)
    meta, cache_hit = results[canonicalize_name(mapped)]
    status, detail, _ = classify_pypi_metadata(meta, typosquat_match=typo)
    is_safe = status == STATUS_SAFE
    advice = detail
    if typo:
        advice = f"This package is risky ({detail}). Suggest '{typo[0]}' instead."
    elif status == STATUS_HALLUCINATED:
        advice = "This package was not found on PyPI (AI hallucination). Do not suggest to user."

    return {
        "package": cleaned,
        "pypi_name": meta.get("name") or mapped,
        "status": status,
        "safe": is_safe,
        "cache_hit": cache_hit,
        "advice": advice,
    }


def mcp_scan_snippet(code: str, cache_path: Path | None = None) -> dict[str, Any]:
    """Scan an in-memory Python code snippet for MCP tool calls (strictly read-only)."""
    try:
        tree = ast.parse(code, filename="<mcp_snippet>")
    except SyntaxError as exc:
        return {
            "valid_syntax": False,
            "error": f"Syntax error on line {exc.lineno}: {exc.msg}",
            "findings": [],
            "sast_findings": [],
        }

    source_lines = code.splitlines()
    suppressed = get_suppressed_lines(code)
    visitor = SecurityASTVisitor(
        rel_path="snippet.py",
        file_name="snippet.py",
        source_lines=source_lines,
        suppressed_lines=suppressed,
        is_test_file=False,
        check_domains=True,
        check_methods=True,
        check_secrets=True,
        check_unsafe=True,
        check_prompts=True,
        check_obfuscation=True,
        check_agents=True,
    )
    visitor.visit(tree)
    visitor.finalize()

    stdlib = get_stdlib_modules()
    pkg_results: list[dict[str, Any]] = []
    seen_pkgs: set[str] = set()
    for mod_name, _, is_rel in visitor.imports:
        if is_rel or mod_name in stdlib or mod_name in seen_pkgs:
            continue
        seen_pkgs.add(mod_name)
        pkg_results.append(mcp_check_package(mod_name, cache_path=cache_path))

    sast_out = [sf.to_dict(include_suggest=True) for sf in visitor.sast_findings]
    risky = any(not p["safe"] for p in pkg_results) or len(sast_out) > 0
    return {
        "valid_syntax": True,
        "risky": risky,
        "packages": pkg_results,
        "sast_findings": sast_out,
    }


def handle_mcp_request(request_obj: dict[str, Any], cache_path: Path | None = None) -> dict[str, Any] | None:
    """Module R: Handle a single JSON-RPC 2.0 MCP message cleanly."""
    req_id = request_obj.get("id")
    method = request_obj.get("method", "")
    params = request_obj.get("params") if isinstance(request_obj.get("params"), dict) else {}

    if method == "notifications/initialized" or req_id is None:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "halluciguard", "version": VERSION},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "check_package",
                        "description": "Check if a Python package exists on PyPI and assess Slopsquatting and Typosquatting risks.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"name": {"type": "string", "description": "Python package or import name"}},
                            "required": ["name"],
                        },
                    },
                    {
                        "name": "scan_snippet",
                        "description": "Scan a Python code snippet for package hallucinations, prompt injection, taint flow, and 20-point hygiene/SAST vulnerabilities.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"code": {"type": "string", "description": "Python source code snippet to scan"}},
                            "required": ["code"],
                        },
                    },
                ]
            },
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if tool_name == "check_package":
            result_data = mcp_check_package(str(args.get("name", "")), cache_path=cache_path)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result_data, ensure_ascii=False, indent=2)}],
                    "isError": False,
                },
            }
        if tool_name == "scan_snippet":
            result_data = mcp_scan_snippet(str(args.get("code", "")), cache_path=cache_path)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result_data, ensure_ascii=False, indent=2)}],
                    "isError": False,
                },
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unknown MCP tool: {tool_name}"},
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Unsupported method: {method}"},
    }


def run_mcp_server() -> int:
    """Run stdio JSON-RPC 2.0 MCP server loop for AI IDEs and agents."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue

        if isinstance(req, dict):
            resp = handle_mcp_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
    return 0


def build_argument_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser for HalluciGuard v6.2."""
    parser = argparse.ArgumentParser(
        prog="halluciguard",
        description=(
            "HalluciGuard v6.2 — Context-Aware, Zero-Noise AI Slopsquatting, "
            "20-Point Hygiene/SAST, Taint Tracking & MCP Security Scanner."
        ),
    )
    parser.add_argument("--clear-cache", action="store_true", help="Clear local PyPI and file cache.")
    parser.add_argument("--install-hook", action="store_true", help="Install .git/hooks/pre-commit security hook.")
    parser.add_argument("--install-menu", action="store_true", help="Register 'Scan with HalluciGuard' in Windows Explorer right-click context menu.")
    parser.add_argument("--setup-editor", action="store_true", help="Configure .vscode/tasks.json for one-key scanning in VS Code / Cursor.")
    parser.add_argument("--mcp-server", action="store_true", help="Start stdio JSON-RPC MCP server for AI IDEs and agents.")
    parser.add_argument("--init-config", action="store_true", help="Generate starter .guardignore configuration file.")
    parser.add_argument("--version", action="version", version=f"HalluciGuard {VERSION}")

    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("clear-cache", help="Clear local PyPI and file cache.")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan target file or project directory (Default: Fast Package, Slopsquatting & Typosquatting). ",
    )
    scan_parser.add_argument("target", help="Path to .py file or project directory to scan.")
    scan_parser.add_argument(
        "--deep",
        "--all",
        dest="deep",
        action="store_true",
        help="Enable all modules and 20-point security/hygiene checks.",
    )
    scan_parser.add_argument("--suggest", action="store_true", help="Display read-only Safe Diff remediation suggestions.")
    scan_parser.add_argument(
        "--patch",
        action="store_true",
        help="Optional: Apply safe automated remediations with AST syntax validation.",
    )
    scan_parser.add_argument("--report", default=None, metavar="FILE.html", help="Generate Cyber-SOC dark-mode interactive HTML report.")
    scan_parser.add_argument("--check-domains", action="store_true", help="Module A: DNS Domain Squatting verification.")
    scan_parser.add_argument("--check-methods", action="store_true", help="Module B: Hallucinated library method detection.")
    scan_parser.add_argument("--check-secrets", action="store_true", help="Module C1: Context-Aware Shannon Entropy secret detection.")
    scan_parser.add_argument("--check-unsafe", action="store_true", help="Module C2/H-K/M/W: 20-point SAST & hygiene scanner.")
    scan_parser.add_argument("--check-prompts", action="store_true", help="Module E: Nested AST LLM Prompt Injection analysis.")
    scan_parser.add_argument("--check-typos", action="store_true", help="Module F: Levenshtein Typosquatting detection.")
    scan_parser.add_argument("--check-confusion", action="store_true", help="Module L: Dependency Confusion detection.")
    scan_parser.add_argument("--check-obfuscation", action="store_true", help="Module N: Obfuscated imports and backdoor detection.")
    scan_parser.add_argument("--check-agents", action="store_true", help="Module O: Autonomous AI Agent Tool security audit.")
    scan_parser.add_argument("--check-cicd", action="store_true", help="Module P: .github/workflows/*.yml CI/CD security.")
    scan_parser.add_argument("--clear-cache", action="store_true", default=argparse.SUPPRESS, help="Clear cache prior to scan execution.")
    scan_parser.add_argument("--json", action="store_true", help="Output results as structured JSON.")
    scan_parser.add_argument("--strict", action="store_true", help="Exit with non-zero code (1) if any vulnerabilities or risks are found.")
    scan_parser.add_argument("--ignore", default=None, help="Comma-separated package names to ignore.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    use_color = configure_terminal()
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.mcp_server:
        return run_mcp_server()

    if args.init_config:
        cfg_path, created = init_guardignore_config()
        if created:
            print(_colorize(f"[OK] .guardignore template created: {cfg_path}", Ansi.GREEN, use_color))
        else:
            print(_colorize(f"[INFO] .guardignore already exists: {cfg_path}", Ansi.YELLOW, use_color))
        return 0

    if args.install_hook:
        hook_path, ok, msg = install_git_precommit_hook()
        if ok:
            print(_colorize(f"[OK] {msg} ({hook_path})", Ansi.GREEN, use_color))
            return 0
        print(_colorize(msg, Ansi.RED + Ansi.BOLD, use_color), file=sys.stderr)
        return 1

    if args.install_menu:
        ok, msg = install_windows_context_menu()
        if ok:
            print(_colorize(f"[OK] {msg}", Ansi.GREEN, use_color))
            return 0
        print(_colorize(msg, Ansi.RED + Ansi.BOLD, use_color), file=sys.stderr)
        return 1

    if args.setup_editor:
        tasks_path, created = setup_editor_tasks()
        action_txt = "created" if created else "updated"
        print(
            _colorize(
                f"[OK] VS Code / Cursor task configuration {action_txt}: {tasks_path} (Shortcut: Ctrl+Shift+B)",
                Ansi.GREEN,
                use_color,
            )
        )
        return 0

    if args.command == "clear-cache" or getattr(args, "clear_cache", False):
        removed = clear_cache()
        if args.command != "scan":
            if removed:
                print(f"[OK] Cache cleared: {CACHE_FILE_PATH}")
            else:
                print(f"[INFO] No cache file found to clear: {CACHE_FILE_PATH}")
            return 0

    if args.command != "scan":
        parser.print_help()
        return 0

    raw_target = args.target
    if os.name == "nt" and raw_target.endswith('"') and not Path(raw_target).exists():
        cleaned_target = raw_target.rstrip('"')
        if len(cleaned_target) == 2 and cleaned_target[1] == ":":
            cleaned_target += "\\"
        raw_target = cleaned_target
    target_path = Path(raw_target)
    if not target_path.exists():
        error_msg = f"Error: Target path not found: {target_path}"
        if args.json:
            print(json.dumps({"error": error_msg}, indent=2, ensure_ascii=False))
        else:
            print(_colorize(error_msg, Ansi.RED + Ansi.BOLD, use_color), file=sys.stderr)
        return 2

    deep = bool(args.deep)
    include_suggest = bool(args.suggest) or bool(args.patch)
    report = scan_target(
        target_path,
        ignore_arg=args.ignore,
        check_domains=deep or bool(args.check_domains),
        check_methods=deep or bool(args.check_methods),
        check_secrets=deep or bool(args.check_secrets),
        check_unsafe=deep or bool(args.check_unsafe),
        check_prompts=deep or bool(args.check_prompts),
        check_typos=True,
        check_confusion=deep or bool(args.check_confusion),
        check_obfuscation=deep or bool(args.check_obfuscation),
        check_agents=deep or bool(args.check_agents),
        check_cicd=deep or bool(args.check_cicd),
        include_suggest=include_suggest,
    )

    patched_files: list[str] = []
    if args.patch:
        patched_files = apply_safe_patches(Path(report["base_dir"]), report["_raw_sast_findings"])
        report["patched_files"] = patched_files

    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        html_content = generate_html_report(report, include_suggest=include_suggest)
        report_path.write_text(html_content, encoding="utf-8")
        if not args.json:
            print(_colorize(f"[OK] Cyber-SOC HTML report generated: {report_path.resolve()}", Ansi.GREEN, use_color))

    if args.json:
        json_payload = {k: v for k, v in report.items() if not k.startswith("_") and k != "base_dir"}
        print(json.dumps(json_payload, indent=2, ensure_ascii=False))
    else:
        print(
            render_table_report(
                report,
                use_color=use_color,
                include_suggest=include_suggest,
                patched_files=patched_files,
            )
        )

    if args.strict:
        risky_count = (
            report["summary"]["hallucinated"]
            + report["summary"]["typosquatting"]
            + report["summary"]["dependency_confusion"]
            + report["summary"]["suspicious"]
            + report["sast_summary"]["total"]
        )
        if risky_count > 0:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
