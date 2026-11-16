# 🛡️ HalluciGuard v6.2 — Security & Supply Chain Scanner

**Zero External Dependencies • Strictly Read-Only Default • One-Click Windows & IDE Integration • 20-Point SAST & Supply Chain Guard for AI-Generated Code**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Stdlib%20Only)-success)](#)
[![Strictly Read-Only Default](https://img.shields.io/badge/Default-Strictly%20Read--Only-informational)](#)
[![One-Click UX](https://img.shields.io/badge/UX-Explorer%20Menu%20%2B%20VS%20Code-blueviolet)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**HalluciGuard** is an open-source, single-file static analysis and supply chain security scanner designed to audit Python code produced by AI coding assistants (ChatGPT, Claude, GitHub Copilot, Cursor, etc.) and human developers alike.

It detects **hallucinated PyPI packages (Slopsquatting)**, **typosquatted lookalikes**, **unregistered DNS domains**, **context-aware hardcoded credentials**, **LLM prompt injection risks**, **multi-step taint flow vulnerabilities**, and **20 distinct real-world security and hygiene code flaws**.

---

## 1. Core Architectural Principles

* **100% Standard Library (`stdlib-only`):** Built exclusively with Python standard libraries (`ast`, `re`, `pathlib`, `json`, `mmap`, `urllib`, `concurrent.futures`, `socket`, `math`, `sys`, `os`, `time`, and platform-guarded `winreg`). No third-party packages or virtual environment overhead required.
* **Strictly Read-Only by Default:** Source code files are never modified during scanning. Remediation suggestions are presented as clean, non-intrusive **Safe Diff** blocks or AI prompt templates. Automated repairs only occur when explicitly instructed via `--patch`.
* **Zero Noise & Context-Aware Secret Detection:** Shannon entropy secret scanning evaluates variable identifiers (e.g., `key`, `secret`, `token`, `password`) and excludes UUIDs, CSS color hex codes, and filesystem paths to eliminate false alarms.
* **AST-Based Parsing (Zero Regex Guesswork):** Uses Python's native `ast.NodeVisitor` to traverse syntax trees, inspecting actual `ast.Import`, `ast.ImportFrom`, and callable sinks while ignoring comments and docstrings.
* **Ultra-Fast Local Caching:** Leverages memory-mapped I/O (`mmap`), file SHA-256 fingerprinting, and a local 24-hour PyPI metadata cache (`~/.halluciguard_cache.json`) to deliver sub-second scans.

---

## 2. CLI Command Reference

### Default Supply Chain Scan
Audits project dependencies across `.py` files, `requirements.txt`, and `pyproject.toml` against the PyPI JSON API:

```bash
python halluciguard.py scan .
```

### Comprehensive Deep Scan + Safe Diff Suggestions (`--deep --suggest`)
Enables all 20 SAST and hygiene checks, domain validation, Shannon entropy secrets, prompt injection analysis, and displays read-only remediation diffs:

```bash
python halluciguard.py scan . --deep --suggest
```

### Common CLI Flags
```bash
# Scan a single Python file
python halluciguard.py scan app.py --deep --suggest

# Enforce strict exit code (returns 1 if risks are detected; ideal for CI/CD pipelines)
python halluciguard.py scan . --deep --strict

# Output machine-readable JSON for automated toolchains
python halluciguard.py scan . --deep --json

# Generate a standalone Cyber-SOC dark-mode interactive HTML report
python halluciguard.py scan . --deep --report security_report.html

# Apply safe automated AST-validated fixes directly to source files
python halluciguard.py scan . --deep --patch

# Ignore internal private packages or custom libraries
python halluciguard.py scan . --ignore internal_lib,private_sdk

# Initialize starter .guardignore configuration file
python halluciguard.py --init-config

# Clear the local PyPI and SHA-256 file cache
python halluciguard.py clear-cache
```

> [!TIP]
> To suppress an intentional alert on a specific line, append `# halluciguard:ignore` or `# noqa` to that line. Virtual environment folders (`venv`, `.venv`), version control (`.git`), build directories (`dist`, `build`, `__pycache__`), and test files (`test_*.py`) are ignored by default.

---

## 3. Module W: 20-Point Security & Code Hygiene Checklist

When invoked with `--deep`, HalluciGuard evaluates the codebase against the comprehensive **Module W** security and hygiene benchmark. Common flaws can be automatically repaired via `--patch`:

| # | Category | Detection Focus | Risk Level | Safe Remediation / Auto-Patch |
|---|---|---|---|---|
| **01** | **Deprecated Stdlib** | Legacy modules removed or deprecated in Python 3.12+ (`imp`, `cgi`, `optparse`, etc.) | Warning | Modern stdlib replacements (e.g., `importlib`, `argparse`) |
| **02** | **Hardcoded Private Key** | Hardcoded RSA/EC cryptographic private key blocks (`-----BEGIN ... PRIVATE KEY-----`) | Critical | Extract to environment variables or secret manager |
| **03** | **Hardcoded DB String** | Database connection URIs containing plaintext credentials | Critical | Store in environment variable (e.g., `DATABASE_URL`) |
| **04** | **Hardcoded Cloud Token** | Cloud credentials, API keys, or PATs (AWS, GitHub `ghp_`, Slack, etc.) | Critical | Move credentials to environment variables |
| **05** | **Hardcoded Internal IP** | RFC1918 private IPv4 addresses hardcoded directly in application logic | Warning | Dynamic configuration via `os.environ.get("SERVICE_HOST")` |
| **06** | **Web Debug Enabled** | Production web applications running with `debug=True` or `DEBUG = True` | Danger | Auto-patchable: `DEBUG = False` |
| **07** | **Insecure CORS** | Overly permissive wildcard CORS origins (`origins=["*"]`) | Warning | Specify explicit allowed origins list |
| **08** | **Insecure Deserialization** | Loading untrusted byte streams with `pickle.loads()`, `marshal`, or `shelve` | Critical | Replace with safe structured formats (`json.loads()`) |
| **09** | **Shell Injection** | Invoking system shells via `subprocess.run(..., shell=True)` | Critical | Auto-patchable: `shell=False` with explicit argument list |
| **10** | **Insecure Temp File** | TOCTOU race conditions via obsolete `tempfile.mktemp()` | High | Auto-patchable: `tempfile.mkstemp()` |
| **11** | **Weak Cryptography** | Legacy hashing algorithms (`hashlib.md5()`, `hashlib.sha1()`) | High | Auto-patchable: `hashlib.sha256()` |
| **12** | **Insecure YAML Load** | Deserializing YAML via `yaml.load()` without specifying a SafeLoader | Critical | Auto-patchable: `yaml.safe_load()` |
| **13** | **Weak Randomness** | Standard PRNG (`random.randint`, `random.choice`) used for tokens or secrets | Warning | Cryptographically secure `secrets.token_hex()` |
| **14** | **SQL Injection** | Dynamic SQL statements formatted via f-strings, `%`, or string concatenation | Critical | Use parameterized queries (e.g., `cursor.execute(sql, (param,))`) |
| **15** | **Path Traversal** | Dynamic user input concatenated directly into filesystem paths | Critical | Path containment validation via `Path.resolve()` & `is_relative_to()` |
| **16** | **Disabled SSL** | Disabling TLS validation via `verify=False` or `_create_unverified_context` | Critical | Auto-patchable: `verify=True` |
| **17** | **Unvalidated Redirect** | Forwarding users to external URLs directly from unvalidated query parameters | Warning | Validate target host against domain allowlist before `redirect()` |
| **18** | **Unsafe Code Pattern** | Execution of dynamic code strings via `eval()` or `exec()` sinks | Critical | Replace with safe dispatch dictionaries or `ast.literal_eval()` |
| **19** | **Bare Except** | Broad `except:` clauses catching `KeyboardInterrupt` and `SystemExit` | Warning | Auto-patchable: `except Exception:` |
| **20** | **Global Mutable State** | Modifying global state inside asynchronous functions or concurrent coroutines | Warning | Use thread/asyncio locks (`threading.Lock`) or encapsulated state |

---

## 4. One-Click Developer Integrations

### Windows Explorer Context Menu (`--install-menu`)
Registers a user-level Windows Explorer right-click shortcut (`HKEY_CURRENT_USER\Software\Classes\Directory\shell\HalluciGuardScan` and `Directory\Background`) without requiring Administrator privileges:

```powershell
python halluciguard.py --install-menu
```

**Usage:**
1. Right-click any project folder (or empty workspace area) in Windows Explorer.
2. Select **"Scan with HalluciGuard"**.
3. A terminal window launches, executes `--deep --suggest`, and displays interactive findings.

*(Note: On non-Windows operating systems, HalluciGuard provides a clear informative notice.)*

### VS Code & Cursor Task Configuration (`--setup-editor`)
Creates or updates `.vscode/tasks.json` in your project root, safely parsing JSONC comments and assigning the scan to the standard build shortcut (`Ctrl+Shift+B`):

```bash
python halluciguard.py --setup-editor
```

**Usage:**
1. Open your workspace in **VS Code** or **Cursor**.
2. Press **`Ctrl + Shift + B`** (or navigate to *Terminal → Run Build Task*).
3. HalluciGuard executes within the integrated editor terminal.

---

## 5. Model Context Protocol (MCP) Server

HalluciGuard implements the Model Context Protocol (MCP) over standard I/O (JSON-RPC 2.0), enabling AI editors (Cursor, Claude Desktop, Windsurf) to query package safety and scan code snippets dynamically:

```bash
python halluciguard.py --mcp-server
```

**Supported MCP Tools:**
* `check_package`: Checks package existence on PyPI, verifying age, Slopsquatting, and Levenshtein typosquatting.
* `scan_snippet`: Audits in-memory code snippets for insecure AST patterns, prompt injection risks, and supply chain threats.

---

## 6. Verification & Testing

HalluciGuard includes a comprehensive test suite covering all modules, regression safeguards, and platform integrations:

```bash
python test_halluciguard.py
```

All 16 unit tests run self-contained using Python's standard `unittest` library in under one second.

---

## 7. License

This project is licensed under the terms of the [MIT License](LICENSE).
