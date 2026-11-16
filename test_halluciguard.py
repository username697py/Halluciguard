#!/usr/bin/env python3
"""Comprehensive automated test suite for HalluciGuard v6.2.0."""

from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error

import halluciguard as hg


def make_pypi_payload(
    name: str,
    upload_dates: list[datetime],
    author: str = "Jane Doe",
    author_email: str = "jane@example.com",
    summary: str = "A valid package summary",
    description: str = "Detailed package description.",
) -> dict:
    """Build a synthetic PyPI JSON API response payload."""
    releases = {}
    for idx, dt in enumerate(upload_dates, start=1):
        ver = f"0.{idx}.0"
        releases[ver] = [
            {
                "filename": f"{name}-{ver}-py3-none-any.whl",
                "upload_time_iso_8601": dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        ]
    return {
        "info": {
            "name": name,
            "version": f"0.{len(upload_dates)}.0" if upload_dates else "0.0.0",
            "author": author,
            "author_email": author_email,
            "maintainer": "",
            "maintainer_email": "",
            "summary": summary,
            "description": description,
        },
        "releases": releases,
    }


class TestZeroDependencyAndCore(unittest.TestCase):
    def test_only_stdlib_no_pass_no_todo_and_1_5s_timeout(self) -> None:
        source = Path(hg.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])

        allowed_stdlib = set(sys.stdlib_module_names) | set(sys.builtin_module_names) | {"__future__"}
        for mod in imported_modules:
            self.assertIn(mod, allowed_stdlib, f"Non-stdlib import detected: {mod}")

        pass_nodes = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Pass)]
        self.assertEqual(pass_nodes, [])
        self.assertNotIn("# TODO", source)
        self.assertEqual(hg.HTTP_TIMEOUT_SECONDS, 1.5)

    def test_ast_ignores_comments_and_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "app.py"
            sample.write_text(
                '"""\nimport fake_docstring_pkg\n"""\n'
                "# import fake_comment_pkg\n"
                'sql = "import fake_string_pkg"\n'
                "import os\n"
                "import cv2\n"
                "from PIL import Image\n"
                "from .local_helper import run_task\n",
                encoding="utf-8",
            )
            deps: dict = {}
            errs: list = []
            hg.scan_python_file(sample, root, deps, errs)
            self.assertEqual(errs, [])
            names = {d.raw_name for d in deps.values()}
            self.assertEqual(names, {"os", "cv2", "PIL", ".local_helper"})

    def test_manifests_and_slopsquatting_heuristics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "base.txt").write_text("requests>=2.31.0\n", encoding="utf-8")
            (root / "requirements.txt").write_text("-r base.txt\nscikit-learn==1.5.0\n", encoding="utf-8")
            (root / "pyproject.toml").write_text(
                '[project]\nname="x"\nversion="0.1.0"\ndependencies=["fastapi>=0.110"]\n',
                encoding="utf-8",
            )
            deps: dict = {}
            hg.parse_requirements_file(root / "requirements.txt", root, deps)
            hg.parse_pyproject_file(root / "pyproject.toml", root, deps)
            self.assertEqual({d.raw_name for d in deps.values()}, {"requests", "scikit-learn", "fastapi"})

        now = datetime.now(timezone.utc)
        safe_m = hg.extract_pypi_metrics(make_pypi_payload("requests", [now - timedelta(days=365), now - timedelta(days=5)]), now_utc=now)
        self.assertEqual(hg.classify_pypi_metadata(safe_m)[0], hg.STATUS_SAFE)
        self.assertEqual(hg.classify_pypi_metadata({"exists": False, "status_type": "not_found"})[0], hg.STATUS_HALLUCINATED)
        new_m = hg.extract_pypi_metrics(make_pypi_payload("slop", [now - timedelta(days=4)]), now_utc=now)
        self.assertEqual(hg.classify_pypi_metadata(new_m)[0], hg.STATUS_SUSPICIOUS)


class TestModulesABC(unittest.TestCase):
    def test_domain_squatting_and_whitelist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            (proj / "net.py").write_text(
                'A = "http://localhost:8000"\n'
                'B = "https://github.com/org/repo"\n'
                'C = "https://pypi.org/simple"\n'
                'D = "https://unregistered-ai-domain-777.com/api"\n',
                encoding="utf-8",
            )
            queried: list[str] = []

            def fake_dns(host: str) -> str:
                queried.append(host)
                raise socket.gaierror(11001, "NXDOMAIN")

            with patch("socket.gethostbyname", side_effect=fake_dns):
                rep = hg.scan_target(proj, cache_path=root / "c.json", check_domains=True)

            self.assertEqual(queried, ["unregistered-ai-domain-777.com"])
            self.assertEqual(rep["sast_summary"]["domain_squatting"], 1)

    def test_methods_secrets_test_path_filter_and_suppression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            (proj / "tests").mkdir()
            (proj / "tests" / "helper.py").write_text(
                'api_key = "sk-test-9K8mN2pQ5rT8vW1xY4zA7bC0dE3fG6hJ"\n'
                "token = random.randint(1000, 9999)\n",
                encoding="utf-8",
            )
            (proj / "test_unit.py").write_text(
                'secret = "sk-test-9K8mN2pQ5rT8vW1xY4zA7bC0dE3fG6hJ"\n',
                encoding="utf-8",
            )
            (proj / "app.py").write_text(
                "import hashlib\n"
                "import pandas as pd\n"
                'api_key = "your_api_key_here"\n'
                'prod_token = "sk-live-9K8mN2pQ5rT8vW1xY4zA7bC0dE3fG6hJ"\n'
                'ignored_secret = "sk-ign-9K8mN2pQ5rT8vW1xY4zA7bC0dE3fG6hJ"  # halluciguard:ignore\n'
                "df = pd.read_pdf('doc.pdf')\n"
                "h = hashlib.md5(b'data')\n",
                encoding="utf-8",
            )

            with patch("urllib.request.urlopen", side_effect=OSError("offline")):
                rep = hg.scan_target(
                    proj,
                    cache_path=root / "c.json",
                    ignore_arg="pandas",
                    check_methods=True,
                    check_secrets=True,
                    check_unsafe=True,
                )

            sast = rep["_raw_sast_findings"]
            self.assertEqual(rep["sast_summary"]["hardcoded_secrets"], 1)
            self.assertEqual(rep["sast_summary"]["hallucinated_methods"], 1)
            self.assertTrue(all("test" not in f.file_line.lower() for f in sast))


class TestV31NestedPromptsAndModulesHIJK(unittest.TestCase):
    def test_v31_nested_ast_walk_prompt_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            (proj / "llm.py").write_text(
                "from flask import request\n"
                "user_input = request.args.get('q')\n"
                "client.chat.completions.create(\n"
                '    model="gpt-4o",\n'
                '    messages=[{"role": "user", "content": {"parts": [f"Summarize: {user_input}"]}}]\n'
                ")\n"
                "client.chat.completions.create(\n"
                '    model="gpt-4o",\n'
                '    messages=[{"role": "user", "content": user_input}]\n'
                ")\n"
                'safe_q = sanitize_input(user_input)\n'
                "client.chat.completions.create(\n"
                '    model="gpt-4o",\n'
                '    messages=[{"role": "user", "content": f"Clean: {safe_q}"}]\n'
                ")\n",
                encoding="utf-8",
            )
            rep = hg.scan_target(
                proj,
                cache_path=root / "c.json",
                ignore_arg="flask",
                check_prompts=True,
            )
            self.assertEqual(rep["sast_summary"]["prompt_injections"], 2)

    def test_modules_h_i_j_k(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            # Module I: setup.py build hook
            (proj / "setup.py").write_text(
                "import subprocess\n"
                "import urllib.request\n"
                "subprocess.run(['curl', 'https://example.com'])\n"
                "urllib.request.urlopen('https://example.com')\n",
                encoding="utf-8",
            )
            # Modules H, J, K
            (proj / "core.py").write_text(
                "import yaml\n"
                "import random\n"
                "from pathlib import Path\n"
                "from flask import request\n\n"
                "cfg_bad = yaml.load('a: 1', Loader=yaml.Loader)\n"
                "cfg_bad2 = yaml.unsafe_load('a: 1')\n"
                "cfg_ok = yaml.load('a: 1', Loader=yaml.SafeLoader)\n"
                "session_token = ''.join(random.choice('abcd') for _ in range(8))\n"
                "api_key = random.randint(100000, 999999)\n"
                "dice_roll = random.randint(1, 6)\n"
                "user_file = request.args.get('file')\n"
                "content = open(user_file).read()\n"
                "content2 = Path(request.args.get('f')).read_text()\n"
                "llm_resp = client.chat.completions.create(model='gpt-4o', messages=[])\n"
                "eval(llm_resp)\n"
                "exec(response.text)\n",
                encoding="utf-8",
            )

            with patch("urllib.request.urlopen", side_effect=OSError("offline")):
                rep = hg.scan_target(
                    proj,
                    cache_path=root / "c.json",
                    ignore_arg="yaml,flask",
                    check_unsafe=True,
                    include_suggest=True,
                )

            cats = [f.category for f in rep["_raw_sast_findings"]]
            sevs = [f.severity for f in rep["_raw_sast_findings"]]
            self.assertEqual(cats.count("Malicious Build Hook"), 2)
            self.assertEqual(cats.count("Insecure YAML Load"), 2)
            self.assertEqual(cats.count("Weak Randomness"), 2)  # dice_roll ignored!
            self.assertEqual(cats.count("Path Traversal"), 2)
            self.assertEqual(cats.count("LLM-to-Code RCE"), 2)
            self.assertIn(hg.SEVERITY_BUILD_HOOK_DANGER, sevs)
            self.assertIn(hg.SEVERITY_YAML_WARNING, sevs)
            self.assertIn(hg.SEVERITY_WEAK_RANDOM_WARNING, sevs)
            self.assertIn(hg.SEVERITY_PATH_TRAVERSAL_WARNING, sevs)
            self.assertIn(hg.SEVERITY_LLM_RCE_DANGER, sevs)


class TestV4ModulesLMNOPAndSOC(unittest.TestCase):
    def test_module_l_dependency_confusion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            (proj / "corp_billing.py").write_text("def bill(): pass\n", encoding="utf-8")
            (proj / "app.py").write_text("import corp_billing\n", encoding="utf-8")
            (proj / "requirements.txt").write_text("corp_billing>=1.0\n", encoding="utf-8")

            now = datetime.now(timezone.utc)
            pub_payload = make_pypi_payload("corp-billing", [now - timedelta(days=200), now - timedelta(days=5)])

            class FakeResp:
                def read(self) -> bytes:
                    return json.dumps(pub_payload).encode("utf-8")

                def __enter__(self):
                    return self

                def __exit__(self, *args) -> bool:
                    return False

            with patch("urllib.request.urlopen", return_value=FakeResp()):
                rep = hg.scan_target(proj, cache_path=root / "c.json", check_confusion=True, include_suggest=True)

            self.assertGreaterEqual(rep["summary"]["dependency_confusion"], 1)
            conf = [f for f in rep["_raw_findings"] if f.status == hg.STATUS_DEP_CONFUSION][0]
            self.assertIsNotNone(conf.suggestion_diff)

    def test_module_m_multistep_taint_tracking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            (proj / "flow.py").write_text(
                "import subprocess\n"
                "raw = input('cmd: ')\n"
                "cleaned = raw.strip()\n"
                "cmd = f'ping {cleaned}'\n"
                "subprocess.Popen(cmd)\n"
                "uid = input('id: ')\n"
                "q_id = uid.strip()\n"
                "cursor.execute(f'SELECT * FROM users WHERE id={q_id}')\n",
                encoding="utf-8",
            )
            rep = hg.scan_target(proj, cache_path=root / "c.json", check_unsafe=True)
            taint_findings = [f for f in rep["_raw_sast_findings"] if f.category == "Tainted Data Flow"]
            self.assertEqual(len(taint_findings), 2)
            self.assertEqual(taint_findings[0].taint_chain, "Line 2 -> Line 5")
            self.assertEqual(taint_findings[1].taint_chain, "Line 6 -> Line 8")

    def test_module_n_obfuscation_module_o_agents_module_p_cicd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            (proj / "agent_obf.py").write_text(
                "import base64\n"
                "import importlib\n"
                "import os\n\n"
                "mod = importlib.import_module('o' + 's')\n"
                "exec(base64.b64decode('cHJpbnQoMSk='))\n"
                "fn = getattr(__builtins__, 'eval')\n\n"
                "@mcp.tool\n"
                "def delete_any_file(path: str):\n"
                "    os.remove(path)\n\n"
                "@tool\n"
                "def safe_delete(path: str):\n"
                "    validate_path(path)\n"
                "    os.remove(path)\n",
                encoding="utf-8",
            )
            wf_dir = proj / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "deploy.yml").write_text(
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  build:\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - name: Risky\n"
                "        run: |\n"
                "          echo ${{ github.event.issue.title }}\n"
                "          curl -sSL https://example.com/install.sh | bash\n",
                encoding="utf-8",
            )

            rep = hg.scan_target(
                proj,
                cache_path=root / "c.json",
                check_obfuscation=True,
                check_agents=True,
                check_cicd=True,
                check_unsafe=True,
                include_suggest=True,
            )

            self.assertEqual(rep["sast_summary"]["obfuscated"], 3)
            self.assertEqual(rep["sast_summary"]["agent_tools"], 1)  # safe_delete skipped
            self.assertEqual(rep["sast_summary"]["cicd_issues"], 3)  # curl|bash, ctx injection, pull_request_target+checkout

            html_doc = hg.generate_html_report(rep, include_suggest=True)
            self.assertIn("#090a0f", html_doc)
            self.assertIn("#00ff66", html_doc)
            self.assertIn("#ff3366", html_doc)
            self.assertIn("JetBrains Mono", html_doc)
            self.assertIn("SECURITY POSTURE", html_doc)
            self.assertIn("Copy Safe Code", html_doc)
            self.assertNotIn("<link ", html_doc.lower())
            self.assertNotIn("<script src=", html_doc.lower())


class TestV41AndV51HookMCPConfigAndPromptBox(unittest.TestCase):
    def test_module_q_install_hook_and_module_v_init_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            hook_path, ok, _ = hg.install_git_precommit_hook(root)
            self.assertTrue(ok)
            self.assertTrue(hook_path.is_file())
            self.assertIn("HalluciGuard", hook_path.read_text(encoding="utf-8"))

            cfg_path, created = hg.init_guardignore_config(root)
            self.assertTrue(created)
            self.assertTrue(cfg_path.is_file())
            _, created_again = hg.init_guardignore_config(root)
            self.assertFalse(created_again)

    def test_module_r_mcp_server_protocol_and_ai_fix_prompt_box(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache_path = root / "cache.json"

            init_resp = hg.handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            self.assertEqual(init_resp["result"]["serverInfo"]["version"], hg.VERSION)

            list_resp = hg.handle_mcp_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            tool_names = [t["name"] for t in list_resp["result"]["tools"]]
            self.assertEqual(tool_names, ["check_package", "scan_snippet"])

            class Fake404(urllib.error.HTTPError):
                pass

            def fake_404(req, timeout=1.5):
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", hdrs=None, fp=io.BytesIO(b""))

            with patch("urllib.request.urlopen", side_effect=fake_404):
                pkg_resp = hg.handle_mcp_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "check_package", "arguments": {"name": "reqeusts"}},
                    },
                    cache_path=cache_path,
                )
            pkg_payload = json.loads(pkg_resp["result"]["content"][0]["text"])
            self.assertFalse(pkg_payload["safe"])
            self.assertIn("Typosquatting", pkg_payload["status"])

            snip_resp = hg.handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "scan_snippet",
                        "arguments": {"code": "import os\neval('1+1')\n"},
                    },
                },
                cache_path=cache_path,
            )
            snip_payload = json.loads(snip_resp["result"]["content"][0]["text"])
            self.assertTrue(snip_payload["risky"])
            self.assertEqual(len(snip_payload["sast_findings"]), 1)

            # Verify AI Fix Prompt Box renders in terminal output when risks exist
            proj = root / "proj"
            proj.mkdir()
            (proj / "bad.py").write_text("eval('1+1')\n", encoding="utf-8")
            rep = hg.scan_target(proj, cache_path=cache_path, check_unsafe=True, include_suggest=True)
            rendered = hg.render_table_report(rep, use_color=False, include_suggest=True)
            self.assertIn("AI Remediation Prompt Template", rendered)
            self.assertIn("bad.py:1", rendered)


class TestV6ModuleWAndPatch(unittest.TestCase):
    def test_context_aware_secret_scanner_zero_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            (proj / "ui_styles.py").write_text(
                'session_uuid = "550e8400-e29b-41d4-a716-446655440000"\n'
                'key_uuid = "550e8400-e29b-41d4-a716-446655440000"\n'
                'primary_color = "#00ff66aa"\n'
                'banner_text = "xK9mP2qW8rT5vY1zB4nL7jH3dF6gC0sA"\n'
                'auth_token = "tok_9K8mN2pQ5rT8vW1xY4zA7bC0dE3fG6hJ"\n',
                encoding="utf-8",
            )
            rep = hg.scan_target(proj, cache_path=root / "c.json", check_secrets=True)
            # Only auth_token should trigger; UUIDs, colors, and banner_text must be ignored
            self.assertEqual(rep["sast_summary"]["hardcoded_secrets"], 1)
            self.assertIn("auth_token", rep["_raw_sast_findings"][0].details)

    def test_all_20_module_w_checks_and_patch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "proj"
            proj.mkdir()
            target_file = proj / "audit_20.py"
            fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
            fake_ghp = "ghp_" + "A" * 36
            fake_pk_begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
            target_file.write_text(
                "import asyncio\n"
                "import hashlib\n"
                "import optparse\n"
                "import pickle\n"
                "import random\n"
                "import requests\n"
                "import subprocess\n"
                "import tempfile\n"
                "import yaml\n"
                "from flask import Flask, redirect, request\n\n"
                f'PRIVATE_PEM = "{fake_pk_begin}\\nMIIE..."\n'
                'DB_URL = "postgres://admin:S3cr3tPass@db.internal:5432/app"\n'
                f'AWS_KEY = "{fake_aws}"\n'
                f'GH_PAT = "{fake_ghp}"\n'
                'INTERNAL_SVC = "http://192.168.10.42:8080/api"\n'
                "DEBUG = True\n"
                "CORS_ALLOW_ALL_ORIGINS = True\n"
                "SHARED_STATE = 0\n\n"
                "def risky(user_arg):\n"
                "    data = pickle.loads(b'x')\n"
                "    subprocess.run('ls', shell=True)\n"
                "    tmp_path = tempfile.mktemp()\n"
                "    digest = hashlib.md5(b'pw').hexdigest()\n"
                "    cfg = yaml.load('a: 1', Loader=yaml.Loader)\n"
                "    api_token = random.randint(1000, 9999)\n"
                "    cursor.execute(f'SELECT * FROM users WHERE name={user_arg}')\n"
                "    fh = open('/var/data/' + user_arg)\n"
                "    requests.get('https://pypi.org', verify=False)\n"
                "    redirect(request.args.get('next'))\n"
                "    eval('1 + 1')\n"
                "    try:\n"
                "        x = 1\n"
                "    except:\n"
                "        x = 0\n\n"
                "async def worker():\n"
                "    global SHARED_STATE\n"
                "    SHARED_STATE += 1\n",
                encoding="utf-8",
            )
            before_text = target_file.read_text(encoding="utf-8")

            with patch("urllib.request.urlopen", side_effect=OSError("offline")):
                rep = hg.scan_target(
                    proj,
                    cache_path=root / "c.json",
                    ignore_arg="requests,yaml,flask",
                    check_secrets=True,
                    check_unsafe=True,
                    include_suggest=True,
                )

            # Default scan_target must be strictly read-only
            self.assertEqual(target_file.read_text(encoding="utf-8"), before_text)

            cats = {f.category for f in rep["_raw_sast_findings"]}
            expected_categories = {
                "Deprecated Stdlib",
                "Hardcoded Private Key",
                "Hardcoded DB String",
                "Hardcoded Cloud Token",
                "Hardcoded Internal IP",
                "Web Debug Enabled",
                "Insecure CORS",
                "Insecure Deserialization",
                "Shell Injection",
                "Insecure Temp File",
                "Weak Cryptography",
                "Insecure YAML Load",
                "Weak Randomness",
                "SQL Injection",
                "Path Traversal",
                "Disabled SSL",
                "Unvalidated Redirect",
                "Unsafe Code Pattern",
                "Bare Except",
                "Global Mutable State",
            }
            for exp in expected_categories:
                self.assertIn(exp, cats, f"Missing Module W check category: {exp}")

            # Verify --patch applies safe repairs while keeping valid Python AST syntax
            with (
                patch.object(hg, "CACHE_FILE_PATH", root / "c2.json"),
                patch("urllib.request.urlopen", side_effect=OSError("offline")),
                patch("sys.stdout", new_callable=io.StringIO),
            ):
                hg.main([
                    "scan",
                    str(proj),
                    "--check-unsafe",
                    "--patch",
                    "--ignore",
                    "requests,yaml,flask",
                ])

            after_text = target_file.read_text(encoding="utf-8")
            ast.parse(after_text)  # Patched code MUST remain valid Python!
            self.assertIn("tempfile.mkstemp()", after_text)
            self.assertIn("hashlib.sha256(b'pw').hexdigest()", after_text)
            self.assertIn("yaml.safe_load('a: 1')", after_text)
            self.assertIn("DEBUG = False", after_text)
            self.assertIn("verify=True", after_text)
            self.assertIn("shell=False", after_text)
            self.assertIn("except Exception:", after_text)


class TestV61IntegrationFeatures(unittest.TestCase):
    def test_setup_editor_creates_and_merges_vscode_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "my_project"
            ws.mkdir()

            # Pre-existing JSONC tasks.json with // comments, /* */ comments, URL strings & trailing comma
            vscode_dir = ws / ".vscode"
            vscode_dir.mkdir()
            (vscode_dir / "tasks.json").write_text(
                "{\n"
                "  // See https://go.microsoft.com/fwlink/?LinkId=733558\n"
                '  "version": "2.0.0",\n'
                '  "tasks": [\n'
                "    /* Custom task preserved */\n"
                '    {"label": "Custom Build", "type": "shell", "command": "echo https://example.com"},\n'
                "  ]\n"
                "}\n",
                encoding="utf-8",
            )

            with (
                patch("pathlib.Path.cwd", return_value=ws),
                patch("sys.stdout", new_callable=io.StringIO) as out_buf,
            ):
                rc = hg.main(["--setup-editor"])

            self.assertEqual(rc, 0)
            self.assertIn("Ctrl+Shift+B", out_buf.getvalue())
            tasks_data = json.loads((vscode_dir / "tasks.json").read_text(encoding="utf-8"))
            labels = [t["label"] for t in tasks_data["tasks"]]
            self.assertIn("Custom Build", labels)
            hg_task = [t for t in tasks_data["tasks"] if t["label"].startswith("HalluciGuard")][0]
            self.assertIn("${workspaceFolder}", hg_task["args"])
            self.assertEqual(hg_task["group"], {"kind": "build", "isDefault": True})

            # If another task already owns isDefault: true, HalluciGuard avoids conflict
            ws2 = Path(tmp) / "other_project"
            (ws2 / ".vscode").mkdir(parents=True)
            (ws2 / ".vscode" / "tasks.json").write_text(
                json.dumps({
                    "version": "2.0.0",
                    "tasks": [{"label": "Main Build", "type": "shell", "command": "make", "group": {"kind": "build", "isDefault": True}}],
                }),
                encoding="utf-8",
            )
            with patch("pathlib.Path.cwd", return_value=ws2), patch("sys.stdout", new_callable=io.StringIO):
                hg.main(["--setup-editor"])
            tasks_data2 = json.loads((ws2 / ".vscode" / "tasks.json").read_text(encoding="utf-8"))
            hg_task2 = [t for t in tasks_data2["tasks"] if t["label"].startswith("HalluciGuard")][0]
            self.assertEqual(hg_task2["group"], "build")

    def test_install_windows_context_menu_with_hkcu_fallback(self) -> None:
        recorded_writes: list[tuple[str, str, str, str]] = []

        class FakeKey:
            def __init__(self, hive_name: str, subkey: str) -> None:
                self.hive_name = hive_name
                self.subkey = subkey

            def __enter__(self):
                return self

            def __exit__(self, *args) -> bool:
                return False

        class FakeWinreg:
            HKEY_CLASSES_ROOT = "HKCR"
            HKEY_CURRENT_USER = "HKCU"
            REG_SZ = 1

            @staticmethod
            def CreateKey(hive, subkey: str):
                return FakeKey(str(hive), subkey)

            @staticmethod
            def SetValueEx(key: FakeKey, name: str, reserved: int, reg_type: int, value: str) -> None:
                recorded_writes.append((key.hive_name, key.subkey, name, value))

        with (
            patch.object(hg.os, "name", "nt"),
            patch.dict(sys.modules, {"winreg": FakeWinreg}),
            patch("sys.stdout", new_callable=io.StringIO) as out_buf,
        ):
            rc = hg.main(["--install-menu"])

        self.assertEqual(rc, 0)
        self.assertIn("HalluciGuardScan", out_buf.getvalue())
        self.assertTrue(
            any(
                w[0] == "HKCU"
                and w[1] == r"Software\Classes\Directory\shell\HalluciGuardScan"
                and w[2] == ""
                and w[3] == "Scan with HalluciGuard"
                for w in recorded_writes
            )
        )
        self.assertTrue(
            any(
                w[0] == "HKCU"
                and w[1] == r"Software\Classes\Directory\Background\shell\HalluciGuardScan"
                and w[2] == ""
                and w[3] == "Scan with HalluciGuard"
                for w in recorded_writes
            )
        )
        cmd_entries = [w for w in recorded_writes if w[1].endswith(r"HalluciGuardScan\command")]
        self.assertEqual(len(cmd_entries), 2)
        self.assertIn("cmd.exe /k", cmd_entries[0][3])
        self.assertIn('scan --deep --suggest "%V"', cmd_entries[0][3])


if __name__ == "__main__":
    unittest.main(verbosity=2)
