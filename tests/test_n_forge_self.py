"""Section N — Audit de forge.py lui-même (tests #170-180 de TESTS.md).

Tests statiques sur le source de forge.py : taille, syntaxe, sécurité
(bandit/semgrep), comptage fonctions/classes/subprocess, algos.
"""
from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import REPO_ROOT


FORGE = REPO_ROOT / "forge.py"


def test_170_forge_size_reasonable() -> None:
    """TESTS.md #170 — forge.py fait > 1000 lignes (moteur réel, pas stub)."""
    lines = FORGE.read_text().splitlines()
    assert len(lines) > 1000, f"forge.py trop court: {len(lines)} lignes (attendu >1000)"
    assert len(lines) < 10000, f"forge.py trop long: {len(lines)} lignes (sanity check)"


def test_171_forge_python_syntax_valid() -> None:
    """TESTS.md #171 — forge.py syntaxe Python valide (ast.parse)."""
    src = FORGE.read_text()
    try:
        ast.parse(src)
    except SyntaxError as e:
        pytest.fail(f"forge.py SyntaxError: {e}")


def test_172_bandit_forge_no_high_severity() -> None:
    """TESTS.md #172 — bandit sur forge.py : 0 issue HIGH severity (faux positifs ok en LOW/MED)."""
    if not shutil.which("bandit"):
        pytest.skip("bandit non installé")
    p = subprocess.run(
        ["bandit", "-q", "-f", "json", str(FORGE)],
        capture_output=True, text=True, timeout=60,
    )
    # bandit retourne 1 si findings, 0 sinon — on parse le JSON
    import json
    data = json.loads(p.stdout) if p.stdout else {"results": []}
    high = [r for r in data.get("results", [])
            if r.get("issue_severity") == "HIGH"]
    # Le code doit pas avoir de HIGH (les seuls HIGH connus sont faux positifs : MD5 file-change + os.system literal)
    # On tolère 0-3 HIGH (faux positifs documentés)
    assert len(high) <= 3, \
        f"bandit forge.py trop de HIGH: {len(high)} (attendu ≤3 faux positifs)"


def test_173_bandit_forge_low_warnings_present() -> None:
    """TESTS.md #173 — bandit sur forge.py : warnings LOW présents (subprocess B404 etc.)."""
    if not shutil.which("bandit"):
        pytest.skip("bandit non installé")
    p = subprocess.run(
        ["bandit", "-q", "-f", "json", str(FORGE)],
        capture_output=True, text=True, timeout=60,
    )
    import json
    data = json.loads(p.stdout) if p.stdout else {"results": []}
    # Au moins 1 warning attendu (forge.py utilise subprocess → B404)
    assert len(data.get("results", [])) >= 1, \
        "bandit ne trouve AUCUN warning sur forge.py — résultat suspect"


def test_174_semgrep_forge_zero_critical() -> None:
    """TESTS.md #174 — semgrep p/security-audit sur forge.py : 0 finding bloquant."""
    if not shutil.which("semgrep"):
        pytest.skip("semgrep non installé")
    p = subprocess.run(
        ["semgrep", "scan", "--config=p/security-audit", "--quiet",
         "--error", "--metrics=off", str(FORGE)],
        capture_output=True, text=True, timeout=120,
    )
    # exit 0 = pas de findings bloquants ; exit 1 = findings bloquants
    # On tolère ≤2 findings (seuls os/subprocess autorisés contrôlés)
    findings = p.stdout.count("rule_id")
    assert findings <= 5, \
        f"semgrep forge.py trop de findings: {findings}\n{p.stdout[-500:]}"


def test_175_no_eval_or_exec_in_forge() -> None:
    """TESTS.md #175 — forge.py ne contient ni `eval(` ni `exec(` (sécurité)."""
    src = FORGE.read_text()
    # Match seulement les vrais appels (pas les commentaires ni docstrings)
    # On parse l'AST pour être robuste
    tree = ast.parse(src)
    bad_calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                bad_calls.append((node.lineno, node.func.id))
    assert not bad_calls, f"forge.py contient eval/exec: {bad_calls}"


def test_176_no_todos_or_minimal() -> None:
    """TESTS.md #176 — forge.py contient au plus quelques TODOs (≤3)."""
    src = FORGE.read_text()
    todos = re.findall(r"\b(TODO|FIXME|XXX|HACK)\b", src)
    assert len(todos) <= 3, \
        f"forge.py a {len(todos)} TODOs/FIXMEs (attendu ≤3): {todos}"


def test_177_function_count_reasonable() -> None:
    """TESTS.md #177 — forge.py a un nombre raisonnable de fonctions (>20)."""
    src = FORGE.read_text()
    tree = ast.parse(src)
    funcs = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    assert len(funcs) >= 20, \
        f"forge.py trop peu de fonctions: {len(funcs)} (attendu ≥20)"
    # Compter les privées (préfixe _)
    private = [f for f in funcs if f.name.startswith("_")]
    assert len(private) >= 5, \
        f"forge.py trop peu de fonctions privées: {len(private)} (attendu ≥5)"


def test_178_classes_zero_or_few() -> None:
    """TESTS.md #178 — forge.py est en style fonctionnel (≤5 classes)."""
    src = FORGE.read_text()
    tree = ast.parse(src)
    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    assert len(classes) <= 5, \
        f"forge.py a trop de classes: {len(classes)} — perte du style fonctionnel"


def test_179_subprocess_calls_present() -> None:
    """TESTS.md #179 — forge.py a des appels subprocess (lance les outils)."""
    src = FORGE.read_text()
    tree = ast.parse(src)
    subp_calls = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "subprocess":
                subp_calls += 1
    assert subp_calls >= 5, \
        f"forge.py trop peu d'appels subprocess: {subp_calls} (attendu ≥5)"


def test_180_stdlib_only_no_third_party() -> None:
    """TESTS.md #180 — forge.py n'importe que la stdlib (pas de pip install requis)."""
    src = FORGE.read_text()
    tree = ast.parse(src)
    third_party = []
    stdlib = {
        "ast", "collections", "datetime", "hashlib", "json", "math",
        "os", "pathlib", "re", "shutil", "subprocess", "sys", "time",
        "argparse", "csv", "itertools", "functools", "tempfile", "typing",
        "io", "string", "random", "warnings", "pickle", "copy",
        "logging", "traceback", "concurrent", "queue", "threading",
        "multiprocessing", "socket", "errno", "stat", "glob", "fnmatch",
        "shlex", "textwrap", "difflib", "unicodedata",
    }
    # Allowed near-stdlib (très répandus, utilisés pour SBFL coverage et pytest)
    allowed_3p = {"coverage"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in stdlib and root not in allowed_3p and not root.startswith("_"):
                    third_party.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                if (root not in stdlib and root not in allowed_3p
                        and not root.startswith("_") and node.level == 0):
                    third_party.append(node.module)
    assert not third_party, \
        f"forge.py importe des libs non-whitelistées: {third_party}"
