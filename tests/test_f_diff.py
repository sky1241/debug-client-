"""Section F — Mode delta `client-audit-diff` (tests #54-57 de TESTS.md)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from conftest import BIN_DIR, run_wrapper


def _create_log_dir_with_outs(parent: Path, outs: dict[str, str]) -> Path:
    """Crée un faux LOG_DIR avec les fichiers .out donnés (clé=tool, valeur=contenu)."""
    log = parent / "log"
    log.mkdir()
    for tool, content in outs.items():
        (log / f"{tool}.out").write_text(content)
    return log


def test_054_diff_detects_fixed_vs_new(tmp_path: Path) -> None:
    """TESTS.md #54-55 — diff catégorise FIXÉ / NOUVEAU correctement."""
    prev = _create_log_dir_with_outs(tmp_path / "prev", {
        "eslint": "bad.js: eval can be harmful no-eval\nbad.js: new Function no-new-func\n",
    })
    new = _create_log_dir_with_outs(tmp_path / "new", {
        "eslint": "bad.js: new Function no-new-func\n",  # eval fixé, new-func reste
    })
    out_file = tmp_path / "delta.md"
    p = run_wrapper("client-audit-diff", str(prev), str(new), f"--out={out_file}", timeout=30)
    assert p.returncode == 0, f"diff exit {p.returncode}: {p.stderr[-200:]}"
    text = out_file.read_text()
    assert "Fixés" in text or "fixés" in text
    # 1 fixé (eval) + 0 nouveau attendu
    assert "✅ Findings fixés" in text, f"section fixed manquante:\n{text[:600]}"


def test_055_diff_zero_change_zero_total(tmp_path: Path) -> None:
    """TESTS.md identique entre runs : 0 fixed / 0 new."""
    same = "bad.js: eval can be harmful no-eval\n"
    prev = _create_log_dir_with_outs(tmp_path / "prev", {"eslint": same})
    new = _create_log_dir_with_outs(tmp_path / "new", {"eslint": same})
    out_file = tmp_path / "delta.md"
    p = run_wrapper("client-audit-diff", str(prev), str(new), f"--out={out_file}", timeout=30)
    assert p.returncode == 0
    text = out_file.read_text()
    # Identique = inchangé
    assert "Findings inchangés" in text or "inchangés" in text


def test_056_diff_empty_dirs_returns_error(tmp_path: Path) -> None:
    """TESTS.md #56 — diff sur 2 dirs sans .out → exit 1."""
    a = tmp_path / "a"; a.mkdir()
    b = tmp_path / "b"; b.mkdir()
    p = run_wrapper("client-audit-diff", str(a), str(b), timeout=15)
    assert p.returncode != 0, "diff devrait retourner non-zero sur dirs vides"
    assert "aucun .out" in (p.stdout + p.stderr).lower(), \
        f"message d'erreur attendu absent:\n{(p.stdout+p.stderr)[-200:]}"


def test_057_diff_handles_empty_out_files(tmp_path: Path) -> None:
    """TESTS.md #57 — diff supporte les .out vides (awk anti-crash, pas de SIGPIPE)."""
    prev = _create_log_dir_with_outs(tmp_path / "prev", {"trufflehog3": ""})
    new = _create_log_dir_with_outs(tmp_path / "new", {"trufflehog3": ""})
    out_file = tmp_path / "delta.md"
    p = run_wrapper("client-audit-diff", str(prev), str(new), f"--out={out_file}", timeout=15)
    assert p.returncode == 0, f"diff a crash sur .out vides: {p.stderr[-200:]}"
    assert out_file.is_file(), "rapport non généré"
