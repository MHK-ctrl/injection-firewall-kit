"""Documentation hygiene: internal links resolve, required docs exist, no placeholder text."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MARKDOWN = sorted(REPO_ROOT.glob("*.md")) + sorted(REPO_ROOT.glob("docs/*.md")) + sorted(
    REPO_ROOT.glob("corpus/*.md")
) + sorted(REPO_ROOT.glob("examples/**/*.md"))
LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

REQUIRED = [
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "PLAN.md",
    "docs/01-what-is-prompt-injection.md",
    "docs/02-threat-model.md",
    "docs/03-attack-taxonomy.md",
    "docs/04-defense-in-depth.md",
    "docs/05-integration-guides.md",
    "docs/06-limitations-and-honesty.md",
    "docs/07-faq.md",
    "docs/benchmark-results.md",
]


def test_required_documents_exist():
    missing = [path for path in REQUIRED if not (REPO_ROOT / path).exists()]
    assert not missing, f"missing required files: {missing}"


def test_markdown_files_are_not_empty():
    for path in MARKDOWN:
        assert path.stat().st_size > 200, f"{path.relative_to(REPO_ROOT)} is suspiciously small"


@pytest.mark.parametrize("path", [p for p in MARKDOWN if p.exists()], ids=lambda p: p.name)
def test_internal_links_resolve(path):
    text = path.read_text(encoding="utf-8")
    broken = []
    for target in LINK.findall(text):
        target = target.strip()
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        file_part = target.split("#", 1)[0]
        if not file_part:
            continue
        candidate = (path.parent / file_part).resolve()
        if not candidate.exists():
            broken.append(target)
    assert not broken, f"{path.relative_to(REPO_ROOT)} has broken links: {broken}"


def test_no_placeholder_markers_in_docs():
    for path in MARKDOWN:
        text = path.read_text(encoding="utf-8").lower()
        assert "lorem ipsum" not in text, path
        assert "todo:" not in text, path


def test_readme_contains_required_sections():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for needle in (
        "injection-firewall-kit",
        "Quick start",
        "Benchmark",
        "Architecture",
        "Responsible use",
        "License",
    ):
        assert needle.lower() in readme.lower(), needle
    assert "```mermaid" in readme


def test_docs_state_the_limitations():
    limitations = (REPO_ROOT / "docs" / "06-limitations-and-honesty.md").read_text(encoding="utf-8")
    assert "does not" in limitations.lower()
    assert "attack" in limitations.lower()


def test_security_policy_mentions_responsible_use():
    policy = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8").lower()
    assert "responsible use" in policy
    assert "does **not** make an application safe" in policy
