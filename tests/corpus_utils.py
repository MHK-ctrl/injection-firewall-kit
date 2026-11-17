"""Helpers shared by the corpus tests and by CI's explicit schema validation step."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "corpus"
SCHEMA_PATH = CORPUS_DIR / "schema.json"


def corpus_files() -> list[Path]:
    return sorted((CORPUS_DIR / "attacks").glob("*.jsonl")) + sorted(
        (CORPUS_DIR / "benign").glob("*.jsonl")
    )


def load_samples() -> list[dict]:
    samples: list[dict] = []
    for path in corpus_files():
        with path.open("r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError as exc:  # pragma: no cover - reported by tests
                    raise ValueError(f"{path.name}:{lineno}: invalid JSON: {exc}") from exc
    return samples


def validate_corpus(schema_path: Path | None = None) -> int:
    """Validate every sample against the schema. Returns the number of samples.

    Raises ``jsonschema.ValidationError`` (or ``ValueError`` for cross-file rules) on the
    first problem, so the message names the offending sample.
    """
    import jsonschema

    schema = json.loads(Path(schema_path or SCHEMA_PATH).read_text(encoding="utf-8"))
    samples = load_samples()
    ids = set()
    for sample in samples:
        try:
            jsonschema.validate(sample, schema)
        except jsonschema.ValidationError as exc:
            raise ValueError(f"sample {sample.get('id')!r} fails schema: {exc.message}") from exc
        if sample["id"] in ids:
            raise ValueError(f"duplicate sample id {sample['id']!r}")
        ids.add(sample["id"])
    return len(samples)


def by_label(label: str) -> Iterable[dict]:
    return (s for s in load_samples() if s["expected_label"] == label)


if __name__ == "__main__":  # pragma: no cover - CLI entry used by CI
    total = validate_corpus()
    print(f"validated {total} corpus samples against {SCHEMA_PATH.name}")
