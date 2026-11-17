"""Measure a defence against the bundled corpus.

Two numbers matter and they pull in opposite directions:

* **recall** - of the attacks, how many were flagged?
* **false-positive rate** - of the benign look-alikes, how many were flagged?

A defence that flags everything scores recall 1.0 and is useless. A defence that flags
nothing scores a perfect false-positive rate and is also useless. The benchmark reports
both, plus precision and F1, per category and per carrier.

"Flagged" means ``risk_score >= threshold`` (default 20, the warn threshold). The policy
action is reported separately so you can see what would actually happen to the content.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from firewall.policy import decide, load_policy
from firewall.scanner import Scanner

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "corpus"
DEFAULT_THRESHOLD = 20


@dataclass(frozen=True)
class Sample:
    id: str
    category: str
    carrier: str
    text: str
    expected_label: str
    severity: str
    notes: str

    @property
    def is_attack(self) -> bool:
        return self.expected_label == "attack"


def load_corpus(corpus_dir: str | Path | None = None) -> list[Sample]:
    root = Path(corpus_dir) if corpus_dir else CORPUS_DIR
    files = sorted((root / "attacks").glob("*.jsonl")) + sorted((root / "benign").glob("*.jsonl"))
    if not files:
        raise FileNotFoundError(f"no corpus files under {root}")
    samples: list[Sample] = []
    for path in files:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    samples.append(Sample(**json.loads(line)))
    return samples


def _metrics(tp: int, fp: int, fn: int, tn: int) -> dict[str, float | int]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    total = tp + fp + fn + tn
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
    }


def evaluate(
    samples: Sequence[Sample],
    *,
    scanner: Scanner | None = None,
    threshold: int = DEFAULT_THRESHOLD,
    policy: str | dict | None = "balanced",
) -> list[dict]:
    """Scan every sample and return one record per sample."""
    scanner = scanner or Scanner()
    resolved = load_policy(policy)
    records: list[dict] = []
    for sample in samples:
        result = scanner.scan(sample.text, sample.carrier, policy=resolved)
        decision = decide(result, resolved)
        flagged = result.risk_score >= threshold
        records.append(
            {
                "id": sample.id,
                "category": sample.category,
                "carrier": sample.carrier,
                "label": sample.expected_label,
                "severity": sample.severity,
                "score": result.risk_score,
                "flagged": flagged,
                "action": decision.action,
                "findings": len(result.findings),
                "detectors": sorted({f.detector for f in result.findings}),
                "categories_hit": result.categories,
                "correct": flagged == sample.is_attack,
            }
        )
    return records


def _group(records: Iterable[dict], key: str) -> dict[str, dict]:
    grouped: dict[str, dict] = {}
    for record in records:
        bucket = grouped.setdefault(
            record[key], {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "attacks": 0, "benign": 0}
        )
        if record["label"] == "attack":
            bucket["attacks"] += 1
            if record["flagged"]:
                bucket["tp"] += 1
            else:
                bucket["fn"] += 1
        else:
            bucket["benign"] += 1
            if record["flagged"]:
                bucket["fp"] += 1
            else:
                bucket["tn"] += 1
    out: dict[str, dict] = {}
    for name, bucket in grouped.items():
        metrics = _metrics(bucket["tp"], bucket["fp"], bucket["fn"], bucket["tn"])
        metrics["attacks"] = bucket["attacks"]
        metrics["benign"] = bucket["benign"]
        out[name] = metrics
    return out


def run_benchmark(
    *,
    threshold: int = DEFAULT_THRESHOLD,
    policy: str | dict | None = "balanced",
    corpus_dir: str | Path | None = None,
    scanner: Scanner | None = None,
) -> dict:
    """Run the whole corpus and return a JSON-serialisable result document."""
    samples = load_corpus(corpus_dir)
    records = evaluate(samples, scanner=scanner, threshold=threshold, policy=policy)

    attacks = [r for r in records if r["label"] == "attack"]
    benign = [r for r in records if r["label"] == "benign"]
    overall = _metrics(
        tp=sum(1 for r in attacks if r["flagged"]),
        fn=sum(1 for r in attacks if not r["flagged"]),
        fp=sum(1 for r in benign if r["flagged"]),
        tn=sum(1 for r in benign if not r["flagged"]),
    )

    attack_scores = [r["score"] for r in attacks]
    benign_scores = [r["score"] for r in benign]
    detector_hits: dict[str, int] = {}
    for record in records:
        for name in record["detectors"]:
            detector_hits[name] = detector_hits.get(name, 0) + 1

    actions: dict[str, int] = {}
    for record in records:
        actions[record["action"]] = actions.get(record["action"], 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "policy": load_policy(policy)["name"],
        "threshold": threshold,
        "totals": {
            "samples": len(records),
            "attacks": len(attacks),
            "benign": len(benign),
        },
        "overall": overall,
        "per_category": _group(records, "category"),
        "per_carrier": _group(records, "carrier"),
        "score_distribution": {
            "attacks": {
                "min": min(attack_scores, default=0),
                "median": statistics.median(attack_scores) if attack_scores else 0,
                "mean": round(statistics.fmean(attack_scores), 2) if attack_scores else 0.0,
                "max": max(attack_scores, default=0),
            },
            "benign": {
                "min": min(benign_scores, default=0),
                "median": statistics.median(benign_scores) if benign_scores else 0,
                "mean": round(statistics.fmean(benign_scores), 2) if benign_scores else 0.0,
                "max": max(benign_scores, default=0),
            },
        },
        "detector_hits": dict(sorted(detector_hits.items(), key=lambda kv: -kv[1])),
        "actions": dict(sorted(actions.items(), key=lambda kv: -kv[1])),
        "false_negatives": [
            {
                "id": r["id"],
                "category": r["category"],
                "carrier": r["carrier"],
                "score": r["score"],
                "severity": r["severity"],
            }
            for r in attacks
            if not r["flagged"]
        ],
        "false_positives": [
            {
                "id": r["id"],
                "category": r["category"],
                "carrier": r["carrier"],
                "score": r["score"],
                "action": r["action"],
                "detectors": r["detectors"],
            }
            for r in benign
            if r["flagged"]
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark the detectors over the corpus.")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parser.add_argument("--policy", default="balanced")
    parser.add_argument("--json", default="", help="write raw results here")
    parser.add_argument("--markdown", default="", help="write a Markdown report here")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    results = run_benchmark(threshold=args.threshold, policy=args.policy)
    overall = results["overall"]
    if not args.quiet:
        print(
            "samples={samples} attacks={attacks} benign={benign}".format(**results["totals"])
        )
        print(
            "precision={precision:.3f} recall={recall:.3f} f1={f1:.3f} fpr={false_positive_rate:.3f}".format(
                **overall
            )
        )
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
    if args.markdown:
        from .report import render_markdown

        Path(args.markdown).write_text(render_markdown(results), encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
