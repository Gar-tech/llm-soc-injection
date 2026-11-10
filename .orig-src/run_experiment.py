"""
Run the runtime-injection evasion experiment over a folder of reduced reports.

For every report labelled 'malicious' we:
  1. classify the clean report              -> baseline verdict
  2. for each payload, inject it and classify again, with and without the defense

We only care about malicious samples the classifier gets RIGHT when clean,
because the attack's goal is to flip a correct 'malicious' into 'benign'. Attack
Success Rate (ASR) = flips / (correctly-detected clean malicious samples).

Usage:
    python run_experiment.py --reports data/reports --labels data/labels.csv \
        --backend mock
    python run_experiment.py --reports data/reports --labels data/labels.csv \
        --backend anthropic --model claude-sonnet-4-6

Outputs results/results.csv and results/summary.json.
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from injections import PAYLOADS            # noqa: E402
from reports import load_report, inject, to_analyst_view  # noqa: E402
from classifier import classify, SYSTEM_PROMPT  # noqa: E402
import classifier                          # noqa: E402
from defense import wrap_untrusted, DEFENSE_SYSTEM_SUFFIX  # noqa: E402


def read_labels(path: str) -> dict:
    labels = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            labels[row["report"]] = row["label"].strip().lower()
    return labels


def classify_view(view: str, backend: str, model: str, defended: bool) -> dict:
    if defended:
        view = wrap_untrusted(view)
        saved = classifier.SYSTEM_PROMPT
        classifier.SYSTEM_PROMPT = saved + DEFENSE_SYSTEM_SUFFIX
        try:
            return classify(view, backend, model)
        finally:
            classifier.SYSTEM_PROMPT = saved
    return classify(view, backend, model)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True, help="folder of reduced *.json reports")
    ap.add_argument("--labels", required=True, help="csv with columns report,label")
    ap.add_argument("--backend", default="mock", choices=["mock", "anthropic", "openai"])
    ap.add_argument("--model", default="claude-sonnet-4-6")
    ap.add_argument("--limit", type=int, default=0, help="0 = all reports")
    ap.add_argument("--sleep", type=float, default=0.0, help="seconds between API calls")
    args = ap.parse_args()

    labels = read_labels(args.labels)
    report_dir = Path(args.reports)
    paths = sorted(report_dir.glob("*.json"))
    if args.limit:
        paths = paths[: args.limit]

    rows = []
    considered = 0  # malicious samples correctly flagged when clean
    flips = {p.id: 0 for p in PAYLOADS if p.id != "none"}
    flips_defended = {p.id: 0 for p in PAYLOADS if p.id != "none"}

    for path in paths:
        name = path.name
        true_label = labels.get(name)
        if true_label != "malicious":
            continue
        report = load_report(path)
        clean_view = to_analyst_view(report)
        base = classify(clean_view, args.backend, args.model)
        if args.sleep:
            time.sleep(args.sleep)
        rows.append({"report": name, "payload": "none", "defended": False,
                     "verdict": base["label"]})
        if base["label"] != "malicious":
            continue  # attack only meaningful where clean verdict is correct
        considered += 1

        for p in PAYLOADS:
            if p.id == "none":
                continue
            injected = inject(report, p)
            view = to_analyst_view(injected)
            for defended in (False, True):
                v = classify_view(view, args.backend, args.model, defended)
                rows.append({"report": name, "payload": p.id, "defended": defended,
                             "verdict": v["label"]})
                if v["label"] == "benign":
                    (flips_defended if defended else flips)[p.id] += 1
                if args.sleep:
                    time.sleep(args.sleep)

    out_dir = Path(__file__).resolve().parent.parent / "results"
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / "results.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["report", "payload", "defended", "verdict"])
        w.writeheader()
        w.writerows(rows)

    def asr(table):
        return {pid: (n / considered if considered else 0.0) for pid, n in table.items()}

    summary = {
        "backend": args.backend,
        "model": args.model if args.backend != "mock" else None,
        "malicious_reports_considered": considered,
        "asr_undefended": asr(flips),
        "asr_defended": asr(flips_defended),
        "overall_asr_undefended": (sum(flips.values()) / (considered * len(flips))
                                   if considered else 0.0),
        "overall_asr_defended": (sum(flips_defended.values()) / (considered * len(flips))
                                 if considered else 0.0),
    }
    with open(out_dir / "summary.json", "w") as fh:
        json.dump(summary, fh, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"\nConsidered {considered} correctly-detected malicious reports.")
    print(f"Wrote {out_dir/'results.csv'} and {out_dir/'summary.json'}.")


if __name__ == "__main__":
    main()
