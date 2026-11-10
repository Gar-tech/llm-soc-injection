"""
Step 4 of the plan: how many clean (un-injected) malicious reports does a model
flag as malicious? Run this before the full experiment to pick a model; ASR can
only be measured on reports the model detects when clean.

Answers go into the same calls.jsonl cache run_experiment.py uses (cond 'none',
undefended), so the full run reuses them instead of paying for them again.

usage (PowerShell or bash, from src/):
    python baseline_check.py --backend openai --model llama3.1:8b --n 12
    python baseline_check.py --backend anthropic --model claude-sonnet-5-5 --n 50
"""
import argparse
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from classifier import classify  # noqa: E402
from reports import load_report, to_analyst_view  # noqa: E402
from run_experiment import CallCache, read_labels, ROOT  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--backend", default="openai", choices=["openai", "anthropic", "mock"])
ap.add_argument("--model", default="llama3.1:8b")
ap.add_argument("--n", type=int, default=12, help="number of reports (0 = all 50)")
ap.add_argument("--reports", default=str(ROOT / "data" / "reports"))
ap.add_argument("--labels", default=str(ROOT / "data" / "labels.csv"))
ap.add_argument("--out", default=None, help="results folder (default ../results/<model>)")
a = ap.parse_args()

out = Path(a.out or ROOT / "results" / a.model.replace(":", "-").replace("/", "-"))
out.mkdir(parents=True, exist_ok=True)
cache = CallCache(out / "calls.jsonl", a.backend, a.model)

fam = {}
import csv  # noqa: E402
with open(a.labels, newline="", encoding="utf-8") as fh:
    for r in csv.DictReader(fh):
        fam[r["report"]] = r.get("family", "")
labels = read_labels(a.labels)

ps = sorted(Path(a.reports).glob("*.json"))
ps = [p for p in ps if labels.get(p.name) == "malicious"]
if a.n:
    ps = ps[: a.n]

t0 = time.time()
counts, by_family = Counter(), Counter()
for p in ps:
    view = to_analyst_view(load_report(p))
    r = cache.get(p.name, "none", False, lambda: classify(view, a.backend, a.model))
    counts[r["label"]] += 1
    by_family[(fam.get(p.name, ""), r["label"])] += 1
    print(f"{p.name[:10]} {fam.get(p.name, ''):9s} {r['label']:9s} {r['reason'][:90]}",
          flush=True)

n = len(ps)
print(f"\nmodel={a.model}  malicious {counts['malicious']}/{n} "
      f"({100 * counts['malicious'] / n:.0f}%)  benign {counts['benign']}  "
      f"error {counts['error']}")
if cache.new_calls:
    print(f"sec/new call {cache.secs / cache.new_calls:.1f}  (new calls: {cache.new_calls})")
print(f"cache: {out / 'calls.jsonl'}")
