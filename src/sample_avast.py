"""
Reproducibly sample reduced reports from the Avast-CTU Public CAPEv2 dataset.

Stratified by malware family (PER_FAMILY each, fixed seed), extracted straight
from public_small_reports.zip into data/reports/, and data/labels.csv written
(every report in this dataset is malicious). Report JSON only; no samples.

usage: python sample_avast.py <dataset_dir> [--per-family 5] [--seed 42]
"""
import argparse, csv, random, zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ap = argparse.ArgumentParser()
ap.add_argument("dataset_dir")
ap.add_argument("--per-family", type=int, default=5)
ap.add_argument("--seed", type=int, default=42)
a = ap.parse_args()

ds = Path(a.dataset_dir)
by_fam = defaultdict(list)
with open(ds / "public_labels.csv", newline="") as fh:
    for row in csv.DictReader(fh):
        by_fam[row["classification_family"]].append(row["sha256"])

rng = random.Random(a.seed)
chosen = []
for fam in sorted(by_fam):
    for h in rng.sample(sorted(by_fam[fam]), a.per_family):
        chosen.append((h, fam))

out = ROOT / "data" / "reports"
out.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(ds / "public_small_reports.zip") as z:
    for h, _ in chosen:
        (out / f"{h}.json").write_bytes(z.read(f"public_small_reports/{h}.json"))

with open(ROOT / "data" / "labels.csv", "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["report", "label", "family"])
    for h, fam in chosen:
        w.writerow([f"{h}.json", "malicious", fam])
print(f"Wrote {len(chosen)} reports to {out}")
