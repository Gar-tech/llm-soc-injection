"""
Plot attack success rate per payload, undefended vs defended, from summary.json.
Writes figures/asr_by_payload.png. Pure matplotlib, no seaborn.
"""

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(ROOT / "results"),
                    help="folder holding summary.json (the --out of run_experiment)")
    results = Path(ap.parse_args().results)
    summary = json.loads((results / "summary.json").read_text(encoding="utf-8"))
    undef = summary["asr_undefended"]
    deff = summary["asr_defended"]
    payloads = list(undef.keys())
    x = range(len(payloads))
    w = 0.38

    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar([i - w / 2 for i in x], [undef[p] * 100 for p in payloads], w,
           label="Undefended", color="#c0392b")
    ax.bar([i + w / 2 for i in x], [deff[p] * 100 for p in payloads], w,
           label="With provenance tagging", color="#2471a3")
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Runtime prompt-injection evasion of LLM malware triage\n"
                 f"backend={summary['backend']} model={summary.get('model')} "
                 f"n={summary['malicious_reports_considered']}")
    ax.set_xticks(list(x))
    ax.set_xticklabels(payloads, rotation=30, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    out = ROOT / "figures" / f"asr_by_payload_{results.name}.png"
    out.parent.mkdir(exist_ok=True)
    fig.savefig(out, dpi=130)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
