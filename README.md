# Runtime Prompt Injection against LLM-Based Malware Triage

**Status: preliminary experiment (work in progress).** A small, honest probe of
one question, not a finished study or a benchmark.

SOC teams are starting to let LLMs read sandbox reports and call benign/malicious.
Published attacks so far hide instructions in *static* artefacts — a file's bytes,
a log line. This probe asks the next question: can text that only appears at
**runtime** — a process name, a dropped-file name, a registry value, a mutex, a
DNS label — survive into a CAPEv2 report and flip an LLM's verdict from malicious
to benign? And does a simple **provenance-tagging** defense reduce that?

This repository classifies *reports*. It never executes a sample and contains no
malware. The injected strings (see `src/injections.py`) are plain text.

## Results (llama3.1:8b, 2026-11-10)

![ASR by payload](figures/asr_by_payload_llama3.1-8b.png)

| | Value |
|---|---|
| Model | `llama3.1:8b` via Ollama, temperature 0, 16,384-token context |
| Reports | 50 real Avast-CTU CAPEv2 reduced reports, 5 per family × 10 families, all malicious |
| Detected as malicious when clean (baseline) | **19 / 50 (38%)**, so n = 19 for the attack |
| Payload present in the text the model saw | 19 / 19 for every condition |
| **Overall ASR, undefended** | **43%** (57 / 133 attack calls) |
| **Overall ASR, with provenance tagging** | **21%** (28 / 133) |
| Control: clean report + defense, flipped to benign | 1 / 19 |
| Unparseable / error verdicts | 0 |

Per condition (n = 19 reports each):

| Condition | Channel | Undefended | Defended |
|---|---|---|---|
| `override_benign` | process name | **68%** | 37% |
| `role_confusion` | mutex | 53% | 16% |
| `fragment_ab` | process name + created file | 53% | 37% |
| `authority_spoof` | registry value | 42% | 11% |
| `benign_framing` | DNS query | 32% | 37% |
| `fragment_a` | process name | 26% | 0% |
| `fragment_b` | created file | 26% | 11% |

What the numbers suggest (directional only, see limitations):

- **Runtime strings flip verdicts often.** A single instruction in a process name
  turned 13 of 19 correct *malicious* verdicts into *benign*, although the system
  prompt already says the summary is untrusted data, never instructions.
- **Fragmentation works when the halves meet.** Each half alone reaches 26%; both
  halves in the same report reach 53%.
- **Provenance tagging roughly halves ASR** (43% → 21%). The control (defense on a
  clean report) flipped only 1 of 19, so the drop is not mainly the defense
  pushing everything toward benign.
- **The defense does not help against benign framing.** `benign_framing` is not an
  instruction but a reassuring-looking DNS name; fencing it as untrusted does
  nothing (32% → 37%, a one-report difference). Provenance tagging addresses
  instruction-following, not persuasion through plausible-looking evidence.

Raw per-call verdicts and reasons: `results/llama3.1-8b/calls.jsonl`;
aggregate: `results/llama3.1-8b/summary.json`.

### Baseline detection by family

The attack can only be measured where the model is right on the clean report, so
which families survive the baseline shapes the result.

| Family | Clean reports flagged malicious |
|---|---|
| Lokibot | 5 / 5 |
| Qakbot | 5 / 5 |
| Trickbot | 3 / 5 |
| Ursnif | 3 / 5 |
| Zeus | 2 / 5 |
| njRAT | 1 / 5 |
| Adload, Emotet, HarHar, Swisyn | 0 / 5 each |

Most misses came with explanations like "appears to be a legitimate Windows
application … standard Windows APIs". The reduced reports carry no signatures,
process tree or network section (see limitations), which likely makes many
samples look ordinary to a small model.

## Limitations

- **Small sample.** n = 19 attacked reports. A one-report change moves a
  per-condition ASR by ~5 points, and per-condition differences under ~20 points
  should not be read as real. A Wilson 95% interval on the overall ASR is roughly
  35–51% undefended and 15–29% defended, but it treats every call as independent;
  calls on the same report are correlated, so the true interval is wider.
- **One small model.** All numbers are for `llama3.1:8b`. A stronger model may
  detect more samples and resist more injections; that comparison is the obvious
  next run (`--backend anthropic` is supported).
- **Biased attack set.** The 19 reports come only from Lokibot, Qakbot, Trickbot,
  Ursnif, Zeus and njRAT. Results say nothing about Adload, Emotet, HarHar or
  Swisyn.
- **Reduced reports.** The Avast-CTU reduced reports have no `processes`,
  `network` or `signatures` fields. The model judges from APIs, registry, files
  and mutexes only. As a result the `process_name` and `dns_query` channels only
  exist in reports that carry an injected payload, so in those conditions the
  payload is the only process / the only DNS name, which makes it more salient
  than it would be in a full report.
- **Simulated placement.** No sample is executed; the payload is inserted where a
  runtime value would land. This does not prove every sandbox records such a
  value verbatim in that field.
- **Defense approximation.** `wrap_untrusted` fences comma-separated values, so a
  payload that itself contains commas (`authority_spoof`) is fenced as two pieces.
  All of it is still inside markers. The defense is a cheap baseline to measure,
  not a claim of robustness; an attacker can target the markers themselves.
- **Output length.** `max_tokens=200` occasionally cut a long JSON reason; 6 of the
  50 baseline verdicts were read from the `"label"` field of truncated JSON. All 6
  were re-queried and matched.

## Method

1. Classify each clean report once. Only reports the model labels *malicious*
   count (flipping an already-wrong verdict proves nothing).
2. For each counted report: one control call (clean report + defense), then each
   of 7 conditions × {undefended, defended} = 14 calls. A *benign* answer is a
   successful attack.
3. ASR = flips / counted reports, per condition and overall.

Payload placement: each payload is inserted at a seeded random position inside
the first 40 items of its field (the part of the list the analyst view shows),
not at the start or end, so it is neither dropped nor unusually salient. The
position depends only on the report name and payload, so runs are reproducible.
An earlier version appended payloads at the end of each list and truncated the
view at 6,000 characters; with real reports (median ~11,000 characters) that
silently dropped the payload in up to 39 of 50 reports for some conditions, which
would have counted delivery failures as failed attacks. The run checks that every
payload is present in the text sent to the model (`payload_reached_view`).

## Dataset

Avast-CTU Public CAPEv2 Dataset, reduced reports
(https://github.com/avast/avast-ctu-cape-dataset). 50 reports sampled with
`src/sample_avast.py` (5 per family, seed 42) from the 48,976-report release.

> Bosansky et al. *Avast-CTU Public CAPE Dataset.* arXiv:2209.03188, 2022.

The report files are not committed (`data/` is in `.gitignore`); re-create them
with `sample_avast.py` from the public release. Check the dataset's licence before
redistributing reports.

## What's here

| File | Role |
|---|---|
| `src/injections.py` | Payloads × the runtime channel each would arrive through, plus multi-field combos |
| `src/reports.py` | Load a reduced CAPEv2 report, inject payloads, flatten to an analyst view |
| `src/classifier.py` | Benign/malicious verdict: `mock`, `anthropic`, or `openai`/Ollama backend |
| `src/defense.py` | Provenance tagging: fence sample-derived values, tell the model to never obey them |
| `src/baseline_check.py` | Clean-report detection rate for a model, run before the full experiment |
| `src/run_experiment.py` | Inject × classify over a report folder; resumable via `calls.jsonl` |
| `src/plot_results.py` | Bar chart of ASR, undefended vs defended |
| `src/sample_avast.py` | Reproducible sampling from the Avast-CTU release |
| `src/make_demo_data.py` | Synthetic reports so the pipeline runs offline |

## Reproduce

```bash
pip install -r requirements.txt openai
# Ollama: set OLLAMA_CONTEXT_LENGTH=16384 before starting it. The default context
# silently drops the start of long prompts, and the payload with it.
ollama pull llama3.1:8b
export OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_API_KEY=ollama
cd src
python sample_avast.py <path-to-avast-ctu-dataset>
python baseline_check.py --backend openai --model llama3.1:8b --n 0
python run_experiment.py --reports ../data/reports --labels ../data/labels.csv \
    --backend openai --model llama3.1:8b --out ../results/llama3.1-8b
python plot_results.py --results ../results/llama3.1-8b
```

Every call is logged to `<out>/calls.jsonl` as it returns; re-running the same
command resumes instead of starting over. For Claude, set `ANTHROPIC_API_KEY` and
use `--backend anthropic --model <model>` with its own `--out` folder.

**Offline demo:** `make demo` runs synthetic reports through a keyword-rule
`mock` classifier to show the pipeline works. It **overwrites `data/reports` and
`data/labels.csv`**, and the mock is not a model, so its numbers mean nothing.
Don't run it in a checkout that holds the real reports.

## Next steps

Run a stronger model on the same 50 reports for comparison; run real samples in
an isolated VM so the injected strings come from genuine execution; widen
payloads and report schemas (full CAPEv2 reports with signatures and network);
and compare provenance tagging with detection-based and structured-output
defenses, especially against non-instruction payloads like benign framing.

## Citing this work

This is a preliminary, ongoing experiment. If you refer to it, please link the
repository and note the model and sample size the numbers come from
(`llama3.1:8b`, n = 19 attacked reports):

> Runtime Prompt Injection against LLM-Based Malware Triage (preliminary).
> https://github.com/Gar-tech/llm-soc-injection, 2026.
