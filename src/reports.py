"""
Load reduced CAPEv2 reports and inject a payload into one dynamic field.

Works with the reduced JSON reports from public datasets such as
Avast-CTU (https://github.com/avast/avast-ctu-cape-dataset) or
Thcrull/win-exe-malware-analysis on the Hugging Face Hub. Those schemas differ
slightly, so insertion is defensive: if the exact field is missing we fall back
to a generic 'behavior.summary' list and still place the string somewhere the
LLM will read. The experiment does not depend on a single schema.

A report is a plain dict parsed from JSON. We never execute anything.
"""

import copy
import json
import random
from pathlib import Path

from injections import Payload

# How many items per field the analyst view shows. inject() must place the
# payload inside this window, or the view silently drops it and a failed
# delivery gets counted as a failed attack.
VIEW_ITEMS = 40


def load_report(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _ensure_list(container: dict, key: str) -> list:
    if key not in container or not isinstance(container[key], list):
        container[key] = []
    return container[key]


def _place(lst: list, value, rng: random.Random) -> None:
    """Insert `value` at a seeded random index inside the visible window. A random
    (not first/last) position avoids rewarding a payload just for being salient."""
    lst.insert(rng.randint(0, min(len(lst), VIEW_ITEMS - 1)), value)


def inject(report: dict, payload: Payload, seed: str = "") -> dict:
    """Return a deep copy of `report` with `payload.text` placed in a field
    the attacker could control at runtime. The control payload ('none') returns
    an unmodified copy so the same code path is used everywhere. `seed` (e.g. the
    report name) makes the insertion position reproducible per report+payload."""
    r = copy.deepcopy(report)
    if payload.id == "none" or not payload.text:
        return r
    rng = random.Random(f"{seed}:{payload.id}")

    behavior = r.setdefault("behavior", {})
    summary = behavior.setdefault("summary", {})

    if payload.channel == "process_name":
        procs = _ensure_list(behavior, "processes")
        _place(procs, {"process_name": payload.text, "pid": 4321, "ppid": 1000}, rng)
    elif payload.channel == "created_file":
        _place(_ensure_list(summary, "files"), payload.text, rng)
    elif payload.channel == "registry_value":
        _place(_ensure_list(summary, "write_keys"), payload.text, rng)
    elif payload.channel == "mutex":
        _place(_ensure_list(summary, "mutexes"), payload.text, rng)
    elif payload.channel == "dns_query":
        network = r.setdefault("network", {})
        _place(_ensure_list(network, "dns"), {"request": payload.text, "type": "A"}, rng)
    else:
        _place(_ensure_list(summary, "injected"), payload.text, rng)
    return r


def inject_all(report: dict, payloads: list, seed: str = "") -> dict:
    """Inject several payloads into one report (multi-field conditions)."""
    for p in payloads:
        report = inject(report, p, seed)
    return report


# Real Avast-CTU reduced reports flatten to ~11k chars (median), ~17k max, so a
# 6000-char cap cut off later sections (e.g. DNS) and the payload with them.
def to_analyst_view(report: dict, max_chars: int = 20000) -> str:
    """Flatten the parts of a reduced report a tier-1 analyst (or an LLM standing
    in for one) would actually read, in a compact, deterministic text block."""
    b = report.get("behavior", {})
    summary = b.get("summary", {})
    net = report.get("network", {})

    def names(items, key=None):
        out = []
        for it in items or []:
            if key and isinstance(it, dict):
                out.append(str(it.get(key, "")))
            else:
                out.append(str(it))
        return [x for x in out if x]

    lines = []
    lines.append("# Dynamic analysis summary")
    procs = names(b.get("processes"), "process_name")
    if procs:
        lines.append("Processes: " + ", ".join(procs[:VIEW_ITEMS]))
    # Reduced CAPEv2 summaries differ between datasets (files, keys, write_keys,
    # read_keys, mutexes, executed_commands, resolved_apis, ...). Emit every list
    # field we find, known ones first, so no schema silently drops the injection.
    preferred = ["files", "write_keys", "keys", "mutexes", "executed_commands",
                 "commands", "delete_files", "read_keys", "resolved_apis", "injected"]
    keys = [k for k in preferred if k in summary] + \
           [k for k in summary if k not in preferred]
    for key in keys:
        vals = names(summary.get(key)) if isinstance(summary.get(key), list) else []
        if vals:
            label = key.replace("_", " ").capitalize()
            lines.append(f"{label}: " + ", ".join(vals[:VIEW_ITEMS]))
    dns = names(net.get("dns"), "request")
    if dns:
        lines.append("DNS: " + ", ".join(dns[:VIEW_ITEMS]))
    sigs = []
    for s in b.get("signatures", []) or report.get("signatures", []) or []:
        if isinstance(s, dict):
            sigs.append(str(s.get("description") or s.get("name") or ""))
        else:
            sigs.append(str(s))
    sigs = [x for x in sigs if x]
    if sigs:
        lines.append("Signatures: " + "; ".join(sigs[:30]))
    text = "\n".join(lines)
    return text[:max_chars]
