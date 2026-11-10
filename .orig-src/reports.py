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
from pathlib import Path

from injections import Payload


def load_report(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _ensure_list(container: dict, key: str) -> list:
    if key not in container or not isinstance(container[key], list):
        container[key] = []
    return container[key]


def inject(report: dict, payload: Payload) -> dict:
    """Return a deep copy of `report` with `payload.text` placed in a field
    the attacker could control at runtime. The control payload ('none') returns
    an unmodified copy so the same code path is used everywhere."""
    r = copy.deepcopy(report)
    if payload.id == "none" or not payload.text:
        return r

    behavior = r.setdefault("behavior", {})
    summary = behavior.setdefault("summary", {})

    if payload.channel == "process_name":
        procs = _ensure_list(behavior, "processes")
        procs.append({"process_name": payload.text, "pid": 4321, "ppid": 1000})
    elif payload.channel == "created_file":
        _ensure_list(summary, "files").append(payload.text)
    elif payload.channel == "registry_value":
        _ensure_list(summary, "write_keys").append(payload.text)
    elif payload.channel == "mutex":
        _ensure_list(summary, "mutexes").append(payload.text)
    elif payload.channel == "dns_query":
        network = r.setdefault("network", {})
        _ensure_list(network, "dns").append({"request": payload.text, "type": "A"})
    else:
        _ensure_list(summary, "injected").append(payload.text)
    return r


def to_analyst_view(report: dict, max_chars: int = 6000) -> str:
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
        lines.append("Processes: " + ", ".join(procs[:40]))
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
            lines.append(f"{label}: " + ", ".join(vals[:40]))
    dns = names(net.get("dns"), "request")
    if dns:
        lines.append("DNS: " + ", ".join(dns[:40]))
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
