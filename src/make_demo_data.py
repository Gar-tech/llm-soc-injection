"""
Generate a small synthetic set of reduced-CAPEv2-style reports for the offline
demo, so `make demo` runs with no download and no network. The schema mirrors the
public reduced reports (behavior.processes, behavior.summary.{files,write_keys,
mutexes,executed_commands}, network.dns) closely enough that the same code runs
unchanged on the real Avast-CTU dataset.

These are not real malware traces. They are plausible-looking placeholders whose
only purpose is to exercise the pipeline end to end.
"""

import json
import random
from pathlib import Path

random.seed(7)

BENIGN_PROCS = ["setup.exe", "notepad.exe", "chrome.exe", "updater.exe", "svchost.exe"]
MAL_PROCS = ["invoice_scan.exe", "svch0st.exe", "winlogon32.exe", "update_helper.exe"]

MAL_FILES = ["C:\\Users\\Public\\readme_decrypt.txt", "%TEMP%\\payload.dll",
             "%APPDATA%\\persist\\run.vbs"]
MAL_KEYS = ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\xmr"]
MAL_CMDS = ["powershell -enc SQBFAFgA", "vssadmin delete shadows /all /quiet",
            "schtasks /create /tn Updater /sc onlogon"]
MAL_MUTEX = ["Global\\LockerMutex", "Global\\m_stealer_01"]
MAL_DNS = ["c2.badnode.top", "pool.minexmr.example", "exfil.data-sink.net"]

BENIGN_FILES = ["%TEMP%\\setup.log", "%APPDATA%\\app\\config.ini"]
BENIGN_KEYS = ["HKCU\\Software\\MyApp\\Settings"]
BENIGN_CMDS = ["setup.exe /quiet"]
BENIGN_DNS = ["update.microsoft.com", "clients2.google.com"]


def mk(i, malicious):
    p = (MAL_PROCS if malicious else BENIGN_PROCS)
    report = {
        "behavior": {
            "processes": [{"process_name": random.choice(p), "pid": 1000 + i}],
            "summary": {
                "files": random.sample(MAL_FILES if malicious else BENIGN_FILES,
                                       k=2 if malicious else 1),
                "write_keys": random.sample(MAL_KEYS if malicious else BENIGN_KEYS,
                                            k=1),
                "mutexes": random.sample(MAL_MUTEX, k=1) if malicious else [],
                "executed_commands": random.sample(MAL_CMDS if malicious else BENIGN_CMDS,
                                                   k=2 if malicious else 1),
            },
        },
        "network": {
            "dns": [{"request": d, "type": "A"}
                    for d in random.sample(MAL_DNS if malicious else BENIGN_DNS, k=1)]
        },
    }
    return report


def main():
    root = Path(__file__).resolve().parent.parent / "data"
    rep_dir = root / "reports"
    rep_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for i in range(30):
        malicious = i % 2 == 0
        name = f"sample_{i:03d}.json"
        with open(rep_dir / name, "w") as fh:
            json.dump(mk(i, malicious), fh, indent=2)
        rows.append((name, "malicious" if malicious else "benign"))
    with open(root / "labels.csv", "w") as fh:
        fh.write("report,label\n")
        for name, lab in rows:
            fh.write(f"{name},{lab}\n")
    print(f"Wrote {len(rows)} demo reports to {rep_dir} and labels.csv")


if __name__ == "__main__":
    main()
