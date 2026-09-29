"""File Integrity Monitor: detect added, deleted, modified, and permission-changed files.

usage:
  python fim.py baseline DIR [--db baseline.json]
  python fim.py check    DIR [--db baseline.json] [--log alerts.jsonl]
  python fim.py watch    DIR [--db baseline.json] [--interval 10]
"""
import argparse
import hashlib
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone

RED, YEL, GRN, DIM, B, R = "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[1m", "\033[0m"
if not (sys.stdout.isatty() or os.environ.get("FORCE_COLOR")):
    RED = YEL = GRN = DIM = B = R = ""


def sha256(path, chunk=1 << 16):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def snapshot(root):
    """{relative path: {sha256, size, mode}} for every regular file under root (symlinks skipped)."""
    snap = {}
    for dirpath, _, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            try:
                st = os.stat(full)
                snap[os.path.relpath(full, root)] = {"sha256": sha256(full), "size": st.st_size,
                                                     "mode": stat.filemode(st.st_mode)}
            except (PermissionError, FileNotFoundError) as e:
                print(f"{YEL}skipped {full}: {e.__class__.__name__}{R}")
    return snap


def compare(old, new):
    """Returns a sorted list of (event, path, detail)."""
    events = []
    for p in new.keys() - old.keys():
        events.append(("ADDED", p, f"{new[p]['size']} bytes"))
    for p in old.keys() - new.keys():
        events.append(("DELETED", p, ""))
    for p in old.keys() & new.keys():
        if old[p]["sha256"] != new[p]["sha256"]:
            events.append(("MODIFIED", p, f"sha256 {old[p]['sha256'][:12]}… → {new[p]['sha256'][:12]}…"))
        if old[p]["mode"] != new[p]["mode"]:
            events.append(("PERMISSIONS", p, f"{old[p]['mode']} → {new[p]['mode']}"))
    return sorted(events, key=lambda e: (e[0], e[1]))


def report(events, log_path):
    color = {"ADDED": YEL, "DELETED": RED, "MODIFIED": RED, "PERMISSIONS": YEL}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not events:
        print(f"{GRN}✔ no changes since baseline{R}")
        return
    print(f"{B}{len(events)} change(s) detected{R}")
    for kind, path, detail in events:
        print(f"  {color[kind]}{kind:<12}{R}{path}  {DIM}{detail}{R}")
    with open(log_path, "a") as f:
        for kind, path, detail in events:
            f.write(json.dumps({"time": now, "event": kind, "path": path, "detail": detail}) + "\n")
    print(f"{DIM}alerts appended to {log_path}{R}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["baseline", "check", "watch"])
    ap.add_argument("dir")
    ap.add_argument("--db", default="baseline.json")
    ap.add_argument("--log", default="alerts.jsonl")
    ap.add_argument("--interval", type=int, default=10)
    a = ap.parse_args()
    if not os.path.isdir(a.dir):
        ap.error(f"not a directory: {a.dir}")

    if a.cmd == "baseline":
        snap = snapshot(a.dir)
        with open(a.db, "w") as f:
            json.dump({"root": os.path.abspath(a.dir), "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "files": snap}, f, indent=1)
        print(f"{GRN}✔ baseline saved:{R} {len(snap)} files hashed → {a.db}")
        return
    if not os.path.exists(a.db):
        ap.error(f"no baseline at {a.db}; run 'baseline' first")
    with open(a.db) as f:
        old = json.load(f)["files"]
    if a.cmd == "check":
        report(compare(old, snapshot(a.dir)), a.log)
        return
    print(f"watching {a.dir} every {a.interval}s (Ctrl+C to stop)")
    while True:  # ponytail: polling; switch to OS file events (watchdog) if near-instant alerts are needed
        events = compare(old, snapshot(a.dir))
        if events:
            report(events, a.log)
            old = snapshot(a.dir)  # alert once per change
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
