"""Stamp every result file with the code version and environment that produced it."""
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone


def _git(*args):
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return ""


def provenance() -> dict:
    status = [l for l in _git("status", "--porcelain").splitlines() if "data/results" not in l.replace("\\", "/")]
    return {
        "code_commit": _git("rev-parse", "HEAD") or "unknown",
        "working_tree_clean": not status,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def dump(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    out = {"provenance": provenance(), **obj}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
