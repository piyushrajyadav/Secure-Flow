"""
Download InjecAgent (Zhan et al., ACL Findings 2024, MIT licence) pinned to one commit.

    python -m experiments.external.fetch_injecagent

Files land in data/external/injecagent/ (git-ignored; not redistributed here).
The content is adversarial TEXT used purely as data: it is only ever parsed with json and
passed to the scorer; nothing in it is executed.
"""
import hashlib
import os
import urllib.request

COMMIT = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
BASE = f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/{COMMIT}/data/"
FILES = ["test_cases_dh_base.json", "test_cases_dh_enhanced.json", "test_cases_ds_base.json",
         "test_cases_ds_enhanced.json", "user_cases.jsonl", "tools.json", "attacker_cases_dh.jsonl", "attacker_cases_ds.jsonl"]
OUT = os.path.join("data", "external", "injecagent")


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in FILES:
        path = os.path.join(OUT, name)
        if not os.path.exists(path):
            with urllib.request.urlopen(BASE + name, timeout=60) as r:
                data = r.read()
            with open(path, "wb") as f:
                f.write(data)
        with open(path, "rb") as f:
            print(f"{name:34} {os.path.getsize(path):>9} bytes  sha256={hashlib.sha256(f.read()).hexdigest()[:16]}")


if __name__ == "__main__":
    main()
