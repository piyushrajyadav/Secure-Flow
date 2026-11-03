"""
Export every evaluation corpus as plain JSONL under data/corpora/ (the released test data),
plus a manifest with SHA-256 checksums.

    python -m experiments.export_corpora

One record per message: {"id", "corpus", "label": "attack"|"benign", "stratum", "text"}.
Texts that contain invisible/tag Unicode are stored with JSON \\u escapes (ensure_ascii=True), so
the files are byte-stable and safe to open in any editor.
"""
import hashlib
import json
import os

from experiments.attack_dataset import get_all_attacks, get_all_legitimate
from experiments.attack_dataset_v2 import get_attacks_v2, get_legit_v2
from experiments.attack_dataset_v3 import ATTACKS_V3, LEGIT_V3
from experiments.provenance import provenance

OUT = os.path.join("data", "corpora")

CORPORA = {
    "v1": {"attacks": get_all_attacks, "benign": get_all_legitimate,
           "note": "Original corpus of the first manuscript (30 attacks / 20 benign). v2 rules were tuned on it."},
    "v2": {"attacks": get_attacks_v2, "benign": get_legit_v2,
           "note": "Written before v2 tuning; its misses were then used to tune, so it is NOT held-out."},
    "v3": {"attacks": lambda: ATTACKS_V3, "benign": lambda: LEGIT_V3,
           "note": "Blind: written after tuning, never tuned on. Contains known weak spots (non-English, semantic)."},
}


def main():
    os.makedirs(OUT, exist_ok=True)
    manifest = {"provenance": provenance(), "files": {}}
    for name, c in CORPORA.items():
        rows = []
        for label, getter in (("attack", c["attacks"]), ("benign", c["benign"])):
            for i, m in enumerate(getter()):
                rows.append({"id": f"{name}-{label}-{i:03d}", "corpus": name, "label": label,
                             "stratum": m.category, "text": m.text})
        path = os.path.join(OUT, f"{name}.jsonl")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=True) + "\n")
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        manifest["files"][f"{name}.jsonl"] = {
            "sha256": digest, "attacks": sum(r["label"] == "attack" for r in rows),
            "benign": sum(r["label"] == "benign" for r in rows), "note": c["note"]}
        print(f"{name}.jsonl  attacks={manifest['files'][f'{name}.jsonl']['attacks']} benign={manifest['files'][f'{name}.jsonl']['benign']} sha256={digest[:16]}")
    with open(os.path.join(OUT, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


if __name__ == "__main__":
    main()
