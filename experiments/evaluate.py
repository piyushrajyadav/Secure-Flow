"""
Before/after evaluation.

    python -m experiments.evaluate            # print tables
    python -m experiments.evaluate --json out.json
    python -m experiments.evaluate --misses   # list every missed attack / false positive

Compares the frozen v1 keyword detector against the current RiskScorer on:
  * v1 dataset (the original 30 attacks / 20 benign - detector was tuned on this)
  * v2 dataset (written first, but its misses were later used to tune - no longer held-out)
  * v3 dataset (blind: written after tuning, never tuned on)
"""
import argparse
import json
from collections import defaultdict

from tabulate import tabulate

from experiments.attack_dataset import get_all_attacks, get_all_legitimate
from experiments.attack_dataset_v2 import get_attacks_v2, get_legit_v2
from experiments.attack_dataset_v3 import ATTACKS_V3, LEGIT_V3
from experiments.legacy_v1 import LegacyScorer
from secureflow.scorer import RiskScorer


def evaluate(is_blocked, attacks, legit):
    by_cat = defaultdict(lambda: [0, 0])          # category -> [blocked, total]
    missed, false_pos = [], []
    for a in attacks:
        blocked = is_blocked(a.text)
        by_cat[a.category][1] += 1
        by_cat[a.category][0] += blocked
        if not blocked:
            missed.append(a)
    for l in legit:
        if is_blocked(l.text):
            false_pos.append(l)
    n_att, n_leg = len(attacks), len(legit)
    caught = sum(b for b, _ in by_cat.values())
    return {
        "attacks": n_att, "legit": n_leg,
        "asr": 100.0 * (n_att - caught) / n_att,
        "detection_rate": 100.0 * caught / n_att,
        "fpr": 100.0 * len(false_pos) / n_leg,
        "precision": 100.0 * caught / (caught + len(false_pos)) if caught + len(false_pos) else 0.0,
        "by_category": {c: {"blocked": b, "total": t} for c, (b, t) in by_cat.items()},
        "missed": [a.text[:90] for a in missed],
        "false_positives": [l.text[:90] for l in false_pos],
    }


def run(threshold: int = 60):
    legacy = LegacyScorer(threshold).is_blocked
    current = RiskScorer(threshold=threshold)
    cur = lambda t: current.score(t).is_blocked
    sets = {
        "v1 dataset (tuned-on)": (get_all_attacks(), get_all_legitimate()),
        "v2 dataset (used in tuning)": (get_attacks_v2(), get_legit_v2()),
        "v3 dataset (blind)": (ATTACKS_V3, LEGIT_V3),
    }
    out = {}
    for name, (att, leg) in sets.items():
        out[name] = {"legacy_v1": evaluate(legacy, att, leg), "current": evaluate(cur, att, leg)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=60)
    ap.add_argument("--json")
    ap.add_argument("--misses", action="store_true")
    args = ap.parse_args()
    res = run(args.threshold)

    rows = []
    for ds, d in res.items():
        for det in ("legacy_v1", "current"):
            r = d[det]
            rows.append([ds, det, f"{r['attacks']}/{r['legit']}", f"{r['asr']:.1f}%",
                         f"{r['fpr']:.1f}%", f"{r['precision']:.1f}%"])
    print(tabulate(rows, headers=["dataset", "detector", "atk/benign", "ASR", "FPR", "precision"], tablefmt="github"))

    for ds, d in res.items():
        print(f"\n{ds}: per-category detection (current)")
        cat_rows = [[c, f"{v['blocked']}/{v['total']}"] for c, v in d["current"]["by_category"].items()]
        print(tabulate(cat_rows, headers=["category", "blocked"], tablefmt="github"))
        if args.misses:
            for t in d["current"]["missed"]:
                print("  MISSED:", t)
            for t in d["current"]["false_positives"]:
                print("  FALSE POSITIVE:", t)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
