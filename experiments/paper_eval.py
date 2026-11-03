"""
Produces every detection table in the paper from the released scorers and corpora.
Deterministic: no model, no network, no randomness.

    python -m experiments.paper_eval            # writes data/results/paper_tables.json

Sections
  1. v1 reproduction on the original 30-attack / 20-benign corpus (checks the numbers in the
     original manuscript: score distribution, rule fire counts, threshold sweep, per-stratum).
  2. v2 on the same corpus, plus the v2 and v3 corpora, with Wilson 95% intervals.
  3. Ablations of the v2 pipeline (no normalization; leave-one-rule-out; no taint threshold).
  4. Benign false-positive analysis by stratum (hard negatives reported separately).
"""
import json
import os
from collections import Counter, defaultdict

import secureflow.scorer as scorer_mod
from experiments.attack_dataset import get_all_attacks, get_all_legitimate
from experiments.attack_dataset_v2 import get_attacks_v2, get_legit_v2
from experiments.attack_dataset_v3 import ATTACKS_V3, LEGIT_V3
from experiments.legacy_v1 import LEGACY_RULES
from experiments.provenance import dump
from experiments.stats import rate
from secureflow.normalize import Views
from secureflow.scorer import RiskScorer

OUT = os.path.join("data", "results", "paper_tables.json")
THRESHOLDS = list(range(5, 105, 5)) + [31, 36]
THRESHOLDS = sorted(set(THRESHOLDS))


def v1_score(text: str):
    """Exactly the original additive scorer (frozen copy)."""
    low, total, fired = text.lower(), 0, []
    names = ["prompt_injection", "privilege_escalation", "role_confusion", "data_exfiltration", "jailbreak_phrases"]
    for (w, pats), name in zip(LEGACY_RULES, names):
        if any(p in low for p in pats):
            total += w
            fired.append(name)
    if len(text) > 2000:
        total += 15
    return min(total, 100), fired


def section1():
    atk, ben = get_all_attacks(), get_all_legitimate()
    scores = [v1_score(a.text) for a in atk]
    dist = Counter(s for s, _ in scores)
    fire = Counter(n for _, f in scores for n in f)
    sweep = {}
    for t in range(5, 85):
        sup = sum(1 for s, _ in scores if s >= t)
        ben_sup = sum(1 for b in ben if v1_score(b.text)[0] >= t)
        sweep[t] = {"suppressed": sup, "ber_pct": round(100 * (30 - sup) / 30, 1), "benign_suppressed": ben_sup}
    cats = defaultdict(lambda: {30: 0, 60: 0, "n": 0})
    for a, (s, _) in zip(atk, scores):
        cats[a.category]["n"] += 1
        cats[a.category][30] += s >= 30
        cats[a.category][60] += s >= 60
    return {
        "score_distribution": {str(k): v for k, v in sorted(dist.items())},
        "rule_fire_counts": dict(fire),
        "benign_scores": dict(Counter(v1_score(b.text)[0] for b in ben)),
        "sweep": sweep,
        "per_stratum": {c: {"tau30": v[30], "tau60": v[60], "n": v["n"]} for c, v in cats.items()},
    }


def eval_set(is_blocked, attacks, benign):
    by_cat = defaultdict(lambda: [0, 0])
    for a in attacks:
        by_cat[a.category][1] += 1
        by_cat[a.category][0] += is_blocked(a.text)
    caught = sum(v[0] for v in by_cat.values())
    fp = [b for b in benign if is_blocked(b.text)]
    hard = [b for b in benign if b.category == "hard_negative"]
    return {
        "detected": rate(caught, len(attacks)),
        "evaded": rate(len(attacks) - caught, len(attacks)),
        "false_positives": rate(len(fp), len(benign)),
        "hard_negative_false_positives": rate(sum(1 for b in hard if is_blocked(b.text)), len(hard)) if hard else None,
        "per_stratum_detected": {c: f"{b}/{n}" for c, (b, n) in by_cat.items()},
        "false_positive_examples": [b.text[:100] for b in fp],
    }


DATASETS = {
    "v1 corpus (30/20)": (get_all_attacks, get_all_legitimate),
    "v2 corpus (42/37)": (get_attacks_v2, get_legit_v2),
    "v3 blind corpus (21/24)": (lambda: ATTACKS_V3, lambda: LEGIT_V3),
}


def pooled():
    atk = get_all_attacks() + get_attacks_v2() + ATTACKS_V3
    ben = get_all_legitimate() + get_legit_v2() + LEGIT_V3
    return atk, ben


def section2():
    out = {}
    v2 = RiskScorer(threshold=60)
    from experiments.legacy_v1 import LegacyScorer
    leg = LegacyScorer(60)
    detectors = {"v1 keyword": lambda t: leg.is_blocked(t), "v2 rules": lambda t: v2.score(t, threshold=60).is_blocked}
    for dname, (fa, fb) in DATASETS.items():
        out[dname] = {dn: eval_set(fn, fa(), fb()) for dn, fn in detectors.items()}
    atk, ben = pooled()
    out["pooled (93/81)"] = {dn: eval_set(fn, atk, ben) for dn, fn in detectors.items()}
    # v2 threshold sweep on the original corpus and on the pooled corpus
    for label, (a, b) in {"v1 corpus (30/20)": (get_all_attacks(), get_all_legitimate()), "pooled (93/81)": (atk, ben)}.items():
        sweep = {}
        a_scores = [v2.score(x.text).score for x in a]
        b_scores = [v2.score(x.text).score for x in b]
        for t in THRESHOLDS:
            sweep[t] = {"ber_pct": round(100 * sum(1 for s in a_scores if s < t) / len(a), 1),
                        "fpr_pct": round(100 * sum(1 for s in b_scores if s >= t) / len(b), 1)}
        out.setdefault("v2_threshold_sweep", {})[label] = sweep
    return out


def section3():
    atk, ben = pooled()
    base = RiskScorer(threshold=60)

    def stats(sc, t=60):
        det = sum(1 for a in atk if sc.score(a.text, threshold=t).is_blocked)
        fp = sum(1 for b in ben if sc.score(b.text, threshold=t).is_blocked)
        return {"detected": rate(det, len(atk)), "false_positives": rate(fp, len(ben))}

    res = {"full v2": stats(base)}
    # (a) no normalization: scan only the lowercased raw text, as v1 did
    orig = scorer_mod.build_views

    def raw_views(message):
        return Views(original=message, texts=[message.lower()], flags=[])
    scorer_mod.build_views = raw_views
    try:
        res["no normalization"] = stats(RiskScorer(threshold=60))
    finally:
        scorer_mod.build_views = orig
    # (b) leave-one-rule-out
    loo = {}
    for r in list(base.rules):
        sc = RiskScorer(threshold=60, rules=[x for x in base.rules if x.name != r.name])
        loo[r.name] = stats(sc)
    res["leave_one_rule_out"] = loo
    # (c) threshold used for tainted/untrusted sources
    res["untrusted threshold 40"] = stats(base, 40)
    # (d) no decay in score combination (plain sum)
    return res


def main():
    result = {"section1_v1_reproduction": section1(), "section2": section2(), "section3_ablation": section3()}
    dump(OUT, result)
    s1 = result["section1_v1_reproduction"]
    print("v1 score distribution:", s1["score_distribution"])
    print("v1 rule fire counts  :", s1["rule_fire_counts"])
    print("v1 sweep tau=30/60   :", s1["sweep"][30], s1["sweep"][60])
    print("v1 per stratum       :", s1["per_stratum"])
    for d, v in result["section2"].items():
        if d.startswith("v2_threshold"):
            continue
        for dn, r in v.items():
            print(f"{d:26} {dn:11} evaded {r['evaded']['k']}/{r['evaded']['n']} ({r['evaded']['pct']}%) FP {r['false_positives']['k']}/{r['false_positives']['n']} hardneg-FP {r['hard_negative_false_positives'] and (r['hard_negative_false_positives']['k'], r['hard_negative_false_positives']['n'])}")
    for k, v in result["section3_ablation"].items():
        if k != "leave_one_rule_out":
            print(f"ablation {k:22} det {v['detected']['k']}/{v['detected']['n']} FP {v['false_positives']['k']}/{v['false_positives']['n']}")
    base = result["section3_ablation"]["full v2"]["detected"]["k"]
    print("leave-one-rule-out (detected drop):", {k: base - v["detected"]["k"] for k, v in result["section3_ablation"]["leave_one_rule_out"].items() if base - v["detected"]["k"]})


if __name__ == "__main__":
    main()
