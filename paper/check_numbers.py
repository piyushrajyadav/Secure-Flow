"""
Consistency check: every headline number quoted in main.tex must match data/results/*.json.

    python paper/check_numbers.py

Exits non-zero (and lists the failures) if the manuscript and the result files disagree.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def R(name):
    with open(os.path.join(ROOT, "data", "results", name + ".json"), encoding="utf-8") as fh:
        return json.load(fh)



with open(os.path.join(ROOT, "paper", "main.tex"), encoding="utf-8") as fh:
    TEX = fh.read().replace(chr(92) + "%", "%")
P, A, I, L = R("paper_tables"), R("adaptive"), R("injecagent"), R("latency")
S2 = P["section2"]
fails = []


def expect(label, cond, tex_snippets=()):
    if not cond:
        fails.append(f"DATA MISMATCH: {label}")
    for s in tex_snippets:
        if s not in TEX:
            fails.append(f"NOT IN TEX: {s!r}  ({label})")


v1c, v2c = S2["v1 corpus (30/20)"], S2["v2 corpus (42/37)"]
v3c, pool = S2["v3 blind corpus (21/24)"], S2["pooled (93/81)"]
k = lambda d: (d["k"], d["n"])

expect("v1 on v1 corpus", k(v1c["v1 keyword"]["evaded"]) == (27, 30), ["27/30 = 90.0% [74.4, 96.5]"])
expect("v2 on v1 corpus", k(v1c["v2 rules"]["evaded"]) == (0, 30), ["0/30 = 0.0% [0.0, 11.4]"])
expect("v1 on v2 corpus", k(v2c["v1 keyword"]["evaded"]) == (40, 42), ["40/42 = 95.2% [84.2, 98.7]"])
expect("v2 on v2 corpus", k(v2c["v2 rules"]["evaded"]) == (0, 42), ["0/42 = 0.0% [0.0, 8.4]"])
expect("v1 on v3", k(v3c["v1 keyword"]["evaded"]) == (21, 21), ["21/21 = 100% [84.5, 100]"])
expect("v2 on v3", k(v3c["v2 rules"]["evaded"]) == (15, 21) and v3c["v2 rules"]["evaded"]["ci95"] == [50.0, 86.2],
       ["15/21 = 71.4% [50.0, 86.2]"])
expect("v2 FP on v3", k(v3c["v2 rules"]["false_positives"]) == (3, 24), ["3/24 = 12.5% [4.3, 31.0]"])
expect("pooled v1", k(pool["v1 keyword"]["evaded"]) == (88, 93), ["88/93 = 94.6% [88.0, 97.7]"])
expect("pooled v2", k(pool["v2 rules"]["evaded"]) == (15, 93) and pool["v2 rules"]["evaded"]["ci95"] == [10.0, 24.9],
       ["15/93 = 16.1% [10.0, 24.9]"])
expect("pooled v2 FP", k(pool["v2 rules"]["false_positives"]) == (3, 81), ["3/81 = 3.7% [1.3, 10.3]"])
expect("v3 strata", v3c["v2 rules"]["per_stratum_detected"] == {"paraphrase": "1/8", "indirect": "2/4", "encoded": "3/3",
       "multilingual": "0/4", "semantic": "0/2"})
ab = P["section3_ablation"]
expect("ablation", ab["full v2"]["detected"]["k"] == 78 and ab["no normalization"]["detected"]["k"] == 71)
loo = {r: 78 - v["detected"]["k"] for r, v in ab["leave_one_rule_out"].items()}
expect("leave-one-out", loo["data_exfiltration"] == 9 and loo["prompt_injection"] == 7 and loo["privilege_escalation"] == 7
       and loo["safety_bypass"] == 6 and loo["role_confusion"] == 4 and loo["exfil_channel"] == 4
       and loo["agent_directed_instruction"] == 2 and sum(1 for v in loo.values() if v == 1) == 6
       and sorted(r for r, v in loo.items() if v == 0) == ["defense_evasion", "delimiter_spoofing", "mode_switch", "propagation"])
sw = P["section2"]["v2_threshold_sweep"]["pooled (93/81)"]
expect("pooled sweep", sw["60"]["ber_pct"] == 16.1 and sw["65"]["ber_pct"] == 39.8 and sw["75"]["ber_pct"] == 50.5
       and sw["75"]["fpr_pct"] == 0.0 and sw["15"]["ber_pct"] == 16.1)
s1 = P["section1_v1_reproduction"]
expect("v1 reproduction", s1["score_distribution"] == {"0": 10, "30": 8, "35": 5, "40": 4, "65": 1, "70": 1, "75": 1}
       and s1["rule_fire_counts"] == {"prompt_injection": 6, "data_exfiltration": 5, "privilege_escalation": 5,
                                      "role_confusion": 6, "jailbreak_phrases": 1})

det = I["detection"]["attack"]
b = det["tool response, base"]; e = det["tool response, enhanced (override phrase)"]
expect("InjecAgent base", k(b["v2 rules (tau=60)"]) == (17, 1054) and k(b["v1 keyword (tau=60)"]) == (0, 1054), ["17 (1.6%) [1.0, 2.6]"])
expect("InjecAgent enhanced", k(e["v2 rules (tau=60)"]) == (1054, 1054) and k(e["v1 keyword (tau=60)"]) == (0, 1054))
pv = I["policy"]["variants"]
expect("policy", [pv[x]["attacker_goal_completed"]["k"] for x in pv] == [1054, 0, 1, 0, 0]
       and [pv[x]["any_attacker_step_authorized"]["k"] for x in pv] == [1054, 1, 74, 8, 1])
expect("policy structure", I["policy"]["attacks_whose_tools_all_share_users_toolkit"]["k"] == 4)

t = A["targets"]
expect("adaptive", k(t["v2 rules (tau=60)"]["evaded_of_initially_blocked"]) == (70, 78)
       and t["v2 rules (tau=60)"]["median_queries_when_rewrite_needed"] == 68
       and k(t["v1 keyword (tau=60)"]["evaded_of_initially_blocked"]) == (5, 5)
       and t["v1 keyword (tau=60)"]["median_queries_when_rewrite_needed"] == 2
       and k(t["v2 rules, untrusted (tau=40)"]["evaded_of_initially_blocked"]) == (69, 78)
       and t["v2 rules, untrusted (tau=40)"]["median_queries_when_rewrite_needed"] == 80
       and t["v2 rules (tau=60)"]["never_evaded_text_only"] == 8 and t["v2 rules, untrusted (tau=40)"]["never_evaded_text_only"] == 9,
       ["70/78 = 89.7%", "69/78 = 88.5%"])

lat = L["results"]
row = lambda name, med: abs(lat[name]["median_ms"] - med) < 1e-9
expect("latency", row("v1 scoring, short (74 chars)", 0.0189) and row("v2 scoring, short (74 chars)", 0.692),
       ["0.0189", "0.692", "26.26"])
expect("latency 3KB", round(lat["v2 scoring, 3 KB"]["median_ms"], 2) == 26.26)
for name in ("provenance",):
    for d, n in ((P, "paper_tables"), (A, "adaptive"), (I, "injecagent"), (L, "latency")):
        expect(f"{n} stamped clean", d["provenance"]["working_tree_clean"] is True)

if fails:
    print("\n".join(fails))
    sys.exit(1)
print("OK: manuscript numbers match data/results/*.json")
