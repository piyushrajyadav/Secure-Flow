"""
External validation on InjecAgent (Zhan et al., 2024): 1,054 indirect-injection cases against
tool-integrated agents (510 direct-harm, 544 data-stealing), each with an "enhanced" variant
that prepends an override phrase.

Two things are measured, both WITHOUT a language model:

A. TEXT-LEVEL DETECTION. Does the scorer flag the tool response that carries the injection?
   Benign counterpart: the same tool response with the injection removed, plus the 17 user
   instructions. (Not the InjecAgent attack-success metric: that needs a model in the loop.)

B. ASSUME-COMPROMISE POLICY EVALUATION. Suppose the injection FULLY succeeds in steering the
   agent (the worst case, i.e. detection failed). Does least-privilege tool authorization still
   stop the attacker's tool calls? Variants P0-P4 below. Reported as "attacker goal completed" =
   every attacker tool call in the case is authorized.

Rules were frozen (git 053d8a6) before this script was first run. Nothing was tuned on it.

    python -m experiments.external.fetch_injecagent
    python -m experiments.external.eval_injecagent
"""
import json
import os
import re
from collections import Counter, defaultdict

from experiments.legacy_v1 import LegacyScorer
from experiments.provenance import dump
from experiments.stats import rate
from secureflow import (AgentRegistry, MessageSigner, Sensitivity, ToolPolicy, ToolSpec, Trust)
from secureflow.scorer import RiskScorer

D = os.path.join("data", "external", "injecagent")
OUT = os.path.join("data", "results", "injecagent.json")
PLACEHOLDER = "<Attacker Instruction>"

# --- tool sensitivity heuristic, declared before any result was computed -------------------
_READ = r"(Get|Search|List|Read|View|Find|Check|Fetch|Lookup|Download|Query|Browse|Track|Show|Retrieve|Locate|Look)"
_DESTR = r"(Delete|Remove|Cancel|Revoke|Erase|Disable|Terminate|Clear|Wipe)"
_EXT = r"(Send|Share|Post|Publish|Transfer|Pay|Invite|Upload|Submit|Dispatch|Place|Order|Buy|Sell|Trade|Deposit|Withdraw|Message|Call|Tweet|Forward|Email)"


def sensitivity_of(short_name: str, full_name: str) -> Sensitivity:
    if full_name == "TerminalExecute":
        return Sensitivity.DESTRUCTIVE            # arbitrary command execution
    if re.match(_READ, short_name):
        return Sensitivity.READ
    if re.match(_DESTR, short_name):
        return Sensitivity.DESTRUCTIVE
    if re.match(_EXT, short_name):
        return Sensitivity.EXTERNAL
    return Sensitivity.WRITE


def load():
    cases = {}
    for key in ("dh_base", "dh_enhanced", "ds_base", "ds_enhanced"):
        with open(os.path.join(D, f"test_cases_{key}.json"), encoding="utf-8") as f:
            cases[key] = json.load(f)
    with open(os.path.join(D, "user_cases.jsonl"), encoding="utf-8") as f:
        users = [json.loads(l) for l in f if l.strip()]
    with open(os.path.join(D, "tools.json"), encoding="utf-8") as f:
        toolkits = json.load(f)
    return cases, users, toolkits


def detection(cases, users):
    legacy = LegacyScorer(60).is_blocked
    scorer = RiskScorer(threshold=60)
    detectors = {
        "v1 keyword (tau=60)": lambda t: legacy(t),
        "v2 rules (tau=60)": lambda t: scorer.score(t, threshold=60).is_blocked,
        "v2 rules, untrusted source (tau=40)": lambda t: scorer.score(t, threshold=40).is_blocked,
    }
    res = {"attack": {}, "benign": {}}
    sets = {
        "attacker instruction alone (base)": [c["Attacker Instruction"] for k in ("dh_base", "ds_base") for c in cases[k]],
        "tool response, base": [c["Tool Response"] for k in ("dh_base", "ds_base") for c in cases[k]],
        "tool response, enhanced (override phrase)": [c["Tool Response"] for k in ("dh_enhanced", "ds_enhanced") for c in cases[k]],
    }
    for sname, texts in sets.items():
        res["attack"][sname] = {dn: rate(sum(1 for t in texts if fn(t)), len(texts)) for dn, fn in detectors.items()}

    benign_responses = sorted({c["Tool Response Template"].replace(PLACEHOLDER, "") for k in ("dh_base", "ds_base") for c in cases[k]})
    benign_users = sorted({u["User Instruction"] for u in users})
    for bname, texts in {"clean tool responses (injection removed)": benign_responses, "user instructions": benign_users}.items():
        res["benign"][bname] = {dn: rate(sum(1 for t in texts if fn(t)), len(texts)) for dn, fn in detectors.items()}

    # per attack type (enhanced-free base tool responses)
    by_type = defaultdict(list)
    for k in ("dh_base", "ds_base"):
        for c in cases[k]:
            by_type[c["Attack Type"]].append(c["Tool Response"])
    res["attack_by_type_base_tool_response"] = {
        t: {dn: rate(sum(1 for x in texts if fn(x)), len(texts)) for dn, fn in detectors.items()} for t, texts in by_type.items()}
    return res


def policy_eval(cases, toolkits):
    """Assume the agent is fully hijacked; does least-privilege authorization stop the tool calls?"""
    kit_of, short_of, kit_tools = {}, {}, defaultdict(set)
    for kit in toolkits:
        for t in kit["tools"]:
            full = kit["toolkit"] + t["name"]
            kit_of[full], short_of[full] = kit["toolkit"], t["name"]
            kit_tools[kit["toolkit"]].add(full)

    registry = AgentRegistry()
    registry.register("agent")
    signer = MessageSigner(registry)
    # Context of the hijacked call = the tool response that carried the injection => tainted.
    tainted = signer.from_untrusted_source("agent", "agent", "tool response", "tool:untrusted")
    trusted = signer.sign("agent", "agent", "user instruction", Trust.USER)

    def build(grants, taint_gating):
        pol = ToolPolicy(max_untrusted_sensitivity=Sensitivity.READ if taint_gating else Sensitivity.DESTRUCTIVE)
        for full in kit_of:
            pol.register_tool(ToolSpec(full, sensitivity_of(short_of[full], full), allow_extra_args=True))
        pol.grant("agent", grants)
        return pol

    variants = {
        "P0 no policy": None,
        "P1 task-scoped grants (user tool only)": ("task", False),
        "P2 toolkit-scoped grants": ("kit", False),
        "P3 toolkit-scoped + taint gating": ("kit", True),
        "P4 task-scoped + taint gating": ("task", True),
    }
    allc = [c for k in ("dh_base", "ds_base") for c in cases[k]]
    out = {"n_cases": len(allc), "variants": {}}
    for vname, spec in variants.items():
        completed = any_step = 0
        by_type = Counter()
        user_ok = 0
        for c in allc:
            tools = c["Attacker Tools"]
            if spec is None:
                completed += 1; any_step += 1; by_type[c["Attack Type"]] += 1
                user_ok += 1
                continue
            scope, gating = spec
            ut = c["User Tool"]
            grants = {ut} if scope == "task" else kit_tools[kit_of[ut]]
            pol = build(grants, gating)
            decisions = [pol.authorize("agent", t, {}, context=tainted).allowed for t in tools]
            if all(decisions):
                completed += 1; by_type[c["Attack Type"]] += 1
            if any(decisions):
                any_step += 1
            user_ok += pol.authorize("agent", ut, {}, context=trusted).allowed
        out["variants"][vname] = {
            "attacker_goal_completed": rate(completed, len(allc)),
            "any_attacker_step_authorized": rate(any_step, len(allc)),
            "legit_user_tool_allowed": rate(user_ok, len(allc)),
            "completed_by_type": dict(by_type),
        }
    # How many attacker tool calls land in the same toolkit as the user's tool (why P2 leaks)?
    same_kit = sum(1 for c in allc if all(kit_of[t] == kit_of[c["User Tool"]] for t in c["Attacker Tools"]))
    out["attacks_whose_tools_all_share_users_toolkit"] = rate(same_kit, len(allc))
    return out


def main():
    cases, users, toolkits = load()
    result = {
        "dataset": "InjecAgent", "commit": "f19c9f2c79a41046eb13c03c51a24c567a8ffa07", "license": "MIT",
        "rules_frozen_at": "053d8a63a8f668e080ac1a5c15c6e57577760c86",
        "detection": detection(cases, users),
        "policy": policy_eval(cases, toolkits),
    }
    dump(OUT, result)
    print(json.dumps(result["detection"]["attack"], indent=1)[:3000])
    print(json.dumps(result["detection"]["benign"], indent=1)[:2000])
    for v, r in result["policy"]["variants"].items():
        print(f"{v:42} goal completed {r['attacker_goal_completed']['k']:>4}/{r['attacker_goal_completed']['n']}  any step {r['any_attacker_step_authorized']['k']:>4}  user tool ok {r['legit_user_tool_allowed']['k']}")
    print("attacks fully inside user's toolkit:", result["policy"]["attacks_whose_tools_all_share_users_toolkit"])


if __name__ == "__main__":
    main()
