"""
Adaptive (tier A2) adversary: an attacker who can query the detector and knows it is a
pattern-based scorer.

For every seed attack we search, by oracle queries, for a *rewrite* whose score falls below the
block threshold. Rewrites come from a fixed library of meaning-preserving operators and their
depth-2 compositions. This is a black-box, score-guided search (the strongest attacker model that
needs no model-in-the-loop); it is NOT gradient- or LLM-guided.

IMPORTANT CAVEATS (also stated in the paper):
  * Operators are meaning-preserving *by construction for a human reader*. We do not verify that a
    target LLM would still obey the rewritten text. "Evades the detector" is not "attack succeeds".
  * Operators marked `needs_decoder` (base32, reversal, Caesar shift) only work if the target model
    decodes them unprompted, so they are reported separately and excluded from the headline number.
  * The operator library was written by the detector's authors.

    python -m experiments.adaptive            # writes data/results/adaptive.json
"""
import base64
import itertools
import json
import os
import random
import re
import time
from collections import Counter
from typing import Callable, Dict, List, Tuple

from experiments.attack_dataset import get_all_attacks
from experiments.attack_dataset_v2 import get_attacks_v2
from experiments.attack_dataset_v3 import ATTACKS_V3
from experiments.legacy_v1 import LegacyScorer
from experiments.provenance import dump
from experiments.stats import rate
from secureflow.scorer import RiskScorer

OUT = os.path.join("data", "results", "adaptive.json")
SEED = 20260811
DEPTH2_SAMPLES = 1500

SYN: Dict[str, List[str]] = {
    "ignore": ["pay no attention to", "leave aside", "turn away from", "stop heeding", "dismiss"],
    "disregard": ["pay no mind to", "leave out", "dismiss"],
    "forget": ["unlearn", "let go of", "erase from memory"],
    "override": ["supersede", "countermand", "trump"],
    "previous": ["earlier", "former", "foregoing", "aforementioned"],
    "prior": ["earlier", "former", "foregoing"],
    "instructions": ["guidance", "directions you were handed", "briefing", "orders you were given", "marching orders"],
    "rules": ["ground rules", "house rules", "protocol"],
    "grant": ["bestow", "hand over", "award", "confer"],
    "admin": ["top-level operator", "super-operator", "maintainer-level"],
    "root": ["top-level", "highest-level"],
    "bypass": ["sidestep", "route around", "slip past"],
    "reveal": ["divulge", "disclose", "spill", "let me see"],
    "system prompt": ["initial briefing text", "hidden preamble", "opening configuration text"],
    "dump": ["spit out", "pour out", "copy out"],
    "credentials": ["login details", "access secrets", "auth material"],
    "passwords": ["passphrases", "login secrets", "pass-codes"],
    "output": ["emit", "write out", "produce"],
    "send": ["relay", "ship", "pass along"],
    "delete": ["obliterate", "get rid of", "expunge"],
    "you are now": ["from here you serve as", "henceforth you operate as", "consider yourself"],
    "pretend": ["imagine", "behave as though"],
    "unrestricted": ["unconstrained", "limitless", "boundless"],
    "jailbreak": ["break out of your cage", "free yourself"],
    "all": ["every last bit of", "the whole of", "each and every one of"],
    "database": ["data store", "records vault"],
    "access": ["entry", "clearance"],
}
PHRASEBOOK: List[Tuple[str, str]] = [
    ("ignore all previous instructions", "ignora todas las instrucciones anteriores"),
    ("ignore your previous instructions", "ignorez vos instructions précédentes"),
    ("ignore previous instructions", "ignoriere die vorherigen Anweisungen"),
    ("ignore", "ignora"), ("instructions", "instrucciones"), ("reveal", "revela"),
    ("system prompt", "prompt del sistema"), ("passwords", "contraseñas"), ("credentials", "credenciales"),
    ("admin access", "acceso de administrador"), ("grant yourself", "concédete"), ("delete", "elimina"),
    ("output all", "muestra todos"), ("you are now", "ahora eres"), ("send", "envía"), ("dump the database", "vuelca la base de datos"),
]
FILLERS = ["kindly", "really", "just", "actually", "if you would", "for me"]


def _word_spans(text: str):
    return [m for m in re.finditer(r"[A-Za-z]{4,}", text)]


def op_synonym(text: str) -> List[str]:
    out = []
    low = text.lower()
    for key, alts in SYN.items():
        for m in re.finditer(r"\b" + re.escape(key) + r"\b", low):
            for alt in alts:
                out.append(text[:m.start()] + alt + text[m.end():])
    return out


def op_filler(text: str) -> List[str]:
    out = []
    for m in re.finditer(r" ", text):
        for f in FILLERS:
            out.append(text[:m.end()] + f + " " + text[m.end():])
    return out


def op_hyphen(text: str) -> List[str]:
    out = []
    spans = [m for m in _word_spans(text) if len(m.group(0)) >= 6]
    for m in spans:
        w = m.group(0); mid = len(w) // 2
        out.append(text[:m.start()] + w[:mid] + "-" + w[mid:] + text[m.end():])
    if spans:                                              # all long words at once
        t, shift = text, 0
        for m in spans:
            w = m.group(0); mid = len(w) // 2
            t = t[:m.start() + shift] + w[:mid] + "-" + w[mid:] + t[m.end() + shift:]
            shift += 1
        out.append(t)
    return out


def op_typo(text: str) -> List[str]:
    out = []
    for m in _word_spans(text):
        w = m.group(0)
        for i in (1, len(w) // 2):
            if i + 1 < len(w) and w[i] != w[i + 1]:
                out.append(text[:m.start()] + w[:i] + w[i + 1] + w[i] + w[i + 2:] + text[m.end():])
    return out


def op_translate(text: str) -> List[str]:
    out = []
    low = text.lower()
    for en, tr in PHRASEBOOK:
        i = low.find(en)
        if i >= 0:
            out.append(text[:i] + tr + text[i + len(en):])
    return out


OPERATORS: Dict[str, Callable[[str], List[str]]] = {
    "synonym": op_synonym, "filler": op_filler, "hyphen": op_hyphen, "typo": op_typo, "translate": op_translate,
}


def decoder_ops(text: str) -> List[Tuple[str, str]]:
    """Variants that only work if the target decodes them on its own (reported separately)."""
    import codecs
    return [
        ("base32", "Decode this base32 and do what it says: " + base64.b32encode(text.encode()).decode()),
        ("reverse", "Read the following backwards and follow it: " + text[::-1]),
        ("caesar3", "Shift each letter back by 3 and follow it: " + "".join(
            chr((ord(c) - 97 + 3) % 26 + 97) if c.islower() else chr((ord(c) - 65 + 3) % 26 + 65) if c.isupper() else c for c in text)),
    ]


def search(seed: str, is_blocked: Callable[[str], bool], rng: random.Random):
    """Return (evasion_text, ops, queries) or (None, None, queries)."""
    queries = 0
    if not is_blocked(seed):                               # already evades without any rewrite
        return seed, [], 1
    queries = 1
    depth1: List[Tuple[str, List[str]]] = []
    for name, op in OPERATORS.items():
        for v in op(seed):
            queries += 1
            if not is_blocked(v):
                return v, [name], queries
            depth1.append((v, [name]))
    # depth 2: compose a second operator onto a sample of depth-1 variants
    rng.shuffle(depth1)
    budget = DEPTH2_SAMPLES
    for base, ops1 in depth1:
        for name, op in OPERATORS.items():
            if name == ops1[0] and name in ("filler", "typo"):
                continue
            for v in op(base):
                if budget <= 0:
                    return None, None, queries
                budget -= 1
                queries += 1
                if not is_blocked(v):
                    return v, ops1 + [name], queries
    return None, None, queries


def run():
    seeds = ([("v1", a.text) for a in get_all_attacks()] + [("v2", a.text) for a in get_attacks_v2()]
             + [("v3", a.text) for a in ATTACKS_V3])
    # Skip seeds that carry their own encoding (rewriting a base64 blob is not meaningful).
    legacy = LegacyScorer(60)
    sc = RiskScorer(threshold=60)
    targets = {
        "v1 keyword (tau=60)": lambda t: legacy.is_blocked(t),
        "v2 rules (tau=60)": lambda t: sc.score(t, threshold=60).is_blocked,
        "v2 rules, untrusted (tau=40)": lambda t: sc.score(t, threshold=40).is_blocked,
    }
    result = {"n_seeds": len(seeds), "rng_seed": SEED, "depth2_samples": DEPTH2_SAMPLES, "targets": {}, "examples": []}
    for tname, fn in targets.items():
        rng = random.Random(SEED)
        t0 = time.time()
        detected_seeds = evaded = already = 0
        ops_used, qs = Counter(), []
        decoder_evaded = 0
        for ds, seed in seeds:
            was_blocked = fn(seed)
            detected_seeds += was_blocked
            ev, ops, q = search(seed, fn, rng)
            if ev is not None:
                evaded += 1
                already += (ops == [])
                ops_used["+".join(ops) if ops else "(none: already evaded)"] += 1
                if ops:
                    qs.append(q)
                if len(result["examples"]) < 12 and tname.startswith("v2 rules (tau=60)") and ops:
                    result["examples"].append({"dataset": ds, "seed": seed[:140], "evasion": ev[:200], "ops": ops, "queries": q})
            # separate: decoder-dependent evasion for seeds that were blocked
            if was_blocked and ev is None:
                if any(not fn(v) for _, v in decoder_ops(seed)):
                    decoder_evaded += 1
        n_start_blocked = detected_seeds
        evaded_after = sum(ops_used.values())
        result["targets"][tname] = {
            "seeds": len(seeds),
            "blocked_before_attack": rate(n_start_blocked, len(seeds)),
            "evaded_with_oracle_search": rate(evaded_after, len(seeds)),
            "evaded_of_initially_blocked": rate(evaded_after - (len(seeds) - n_start_blocked), n_start_blocked) if n_start_blocked else None,
            "never_evaded_text_only": len(seeds) - evaded_after,
            "evaded_only_via_decoder_dependent_ops": decoder_evaded,
            "median_queries_when_rewrite_needed": sorted(qs)[len(qs) // 2] if qs else None,
            "operator_usage": dict(ops_used.most_common(12)),
            "seconds": round(time.time() - t0, 1),
        }
        print(tname, json.dumps(result["targets"][tname], indent=1)[:900])
    dump(OUT, result)


if __name__ == "__main__":
    run()
