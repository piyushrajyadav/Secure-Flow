# 🛡️ SecureFlow v2: Security Middleware for Multi-Agent LLM Systems
![Downloads](https://img.shields.io/pypi/dm/secureflow-ai)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SecureFlow sits on the edges between agents (LangGraph, LangChain, or your own loop) and treats
**every inter-agent message as untrusted input**. v2 is built around one lesson from the last
year of agent-security work: *pattern matching alone cannot stop prompt injection*. Some
paraphrased or non-English attack will always get through, so v2 adds controls that limit the
damage when it does.

| Layer | What it does | Addresses |
|---|---|---|
| **1. Normalization + rules** | Decodes base64/hex/URL/ROT13, strips zero-width & Unicode-tag smuggling, folds homoglyphs/full-width/leetspeak, then scans 17 rule families | OWASP ASI01 goal hijack, LLM01 |
| **2. Authenticated messages** | HMAC-signed `Envelope`s bound to sender, receiver, nonce, timestamp; rejects spoofing, tampering, replay, misdelivery | ASI07 insecure inter-agent comms |
| **3. Taint tracking** | Content derived from a web page / e-mail / tool result stays `UNTRUSTED` as it flows through "trusted" agents; screened harder downstream | indirect injection, CaMeL/FIDES-style provenance |
| **4. Least-privilege tool policy** | Default-deny per-agent tool grants, argument validators (domain allow-list, path jail), human approval for sensitive actions when context is tainted, injection scan of tool arguments | ASI02 tool misuse, LLM06 excessive agency |
| **5. Semantic judge (optional)** | Plug in any LLM/classifier for paraphrase & non-English. Can only *raise* a score, never lower it | what regexes can't see |
| **6. Tamper-evident audit log** | SHA-256 hash-chained JSONL, optional redaction, `verify_chain()` | forensics |
| **7. Spotlighting** | `SecureFlowMiddleware.spotlight()` wraps untrusted text in an unforgeable boundary before it reaches a prompt | defence-in-depth |

## 📦 Install
```bash
pip install secureflow-ai          # core has no heavy dependencies
```

## ⚡ Quick start (v1 API, unchanged)
```python
from secureflow import SecureFlowMiddleware

firewall = SecureFlowMiddleware(threshold=60)
if firewall.intercept("agent_A", "agent_B", message) is None:
    ...  # blocked
```

## 🔐 v2: signed, taint-aware messages + tool policy
```python
from secureflow import (AgentRegistry, MessageSigner, SecureFlowMiddleware,
                        ToolPolicy, ToolSpec, Sensitivity, Trust)
from secureflow.policy import allow_domains

registry = AgentRegistry()
for a in ("orchestrator", "researcher", "writer"):
    registry.register(a)
signer = MessageSigner(registry)

policy = (ToolPolicy()
          .register_tool(ToolSpec("post_report", Sensitivity.EXTERNAL,
                                  {"url": allow_domains("reports.internal.example")}, {"url"}))
          .grant("writer", ["post_report"]))

firewall = SecureFlowMiddleware(signer=signer, policy=policy)

# The researcher read a web page -> everything derived from it is tainted.
page    = signer.from_untrusted_source("researcher", "researcher", html, source="web:news.example")
summary = signer.derive("researcher", "writer", summary_text, parents=[page])

if firewall.intercept_envelope(summary, expected_receiver="writer"):
    # The writer wants to act. Tainted context + EXTERNAL tool => needs human approval.
    decision = firewall.authorize_tool_call("writer", "post_report",
                                            {"url": "https://reports.internal.example/q3"},
                                            context=summary)
    if decision.requires_approval:
        ...  # ask a human, then call again with approved=True
```
Run the full walkthrough (no LLM needed): `python -m examples.offline_demo`

## 🧠 Optional semantic judge
```python
import ollama
from secureflow import LLMJudge, SecureFlowMiddleware

ask = lambda p: ollama.chat(model="llama3.1", messages=[{"role": "user", "content": p}])["message"]["content"]
firewall = SecureFlowMiddleware(judge=LLMJudge(ask), judge_scope="untrusted")   # or "gray" / "all"
```
The judge runs only where it matters (`gray` = near-threshold, `untrusted` = tainted content,
`all` = everything), is boundary-wrapped against being injected itself, and can never lower a
score. If it errors, the default is fail-open (regex verdict stands); use `judge_failure="closed"` to block.
> The LLM judge is covered by unit tests with stub models; it has **not** been benchmarked against
> a real model in this repo. Measure it on your own traffic before relying on it.

## 📊 Measured results (reproduce with `python -m experiments.evaluate`)

Attack Success Rate (ASR, lower is better) and False Positive Rate (FPR) at threshold 60:

| Dataset | v1 keyword detector | v2 rules layer |
|---|---|---|
| v1 set, 30 attacks / 20 benign (v2 was tuned on this) | ASR 90.0%, FPR 0% | ASR 0%, FPR 0% |
| v2 set, 42 / 37 incl. hard negatives (**its misses were used to tune** → no longer held-out) | ASR 95.2%, FPR 0% | ASR 0%, FPR 0% |
| **v3 blind set, 21 / 24** (written after tuning, never tuned on) | ASR 100%, FPR 0% | **ASR 71.4%, FPR 12.5%** |

Read the last row as the honest one. On the blind set the rules layer catches obfuscation/encoding
tricks (3/3) and some indirect injection, but **misses most paraphrases (1/8 caught), all
non-English attacks (0/4) and purely semantic social engineering (0/2)**, and has false positives
on security-awareness text ("explain what a DAN jailbreak is") and on legitimate role assignment.
These are the cases the signed/taint-aware layers, the tool policy and the optional judge exist for.
All datasets are small, hand-written, English-centric and authored by the detector's author, so treat
them as regression tests rather than a security guarantee.

**Latency** (single thread, pure Python, rules layer): ~1 ms for short messages, ~9 ms per KB of text,
~25 ms for a 2 KB+ message with encoded blobs (v1 was ~0.01–0.1 ms). End-to-end middleware overhead
including a log write measured ~4 ms/message. Negligible next to an LLM call, but not "real-time at
0.2 ms" as v1's README claimed.

## 🔬 Research artifact
The accompanying paper is in [`paper/`](paper/) (`main.tex`, `main.pdf`). Every number in it is produced by
released code and data, and `python paper/check_numbers.py` verifies that the manuscript matches `data/results/`.

```bash
python -m experiments.run_all           # reproduce all results (~7 min, no model/GPU; needs network once for InjecAgent)
python -m experiments.run_all --offline # skip the external benchmark
python paper/check_numbers.py           # manuscript <-> results consistency
```
Headline results (details, intervals and caveats in the paper): on the **independent InjecAgent benchmark** the rules
layer flags only **1.6 %** of plain-request injections (100 % on the "enhanced" variant only because every case carries
one identical override phrase); an **oracle-guided adaptive attacker** evades v2 on **89.7 %** of the attacks it
initially detects (median 68 queries; v1: 2); but under an **assumed-compromise** evaluation, least-privilege tool
policy with taint gating completes the attacker's goal in **0 / 1054** cases (vs 1054 / 1054 without it, a result that is
partly structural to the benchmark; see the paper). Test data: [`data/`](data/).

Scoring cost is linear in message length (~9-11 ms/KB measured), so messages over 32,768 characters are **not scanned and
are blocked** by default (`RiskScorer(max_scan_chars=..., oversize_action="block"|"window"|"scan_all")`).

## 🧭 What this does *not* do
- It does not make prompt injection impossible. Treat detection as a speed bump and the **tool policy + human approval** as the actual boundary.
- HMAC signing uses shared secrets (fine inside one process / trust domain). Across trust domains use asymmetric signatures.
- Rules are English-centric. Add a judge or a multilingual classifier for other languages.
- Taint tracking only works if your orchestration code actually uses `from_untrusted_source` / `derive`. SecureFlow can't see data flows it isn't told about.
- The hash-chained log detects tampering; it does not prevent it. Ship logs to write-once storage.

## 🚀 Run
```bash
pip install -r requirements.txt         # Python 3.9-3.13 recommended for the LangGraph demo
python -m examples.offline_demo         # architecture walkthrough, no LLM
python -m experiments.evaluate --misses # before/after detection numbers
python -m experiments.attack_sim        # original ASR simulation
python -m pytest tests                  # 74 tests
python dashboard/app.py                 # Flask dashboard
python demo.py                          # LangGraph + Ollama demo (needs Ollama running)
```
Docker: `docker compose up -d --build`.

## 🔄 Migrating from v1
- `SecureFlowMiddleware.intercept()` and `RiskScorer.score()` keep their signatures.
- **Behaviour change:** a single clear injection now scores ≥ 60 and is blocked by default (v1 scored it 35 and let it through, which is why v1 measured ~90% ASR).
- `ScoreResult` gained `evidence`, `flags`, `contributions`. `Rule` gained `regex=` and `category=`.
- Log records gained `prev_hash`/`hash`; older logs still load (unchained records are skipped by `verify_chain`).
- `ChatOllama` now comes from `langchain-ollama` (`langchain-community` is sunset).

## 📚 Design references
OWASP Top 10 for Agentic Applications (2026) · CaMeL "Defeating Prompt Injections by Design" · Microsoft FIDES "Securing AI Agents with Information-Flow Control" (arXiv:2505.23643) · "Prompt Infection" (arXiv:2410.07283) · multi-agent threat-model work (arXiv:2609.22949).
