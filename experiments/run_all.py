"""
Reproduce every number in the paper with one command (no GPU; ~8 minutes).

    python -m experiments.run_all             # needs network once, for InjecAgent
    python -m experiments.run_all --offline   # skip the InjecAgent download (uses data/external if present)
    python -m experiments.run_all --no-llm    # skip the model-in-the-loop replay

The model-in-the-loop experiments (classifier baseline, LLM judge, agent) are re-derived from the released
request/response cache in REPLAY mode: no network access and no credentials are needed. To re-run them live
instead, set LLM_API_KEY and LLM_REPLAY=0 (results may differ slightly: hosted-model outputs can drift).

Outputs: data/results/*.json   (each stamped with the git commit that produced it)
"""
import argparse
import os
import sys

from experiments import adaptive, export_corpora, latency_eval, llm_eval, paper_eval
from experiments.external import eval_injecagent, fetch_injecagent


def llm_replay():
    os.environ.setdefault("LLM_REPLAY", "1")
    llm_eval.run_promptguard(50)
    llm_eval.run_judge(50, llm_eval.JUDGE_MODEL_MAIN, "27b", ("v3", "injecagent", "v2"))
    llm_eval.run_judge(50, llm_eval.JUDGE_MODEL, "120b", ("v3",))
    llm_eval.run_e2e(40, 40)
    llm_eval.run_e2e(25, 20, "qwen/qwen3.8-27b", "qwen27b")
    llm_eval.run_capability_control("qwen/qwen3.8-27b", "qwen27b")
    llm_eval.run_capability_control(llm_eval.AGENT_MODEL, "gptoss20b")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--no-llm", action="store_true")
    args = ap.parse_args()
    steps = [("export corpora", export_corpora.main), ("paper tables", paper_eval.main),
             ("adaptive adversary", adaptive.run), ("latency", latency_eval.main)]
    if not args.offline:
        steps[1:1] = [("fetch InjecAgent", fetch_injecagent.main)]
    steps.insert(2 if args.offline else 3, ("InjecAgent evaluation", eval_injecagent.main))
    if not args.no_llm:
        steps.append(("model-in-the-loop (cache replay)", llm_replay))
    for name, fn in steps:
        print(f"\n===== {name} =====")
        fn()
    print("\nDone. Results in data/results/")


if __name__ == "__main__":
    sys.exit(main())
