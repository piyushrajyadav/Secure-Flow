"""
Reproduce every number in the paper with one command (no model, no GPU, ~5 minutes).

    python -m experiments.run_all             # needs network once, for InjecAgent
    python -m experiments.run_all --offline   # skip the InjecAgent step

Outputs: data/results/*.json   (each stamped with the git commit that produced it)
"""
import argparse
import sys

from experiments import adaptive, export_corpora, latency_eval, paper_eval
from experiments.external import eval_injecagent, fetch_injecagent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()
    steps = [("export corpora", export_corpora.main), ("paper tables", paper_eval.main),
             ("adaptive adversary", adaptive.run), ("latency", latency_eval.main)]
    if not args.offline:
        steps[1:1] = [("fetch InjecAgent", fetch_injecagent.main), ("InjecAgent evaluation", eval_injecagent.main)]
    for name, fn in steps:
        print(f"\n===== {name} =====")
        fn()
    print("\nDone. Results in data/results/")


if __name__ == "__main__":
    sys.exit(main())
