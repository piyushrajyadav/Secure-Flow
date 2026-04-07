import time
import json
from dataclasses import dataclass
from typing import Dict, Any
from tabulate import tabulate

from secureflow.middleware import SecureFlowMiddleware
from experiments.attack_dataset import get_all_attacks, get_all_legitimate, get_categories

@dataclass
class ExperimentResult:
    """Stores the metrics from an experiment run."""
    total_attacks: int
    total_legitimate: int
    attacks_blocked: int
    attacks_passed: int
    legit_blocked: int
    legit_passed: int
    attack_success_rate: float
    false_positive_rate: float
    results_by_category: Dict[str, Dict[str, Any]]

def run_experiment_with_secureflow(threshold: int = 60, verbose: bool = False) -> ExperimentResult:
    """
    Runs the full dataset of attacks and legit messages through SecureFlow.
    
    Args:
        threshold (int): The risk block threshold.
        verbose (bool): Whether to see middleware prints.
        
    Returns:
        ExperimentResult: The resulting metrics.
    """
    middleware = SecureFlowMiddleware(threshold=threshold, verbose=verbose)
    
    attacks = get_all_attacks()
    legitimates = get_all_legitimate()
    
    attacks_blocked = 0
    attacks_passed = 0
    legit_blocked = 0
    legit_passed = 0

    categories = get_categories()
    results_by_category = {cat: {"blocked": 0, "passed": 0, "total": 0, "asr": 0.0} for cat in categories}
    
    # Process Attacks
    for msg in attacks:
        result = middleware.intercept("orchestrator", "worker", msg.text)
        results_by_category[msg.category]["total"] += 1
        
        if result is None:
            attacks_blocked += 1
            results_by_category[msg.category]["blocked"] += 1
        else:
            attacks_passed += 1
            results_by_category[msg.category]["passed"] += 1

    # Process Legitimate
    for msg in legitimates:
        result = middleware.intercept("orchestrator", "worker", msg.text)
        if result is None:
            legit_blocked += 1
        else:
            legit_passed += 1

    # Calculate metrics
    total_attacks = len(attacks)
    total_legit = len(legitimates)
    
    asr = (attacks_passed / total_attacks * 100) if total_attacks > 0 else 0.0
    fpr = (legit_blocked / total_legit * 100) if total_legit > 0 else 0.0
    
    for cat in categories:
        cat_total = results_by_category[cat]["total"]
        cat_passed = results_by_category[cat]["passed"]
        results_by_category[cat]["asr"] = (cat_passed / cat_total * 100) if cat_total > 0 else 0.0

    return ExperimentResult(
        total_attacks=total_attacks,
        total_legitimate=total_legit,
        attacks_blocked=attacks_blocked,
        attacks_passed=attacks_passed,
        legit_blocked=legit_blocked,
        legit_passed=legit_passed,
        attack_success_rate=asr,
        false_positive_rate=fpr,
        results_by_category=results_by_category
    )

def run_experiment_baseline() -> ExperimentResult:
    """
    Simulates a baseline scenario without SecureFlow (all pass).
    
    Returns:
        ExperimentResult: The resulting metrics.
    """
    attacks = get_all_attacks()
    legitimates = get_all_legitimate()
    
    total_attacks = len(attacks)
    total_legit = len(legitimates)
    
    categories = get_categories()
    results_by_category = {cat: {"blocked": 0, "passed": 0, "total": 0, "asr": 0.0} for cat in categories}
    
    for msg in attacks:
        results_by_category[msg.category]["total"] += 1
        results_by_category[msg.category]["passed"] += 1

    for cat in categories:
        results_by_category[cat]["asr"] = 100.0

    return ExperimentResult(
        total_attacks=total_attacks,
        total_legitimate=total_legit,
        attacks_blocked=0,
        attacks_passed=total_attacks,
        legit_blocked=0,
        legit_passed=total_legit,
        attack_success_rate=100.0,
        false_positive_rate=0.0,
        results_by_category=results_by_category
    )

def print_results(result: ExperimentResult, label: str):
    """Prints a formatted report of an experiment run."""
    print(f"\n{'='*40}")
    print(f" EXPERIMENT RESULTS: {label}")
    print(f"{'='*40}")
    
    summary = [
        ["Total Attacks", result.total_attacks],
        ["Total Legitimate", result.total_legitimate],
        ["Attacks Blocked", result.attacks_blocked],
        ["Attacks Passed", result.attacks_passed],
        ["Legitimate Blocked (FP)", result.legit_blocked],
        ["Legitimate Passed", result.legit_passed],
        ["Attack Success Rate (ASR)", f"{result.attack_success_rate:.1f}%"],
        ["False Positive Rate (FPR)", f"{result.false_positive_rate:.1f}%"]
    ]
    print(tabulate(summary, tablefmt="grid"))
    
    print("\nBreakdown by Category:")
    cat_data = []
    for cat, data in result.results_by_category.items():
        if data["total"] > 0:
            cat_data.append([cat, data["total"], data["blocked"], data["passed"], f"{data['asr']:.1f}%"])
            
    print(tabulate(cat_data, headers=["Category", "Total", "Blocked", "Passed", "ASR"], tablefmt="grid"))


if __name__ == "__main__":
    print("Running experiments...")
    
    secureflow_result = run_experiment_with_secureflow(threshold=60, verbose=False)
    baseline_result = run_experiment_baseline()
    
    print_results(secureflow_result, "WITH SECUREFLOW")
    print_results(baseline_result, "WITHOUT SECUREFLOW (BASELINE)")
    
    # Save to JSON
    output_data = {
        "secureflow": {
            "attack_success_rate": secureflow_result.attack_success_rate,
            "false_positive_rate": secureflow_result.false_positive_rate,
            "categories": secureflow_result.results_by_category
        },
        "baseline": {
            "attack_success_rate": baseline_result.attack_success_rate,
            "false_positive_rate": baseline_result.false_positive_rate,
            "categories": baseline_result.results_by_category
        }
    }
    
    with open("experiment_results.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=4)
        
    print("\nResults saved to experiment_results.json")
