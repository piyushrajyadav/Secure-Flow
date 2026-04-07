import os
import json
from flask import Flask, jsonify, render_template, request
from secureflow import SecureFlowMiddleware
from experiments.attack_sim import run_experiment_with_secureflow, run_experiment_baseline

app = Flask(__name__)
middleware = SecureFlowMiddleware(threshold=60, verbose=False)

RESULTS_FILE = "experiment_results.json"

@app.route("/")
def index():
    """Renders the main dashboard page."""
    results = None
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            results = json.load(f)
    return render_template("index.html", initial_results=results)

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Returns current middleware statistics."""
    return jsonify(middleware.get_stats())

@app.route("/api/test", methods=["POST"])
def test_message():
    """Tests a single message through the middleware."""
    data = request.json
    if not data or "message" not in data:
        return jsonify({"error": "No message provided"}), 400
        
    sender = data.get("sender", "orchestrator")
    receiver = data.get("receiver", "worker")
    message = data.get("message")
    
    score_result = middleware.scorer.score(message)
    
    if score_result.is_blocked:
        middleware.logger.log_blocked(sender, receiver, message, score_result)
        result_msg = "Message blocked by SecureFlow"
    else:
        middleware.logger.log_passed(sender, receiver, score_result.score)
        result_msg = message

    return jsonify({
        "score": score_result.score,
        "blocked": score_result.is_blocked,
        "triggered_rules": score_result.triggered_rules,
        "message": result_msg,
        "original_message": message
    })

@app.route("/api/results", methods=["GET"])
def get_results():
    """Returns the saved experiment results."""
    if not os.path.exists(RESULTS_FILE):
        return jsonify({"error": "Run experiments first"}), 404
        
    with open(RESULTS_FILE, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))

@app.route("/api/run_experiments", methods=["POST"])
def run_experiments():
    """Runs the full experiment suite and saves results."""
    try:
        secureflow_result = run_experiment_with_secureflow(threshold=60, verbose=False)
        baseline_result = run_experiment_baseline()
        
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
        
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=4)
            
        return jsonify(output_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Returns the last 10 blocked messages from the log."""
    logs = []
    if os.path.exists(middleware.log_file):
        with open(middleware.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in reversed(lines):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "BLOCKED":
                        logs.append(event)
                        if len(logs) >= 10:
                            break
                except json.JSONDecodeError:
                    pass
    return jsonify(logs)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SecureFlow Dashboard")
    parser.add_argument("--prod", action="store_true", help="Run with Waitress (production WSGI server)")
    args = parser.parse_args()

    # Ensure templates folder exists
    os.makedirs("dashboard/templates", exist_ok=True)
    
    if args.prod:
        from waitress import serve
        print("Starting SecureFlow Dashboard in PRODUCTION mode via Waitress on port 5000...")
        serve(app, host="0.0.0.0", port=5000)
    else:
        print("Starting SecureFlow Dashboard in DEVELOPMENT mode (Flask dev server)...")
        app.run(host="0.0.0.0", port=5000, debug=False)
