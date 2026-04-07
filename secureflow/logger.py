import json
import os
from datetime import datetime
from typing import Dict, Any

class SecurityLogger:
    """Handles logging of blocked messages and security events in a JSON lines file."""

    def __init__(self, log_file: str = "secureflow_log.json"):
        """
        Initializes the SecurityLogger.
        
        Args:
            log_file (str): Path to the log file.
        """
        self.log_file = log_file

    def _write_log(self, event: Dict[str, Any]):
        """Helper to write a JSON line to the log file."""
        with open(self.log_file, "a", encoding="utf-8") as f:
            json.dump(event, f)
            f.write("\n")

    def log_blocked(self, sender: str, receiver: str, message: str, score_result):
        """
        Logs a blocked message event.
        
        Args:
            sender (str): The sending agent/entity.
            receiver (str): The receiving agent/entity.
            message (str): The original message payload.
            score_result: The ScoreResult object containing risk details.
        """
        message_preview = message[:100] + ("..." if len(message) > 100 else "")
        
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "BLOCKED",
            "sender": sender,
            "receiver": receiver,
            "message_preview": message_preview,
            "score": score_result.score,
            "triggered_rules": score_result.triggered_rules,
            "threshold": score_result.threshold
        }
        self._write_log(event)

    def log_passed(self, sender: str, receiver: str, score: int):
        """
        Logs a passed message event.
        
        Args:
            sender (str): The sending agent/entity.
            receiver (str): The receiving agent/entity.
            score (int): The calculated risk score.
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "PASSED",
            "sender": sender,
            "receiver": receiver,
            "score": score
        }
        self._write_log(event)

    def get_stats(self) -> Dict[str, Any]:
        """
        Reads the log file and calculates statistics.
        
        Returns:
            Dict[str, Any]: Basic stats about the logged events.
        """
        if not os.path.exists(self.log_file):
            return {
                "total_events": 0,
                "total_blocked": 0,
                "total_passed": 0,
                "block_rate": 0.0,
                "most_triggered_rule": None
            }

        total_events = 0
        total_blocked = 0
        total_passed = 0
        rule_counts = {}

        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    total_events += 1
                    
                    if event.get("event_type") == "BLOCKED":
                        total_blocked += 1
                        for rule in event.get("triggered_rules", []):
                            rule_counts[rule] = rule_counts.get(rule, 0) + 1
                    elif event.get("event_type") == "PASSED":
                        total_passed += 1
                except json.JSONDecodeError:
                    continue

        block_rate = (total_blocked / total_events) * 100 if total_events > 0 else 0.0
        most_triggered_rule = max(rule_counts, key=rule_counts.get) if rule_counts else None

        return {
            "total_events": total_events,
            "total_blocked": total_blocked,
            "total_passed": total_passed,
            "block_rate": block_rate,
            "most_triggered_rule": most_triggered_rule
        }

    def clear_log(self):
        """Clears the existing log file."""
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
