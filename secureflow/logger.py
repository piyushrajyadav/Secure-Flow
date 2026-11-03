import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

_GENESIS = "0" * 64


class SecurityLogger:
    """
    Append-only JSON-lines security log.

    * Thread-safe (agents run concurrently).
    * Tamper-evident: every record carries ``prev_hash`` and ``hash`` (SHA-256 chain), so an
      edited, deleted or reordered line is detectable with ``verify_chain()``. This is
      detection, not prevention - ship the log to write-once storage for real guarantees.
    * Optional redaction: with ``redact=True`` message bodies are never written, only a
      SHA-256 fingerprint and the length (logs full of attack payloads and PII are a liability).
    """

    def __init__(self, log_file: str = "secureflow_log.json", redact: bool = False):
        self.log_file = log_file
        self.redact = redact
        self._lock = threading.Lock()
        self._last_hash = self._load_last_hash()

    # ------------------------------------------------------------------ internals
    def _load_last_hash(self) -> str:
        if not os.path.exists(self.log_file):
            return _GENESIS
        last = _GENESIS
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line).get("hash", last)
                except json.JSONDecodeError:
                    continue
        return last

    @staticmethod
    def _digest(prev_hash: str, event: Dict[str, Any]) -> str:
        body = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()

    def _write_log(self, event: Dict[str, Any]):
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        with self._lock:
            event["prev_hash"] = self._last_hash
            event["hash"] = self._digest(self._last_hash, {k: v for k, v in event.items() if k != "hash"})
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._last_hash = event["hash"]

    def _message_fields(self, message: str) -> Dict[str, Any]:
        fingerprint = hashlib.sha256(message.encode("utf-8", "replace")).hexdigest()[:16]
        if self.redact:
            return {"message_sha256_16": fingerprint, "message_length": len(message)}
        preview = message[:100] + ("..." if len(message) > 100 else "")
        return {"message_preview": preview, "message_sha256_16": fingerprint}

    # ------------------------------------------------------------------ public API
    def log_blocked(self, sender: str, receiver: str, message: str, score_result, extra: Optional[Dict[str, Any]] = None):
        event = {
            "event_type": "BLOCKED",
            "sender": sender,
            "receiver": receiver,
            **self._message_fields(message),
            "score": score_result.score,
            "triggered_rules": score_result.triggered_rules,
            "threshold": score_result.threshold,
            "evidence": getattr(score_result, "evidence", {}),
        }
        if extra:
            event.update(extra)
        self._write_log(event)

    def log_passed(self, sender: str, receiver: str, score: int, extra: Optional[Dict[str, Any]] = None):
        event = {"event_type": "PASSED", "sender": sender, "receiver": receiver, "score": score}
        if extra:
            event.update(extra)
        self._write_log(event)

    def log_event(self, event_type: str, **fields: Any):
        """Log any other security event (TOOL_DENIED, SIGNATURE_INVALID, JUDGE_ERROR, ...)."""
        self._write_log({"event_type": event_type, **fields})

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """Returns (ok, first_bad_line_number). ``(True, None)`` means the chain is intact."""
        if not os.path.exists(self.log_file):
            return True, None
        prev = _GENESIS
        with open(self.log_file, "r", encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    return False, n
                if "hash" not in event:                      # pre-chain (legacy) record
                    continue
                if event.get("prev_hash") != prev:
                    return False, n
                body = {k: v for k, v in event.items() if k != "hash"}
                if self._digest(prev, body) != event["hash"]:
                    return False, n
                prev = event["hash"]
        return True, None

    def get_stats(self) -> Dict[str, Any]:
        empty = {"total_events": 0, "total_blocked": 0, "total_passed": 0, "block_rate": 0.0,
                 "most_triggered_rule": None, "tool_denied": 0, "signature_failures": 0}
        if not os.path.exists(self.log_file):
            return empty

        total_blocked = total_passed = tool_denied = sig_fail = 0
        rule_counts: Dict[str, int] = {}
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = event.get("event_type")
                if kind == "BLOCKED":
                    total_blocked += 1
                    for rule in event.get("triggered_rules", []):
                        rule_counts[rule] = rule_counts.get(rule, 0) + 1
                elif kind == "PASSED":
                    total_passed += 1
                elif kind == "TOOL_DENIED":
                    tool_denied += 1
                elif kind == "SIGNATURE_INVALID":
                    sig_fail += 1

        total_events = total_blocked + total_passed
        return {
            "total_events": total_events,
            "total_blocked": total_blocked,
            "total_passed": total_passed,
            "block_rate": (total_blocked / total_events) * 100 if total_events else 0.0,
            "most_triggered_rule": max(rule_counts, key=rule_counts.get) if rule_counts else None,
            "tool_denied": tool_denied,
            "signature_failures": sig_fail,
        }

    def clear_log(self):
        with self._lock:
            if os.path.exists(self.log_file):
                os.remove(self.log_file)
            self._last_hash = _GENESIS
