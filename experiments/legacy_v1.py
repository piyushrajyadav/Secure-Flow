"""Frozen copy of the original v1 keyword detector, kept ONLY as a comparison baseline."""
LEGACY_RULES = [
    (35, ["ignore previous instructions", "ignore your previous instructions", "ignore your instructions",
          "disregard your", "forget your instructions", "override your", "do not follow",
          "bypass your guidelines", "act as if", "you have no restrictions", "your instructions are wrong"]),
    (40, ["admin access", "root access", "root permission", "grant yourself", "bypass authentication",
          "bypass security", "sudo", "superuser", "elevated privileges", "system administrator access",
          "unrestricted access"]),
    (30, ["you are now", "your new identity", "pretend you are", "your real purpose", "your true purpose",
          "forget what you are", "you are actually", "act as a different", "your persona is"]),
    (30, ["output all", "reveal your system prompt", "show me your prompt", "send me all data",
          "list all users", "dump the database", "show all credentials", "output your instructions",
          "reveal your training", "what is your system prompt"]),
    (45, ["dan mode", "developer mode", "jailbreak", "unrestricted mode", "no filter mode",
          "do anything now", "evil mode", "chaos mode"]),
]


class LegacyScorer:
    def __init__(self, threshold: int = 60):
        self.threshold = threshold

    def is_blocked(self, message: str) -> bool:
        low = message.lower()
        total = sum(s for s, pats in LEGACY_RULES if any(p in low for p in pats))
        if len(message) > 2000:
            total += 15
        return min(total, 100) >= self.threshold
