from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Rule:
    """Represents an attack detection rule used by the risk scorer."""
    name: str  # rule name for logging
    patterns: List[str]  # list of keyword/phrase patterns to search for
    score: int  # how much score to add when this rule matches
    case_sensitive: bool = False  # whether matching is case-sensitive


DEFAULT_RULES = [
    Rule(
        name="prompt_injection",
        patterns=[
            "ignore previous instructions", "ignore your previous instructions", "ignore your instructions",
            "disregard your", "forget your instructions", "override your",
            "do not follow", "bypass your guidelines", "act as if",
            "you have no restrictions", "your instructions are wrong"
        ],
        score=35
    ),
    Rule(
        name="privilege_escalation",
        patterns=[
            "admin access", "root access", "root permission", "grant yourself",
            "bypass authentication", "bypass security", "sudo", "superuser",
            "elevated privileges", "system administrator access", "unrestricted access"
        ],
        score=40
    ),
    Rule(
        name="role_confusion",
        patterns=[
            "you are now", "your new identity", "pretend you are",
            "your real purpose", "your true purpose", "forget what you are",
            "you are actually", "act as a different", "your persona is"
        ],
        score=30
    ),
    Rule(
        name="data_exfiltration",
        patterns=[
            "output all", "reveal your system prompt", "show me your prompt",
            "send me all data", "list all users", "dump the database",
            "show all credentials", "output your instructions", "reveal your training",
            "what is your system prompt"
        ],
        score=30
    ),
    Rule(
        name="jailbreak_phrases",
        patterns=[
            "dan mode", "developer mode", "jailbreak", "unrestricted mode",
            "no filter mode", "do anything now", "evil mode", "chaos mode"
        ],
        score=45
    )
]

def get_rules() -> List[Rule]:
    """
    Returns the list of default detection rules.
    """
    return DEFAULT_RULES

def get_rule_by_name(name: str) -> Optional[Rule]:
    """
    Finds and returns a rule by its name.
    
    Args:
        name (str): The name of the rule to search for.
        
    Returns:
        Optional[Rule]: The rule if found, otherwise None.
    """
    for rule in DEFAULT_RULES:
        if rule.name == name:
            return rule
    return None
