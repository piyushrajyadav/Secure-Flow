"""
Least-privilege tool policy.

Detection is probabilistic: some paraphrased injection WILL get through. What limits the damage
is what a compromised agent is *able to do*. This module is the deterministic backstop:

* **Default deny** - an agent can only call tools explicitly granted to it.
* **Argument validation** - per-tool validators (allowed domains, path jail, length caps).
* **Taint-aware gating** - when the triggering context came from untrusted data, sensitive
  tools (writes, outbound network, destructive actions) need explicit human approval.
* **Argument scanning** - string arguments run through the same risk scorer, so an injected
  payload cannot be smuggled in as a "parameter".

This is the control that matters most for "excessive agency" (OWASP LLM06 / Agentic ASI02).
"""
import os
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

from secureflow.provenance import Envelope, Trust


class Sensitivity(IntEnum):
    READ = 0          # read-only, local
    WRITE = 1         # modifies internal state
    EXTERNAL = 2      # sends data outside the trust boundary (HTTP, e-mail, chat)
    DESTRUCTIVE = 3   # deletes / irreversible / privilege changes


@dataclass
class ToolSpec:
    name: str
    sensitivity: Sensitivity = Sensitivity.READ
    validators: Dict[str, Callable[[Any], bool]] = field(default_factory=dict)   # arg name -> check
    required_args: Set[str] = field(default_factory=set)
    allow_extra_args: bool = False
    description: str = ""


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    requires_approval: bool = False
    rules: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------- ready-made validators
def allow_domains(*domains: str) -> Callable[[Any], bool]:
    """URL must use https and a host equal to / a subdomain of one of ``domains``."""
    allowed = [d.lower() for d in domains]

    def check(value: Any) -> bool:
        try:
            u = urlparse(str(value))
        except ValueError:
            return False
        host = (u.hostname or "").lower()
        return u.scheme == "https" and any(host == d or host.endswith("." + d) for d in allowed)
    return check


def path_within(root: str) -> Callable[[Any], bool]:
    """Path must resolve inside ``root`` (blocks ../ traversal and absolute escapes)."""
    root_real = os.path.realpath(root)

    def check(value: Any) -> bool:
        target = os.path.realpath(os.path.join(root_real, str(value)))
        return target == root_real or target.startswith(root_real + os.sep)
    return check


def max_length(n: int) -> Callable[[Any], bool]:
    return lambda v: len(str(v)) <= n


def matches(pattern: str) -> Callable[[Any], bool]:
    rx = re.compile(pattern)
    return lambda v: bool(rx.fullmatch(str(v)))


class ToolPolicy:
    """Registry of tools + per-agent grants + the authorization decision."""

    def __init__(self, max_untrusted_sensitivity: Sensitivity = Sensitivity.READ, scorer=None):
        self.max_untrusted = max_untrusted_sensitivity
        self.tools: Dict[str, ToolSpec] = {}
        self.grants: Dict[str, Set[str]] = {}
        self.scorer = scorer          # optional RiskScorer used to scan string arguments

    def register_tool(self, spec: ToolSpec) -> "ToolPolicy":
        self.tools[spec.name] = spec
        return self

    def grant(self, agent: str, tools: Iterable[str]) -> "ToolPolicy":
        self.grants.setdefault(agent, set()).update(tools)
        return self

    def authorize(self, agent: str, tool: str, args: Optional[Dict[str, Any]] = None,
                  context: Optional[Envelope] = None, approved: bool = False) -> PolicyDecision:
        args = args or {}
        spec = self.tools.get(tool)
        if spec is None:
            return PolicyDecision(False, f"unknown tool '{tool}'", rules=["unknown_tool"])
        if tool not in self.grants.get(agent, set()):
            return PolicyDecision(False, f"agent '{agent}' is not granted tool '{tool}'", rules=["not_granted"])

        missing = spec.required_args - set(args)
        if missing:
            return PolicyDecision(False, f"missing required args: {sorted(missing)}", rules=["missing_args"])
        if not spec.allow_extra_args:
            extra = set(args) - set(spec.validators) - spec.required_args
            if extra:
                return PolicyDecision(False, f"unexpected args: {sorted(extra)}", rules=["unexpected_args"])
        for name, check in spec.validators.items():
            if name in args:
                try:
                    ok = check(args[name])
                except Exception:
                    ok = False
                if not ok:
                    return PolicyDecision(False, f"argument '{name}' failed validation", rules=["invalid_arg"])

        if self.scorer is not None:
            for name, value in args.items():
                if isinstance(value, str):
                    res = self.scorer.score(value)
                    if res.is_blocked:
                        return PolicyDecision(False, f"argument '{name}' looks like an injection payload "
                                              f"({', '.join(res.triggered_rules)})", rules=["suspicious_arg"])

        trust = context.effective_trust if context is not None else Trust.USER
        needs_gate = (trust == Trust.UNTRUSTED and spec.sensitivity > self.max_untrusted) \
            or spec.sensitivity == Sensitivity.DESTRUCTIVE
        if needs_gate and not approved:
            why = ("destructive action" if spec.sensitivity == Sensitivity.DESTRUCTIVE
                   else f"context influenced by untrusted data ({', '.join(sorted(context.taint)) or 'untrusted'})")
            return PolicyDecision(False, f"human approval required: {why}", requires_approval=True,
                                  rules=["approval_required"])
        return PolicyDecision(True, "ok")
