"""
Message provenance: who sent this, did it arrive intact, and what untrusted data influenced it?

Two ideas from the recent agent-security literature (OWASP Agentic Top 10 ASI07, CaMeL, FIDES):

1. **Authenticated messages.** Every inter-agent message is wrapped in an ``Envelope`` that is
   HMAC-signed by the sending agent and bound to its receiver, a nonce and a timestamp. A
   spoofed sender, tampered body, replayed message or wrong-recipient message is rejected.
   (A signature proves *origin and integrity*, NOT that the content is benign.)

2. **Taint tracking.** If an agent read untrusted data (a web page, an e-mail, a tool result)
   and then wrote a message, that message inherits the taint. ``effective_trust`` drops to
   ``UNTRUSTED`` no matter how trusted the sending agent is. Downstream, the middleware
   applies a stricter threshold and the tool policy refuses sensitive actions - so an
   injected instruction cannot ride a trusted agent's credentials.

Keys are shared secrets held in an ``AgentRegistry``. For agents in separate trust domains use
asymmetric signatures instead (Ed25519 via ``cryptography``/PyNaCl); only ``MessageSigner``
needs to change.
"""
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Dict, FrozenSet, Iterable, Optional, Tuple


class Trust(IntEnum):
    UNTRUSTED = 0   # web pages, e-mails, documents, tool output, anything attacker-reachable
    AGENT = 1       # another agent, provenance unknown
    USER = 2        # authenticated human principal
    SYSTEM = 3      # the developer / operator (system prompt, config)


@dataclass(frozen=True)
class Envelope:
    sender: str
    receiver: str
    content: str
    trust: Trust = Trust.AGENT
    taint: FrozenSet[str] = field(default_factory=frozenset)   # labels of untrusted sources
    nonce: str = ""
    timestamp: float = 0.0
    signature: str = ""

    @property
    def effective_trust(self) -> Trust:
        """Declared trust, capped to UNTRUSTED if any untrusted source influenced the content."""
        return Trust.UNTRUSTED if self.taint else self.trust

    def canonical(self) -> bytes:
        body = {
            "s": self.sender, "r": self.receiver, "c": self.content, "t": int(self.trust),
            "x": sorted(self.taint), "n": self.nonce, "ts": round(self.timestamp, 3),
        }
        return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class AgentRegistry:
    """Maps agent ids to signing keys."""

    def __init__(self):
        self._keys: Dict[str, bytes] = {}

    def register(self, agent_id: str, key: Optional[bytes] = None) -> bytes:
        self._keys[agent_id] = key or secrets.token_bytes(32)
        return self._keys[agent_id]

    def key_for(self, agent_id: str) -> Optional[bytes]:
        return self._keys.get(agent_id)

    def __contains__(self, agent_id: str) -> bool:
        return agent_id in self._keys


class MessageSigner:
    """Creates and verifies signed ``Envelope`` objects."""

    def __init__(self, registry: AgentRegistry, max_age_seconds: float = 300.0, replay_cache_size: int = 10_000):
        self.registry = registry
        self.max_age = max_age_seconds
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._seen_max = replay_cache_size
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ creating
    def sign(self, sender: str, receiver: str, content: str, trust: Trust = Trust.AGENT,
             taint: Iterable[str] = ()) -> Envelope:
        key = self.registry.key_for(sender)
        if key is None:
            raise KeyError(f"unknown agent '{sender}' - register it first")
        env = Envelope(sender, receiver, content, trust, frozenset(taint), secrets.token_hex(12), time.time())
        return replace(env, signature=hmac.new(key, env.canonical(), hashlib.sha256).hexdigest())

    def derive(self, sender: str, receiver: str, content: str, parents: Iterable[Envelope],
               trust: Trust = Trust.AGENT, extra_taint: Iterable[str] = ()) -> Envelope:
        """
        Sign a message that was *computed from* other messages (e.g. a summary). Taint and the
        lowest trust level of every parent propagate to the new message.
        """
        parents = list(parents)
        taint = set(extra_taint)
        low = trust
        for p in parents:
            taint |= set(p.taint)
            low = min(low, p.effective_trust)
        if low == Trust.UNTRUSTED and not taint:
            taint.add(f"derived-from-untrusted:{sender}")
        return self.sign(sender, receiver, content, min(trust, low), taint)

    def from_untrusted_source(self, sender: str, receiver: str, content: str, source: str) -> Envelope:
        """Wrap external content (web page, tool output, e-mail body) as an untrusted message."""
        return self.sign(sender, receiver, content, Trust.UNTRUSTED, {source})

    # ------------------------------------------------------------------ verifying
    def verify(self, env: Envelope, expected_receiver: Optional[str] = None) -> Tuple[bool, str]:
        key = self.registry.key_for(env.sender)
        if key is None:
            return False, f"unknown sender '{env.sender}'"
        expected = hmac.new(key, env.canonical(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, env.signature or ""):
            return False, "bad signature (spoofed sender or tampered content)"
        if expected_receiver is not None and env.receiver != expected_receiver:
            return False, f"message addressed to '{env.receiver}', delivered to '{expected_receiver}'"
        now = time.time()
        if abs(now - env.timestamp) > self.max_age:
            return False, "stale or future-dated message"
        with self._lock:
            if env.nonce in self._seen:
                return False, "replayed message"
            self._seen[env.nonce] = now
            while len(self._seen) > self._seen_max:
                self._seen.popitem(last=False)
        return True, "ok"
