"""
Minimal Groq (OpenAI-compatible) client with an on-disk response cache and rate-limit pacing.

* The API key is read ONLY from the GROQ_API_KEY environment variable and is never written to disk.
* Every response is cached in data/results/groq_cache.jsonl keyed by SHA-256 of the request
  (model + messages + tools + params). Re-running with the cache present needs no key and no network,
  which is how the released numbers can be re-derived (`GROQ_REPLAY=1`).
* Pacing: sleeps when the per-minute token budget is nearly exhausted, and honours 429 Retry-After.

Models are sampled at temperature 0, but hosted-model outputs are not guaranteed bit-identical across
days; the cache is the reproducibility artifact.
"""
import hashlib
import collections
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request

URL = "https://api.groq.com/openai/v1/chat/completions"
CACHE = os.path.join("data", "results", "groq_cache.jsonl")
_lock = threading.Lock()


def _log(msg):
    if os.environ.get("LLM_VERBOSE") == "1":
        print("[llm]", msg, file=sys.stderr, flush=True)
_cache = None


def _load():
    global _cache
    if _cache is None:
        _cache = {}
        if os.path.exists(CACHE):
            with open(CACHE, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        rec = json.loads(line)
                        _cache[rec["key"]] = rec["response"]
    return _cache


def _key(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _secs(s: str) -> float:
    total = 0.0
    for num, unit in re.findall(r"([\d.]+)(ms|m|s)", s or ""):
        total += float(num) * {"ms": 0.001, "s": 1, "m": 60}[unit]
    return total


TPM_BUDGET = int(os.environ.get("LLM_TPM_BUDGET", "7000"))      # stay under the provider's 8000 tokens/min
_windows = collections.defaultdict(collections.deque)           # model -> deque[(timestamp, reserved_tokens)]


def _throttle(model: str, reserve: int) -> None:
    """Client-side token bucket: the provider counts prompt + max completion tokens against the
    per-minute budget, so wait until this request fits in the trailing 60 s instead of eating a 429."""
    with _lock:
        win = _windows[model]
        while True:
            now = time.time()
            while win and now - win[0][0] >= 60:
                win.popleft()
            used = sum(t for _, t in win)
            if used + reserve <= TPM_BUDGET or not win:
                win.append((now, reserve))
                return
            wait = 60 - (now - win[0][0]) + 0.2
            _log(f"throttle {model}: used={used} reserve={reserve}, sleeping {wait:.1f}s")
            time.sleep(wait)


class ReplayMiss(RuntimeError):
    pass


def chat(model: str, messages: list, tools: list = None, max_tokens: int = 400, est_tokens: int = 1500, **extra) -> dict:
    """Return {'message': {...}} or {'error': {...}} (errors such as tool_use_failed are cached too)."""
    body = {"model": model, "messages": messages, "temperature": 0, "max_completion_tokens": max_tokens, **extra}
    if tools:
        body["tools"] = tools
    k = _key(body)
    cache = _load()
    if k in cache:
        return cache[k]
    if os.environ.get("GROQ_REPLAY") == "1":
        raise ReplayMiss("response not in cache and GROQ_REPLAY=1")
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set (or set GROQ_REPLAY=1 to use the cache only)")
    reserve = int(len(json.dumps(body)) / 3.2) + max_tokens
    attempt = 0
    while True:
        attempt += 1
        _throttle(model, reserve)
        req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers={
            "Authorization": "Bearer " + api_key, "Content-Type": "application/json", "User-Agent": "secureflow-eval/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                data = json.load(r)
                hdr = {h.lower(): v for h, v in r.headers.items()}
            resp = {"message": data["choices"][0]["message"], "usage": data.get("usage", {})}
            rem = hdr.get("x-ratelimit-remaining-tokens")
            _log(f"ok {model} remaining-tokens={rem} usage={resp['usage'].get('total_tokens')}")
            if rem is not None and int(rem) < est_tokens:
                time.sleep(min(70, _secs(hdr.get("x-ratelimit-reset-tokens", "5s")) + 0.5))
            break
        except urllib.error.HTTPError as e:                     # must precede URLError (its base class)
            text = e.read().decode("utf-8", "replace")
            if e.code == 429 and attempt < 8:
                wait = float(e.headers.get("retry-after", "10"))
                _log(f"429 attempt {attempt}: retry-after={wait}s :: {text[:700]}")
                time.sleep(min(90, wait + 1))
                continue
            if e.code == 400:
                try:
                    err = json.loads(text).get("error", {})
                except json.JSONDecodeError:
                    err = {"message": text[:300]}
                resp = {"error": {"code": err.get("code"), "message": str(err.get("message"))[:300],
                                  "failed_generation": str(err.get("failed_generation", ""))[:600]}}
                break
            if attempt < 4 and e.code >= 500:
                time.sleep(5 * attempt)
                continue
            raise RuntimeError(f"Groq HTTP {e.code}: {text[:200]}")
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            if attempt < 8:                                     # transient DNS / connection / timeout
                time.sleep(min(60, 3 * attempt))
                continue
            raise RuntimeError(f"Groq network error after {attempt} attempts: {type(e).__name__}")
    with _lock:
        cache[k] = resp
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        line = json.dumps({"key": k, "model": model, "response": resp}, ensure_ascii=False) + "\n"
        for attempt_w in range(8):                 # another process may be appending to the same file (Windows)
            try:
                with open(CACHE, "a", encoding="utf-8") as f:
                    f.write(line)
                break
            except OSError:
                if attempt_w == 7:
                    raise
                time.sleep(0.2 * (attempt_w + 1))
    return resp
