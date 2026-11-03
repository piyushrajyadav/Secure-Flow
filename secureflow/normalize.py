"""
Input normalization.

Attackers rarely send ``ignore previous instructions`` in plain ASCII. They hide it with
zero-width characters, Unicode "tag" characters (ASCII smuggling), homoglyphs, leetspeak,
spaced-out letters, or encodings (base64 / hex / URL / HTML entities / ROT13).

``build_views`` turns one message into several *views* of the same text. The scorer runs
its detectors over every view, so an attack only has to be visible in one of them to be seen.
"""
import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import List

# Characters that render as nothing (or reorder text) but survive copy/paste into a prompt.
_INVISIBLE = {
    0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E,
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0x3164, 0xFEFF, 0xFFA0,
}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_TAG_LO, _TAG_HI = 0xE0000, 0xE007F          # Unicode "tag" block, used for ASCII smuggling

# Common Cyrillic / Greek look-alikes -> Latin. NFKC does not fold these.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "н": "h",
    "в": "b", "ɡ": "g", "ο": "o", "ι": "i", "ν": "v", "α": "a", "ε": "e", "ρ": "p", "τ": "t",
    "υ": "u", "κ": "k", "μ": "u", "η": "n", "χ": "x", "ɑ": "a", "ӏ": "l",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,}={0,2}")
_BS = chr(92)   # a literal backslash, spelled out so no tool/editor layer can mangle the escape below
_HEX_RE = re.compile(
    "(?:(?:" + _BS + _BS + "x[0-9a-fA-F]{2}){8,}"                          # \x69\x67\x6e...
    "|(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[ :]){9,}[0-9a-fA-F]{2}"           # 69 67 6e 6f... / 69:67:6e...
    "|(?<![0-9a-fA-F])[0-9a-fA-F]{20,}(?![0-9a-fA-F]))"                   # 69676e6f72...
)
_SPACED_RE = re.compile(r"\b(?:[A-Za-z][\s.\-_*]){5,}[A-Za-z]\b")
_WS_RE = re.compile(r"\s+")
_MAX_DECODE_DEPTH = 3
_MAX_VIEWS = 24


@dataclass
class Views:
    """All the textual views derived from one message."""
    original: str
    texts: List[str] = field(default_factory=list)        # lowercase, scanned by detectors
    flags: List[str] = field(default_factory=list)        # evidence of deliberate hiding
    hidden_payload: str = ""                              # text smuggled via invisible chars


def _strip_invisible(text: str):
    """Remove invisible chars; return (clean_text, smuggled_ascii, found_any)."""
    out, smuggled, found = [], [], False
    for ch in text:
        cp = ord(ch)
        if _TAG_LO <= cp <= _TAG_HI:
            found = True
            if 0xE0020 <= cp <= 0xE007E:           # tag char == ASCII char + 0xE0000
                smuggled.append(chr(cp - 0xE0000))
            continue
        if cp in _INVISIBLE or cp in _BIDI:
            found = True
            continue
        if unicodedata.category(ch) == "Cc" and ch not in "\n\t\r":
            found = True
            continue
        out.append(ch)
    return "".join(out), "".join(smuggled), found


def _canonical(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_HOMOGLYPHS)
    return _WS_RE.sub(" ", text).strip().lower()


def _printable_ratio(s: str) -> float:
    return sum(ch.isprintable() or ch in "\n\t" for ch in s) / len(s) if s else 0.0


def _try_b64(token: str) -> str:
    tok = token.replace("-", "+").replace("_", "/")
    tok += "=" * (-len(tok) % 4)
    try:
        raw = base64.b64decode(tok, validate=True)
        s = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return ""
    return s if len(s) >= 8 and _printable_ratio(s) > 0.95 else ""


def _try_hex(blob: str) -> str:
    cleaned = re.sub(r"\\x|[\s:]", "", blob)
    if len(cleaned) < 16 or len(cleaned) % 2:
        return ""
    try:
        s = bytes.fromhex(cleaned).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""
    return s if _printable_ratio(s) > 0.95 else ""


def _rot13(s: str) -> str:
    import codecs
    return codecs.encode(s, "rot_13")


def _decode_layers(text: str, depth: int, flags: List[str], out: List[str]):
    """Find encoded substrings, decode them and recurse (attackers nest encodings)."""
    if depth > _MAX_DECODE_DEPTH or len(out) >= _MAX_VIEWS:
        return
    found = []
    for m in _B64_RE.finditer(text):
        dec = _try_b64(m.group(0))
        if dec:
            flags.append("base64")
            found.append(dec)
    for m in _HEX_RE.finditer(text):
        dec = _try_hex(m.group(0))
        if dec:
            flags.append("hex")
            found.append(dec)
    if "%" in text:
        dec = urllib.parse.unquote(text)
        if dec != text:
            flags.append("url_encoding")
            found.append(dec)
    if "&" in text:
        dec = html.unescape(text)
        if dec != text:
            flags.append("html_entities")
            found.append(dec)
    for dec in found:
        canon = _canonical(dec)
        if canon and canon not in out:
            out.append(canon)
            _decode_layers(dec, depth + 1, flags, out)


def build_views(message: str) -> Views:
    """Return every view of ``message`` that detectors should scan."""
    clean, smuggled, hidden = _strip_invisible(message)
    flags: List[str] = []
    if hidden:
        flags.append("invisible_characters")
    if smuggled:
        flags.append("unicode_tag_smuggling")

    views = Views(original=message, hidden_payload=smuggled)
    base = _canonical(clean)
    texts = [base]

    if smuggled:
        texts.append(_canonical(smuggled))
        texts.append(_canonical(clean + " " + smuggled))

    # Homoglyph usage is itself a signal when mixed into otherwise-Latin text.
    if clean != clean.translate(_HOMOGLYPHS) and re.search(r"[A-Za-z]", clean):
        flags.append("homoglyphs")

    # Spaced-out / punctuated letters: "i g n o r e", "i.g.n.o.r.e"
    def _despace(m):
        return re.sub(r"[\s.\-_*]", "", m.group(0))
    despaced = _SPACED_RE.sub(_despace, clean)
    if despaced != clean:
        flags.append("letter_spacing")
        texts.append(_canonical(despaced))

    # Leetspeak: only worth a view if digits/symbols are mixed into words.
    if re.search(r"[A-Za-z][0-9@$][A-Za-z]|[A-Za-z]{2}[0-9@$!]{1}[A-Za-z]", clean):
        leet = base.translate(_LEET)
        if leet != base:
            texts.append(leet)
            flags.append("leetspeak")

    _decode_layers(clean, 1, flags, texts)

    # ROT13 of the visible text only (catches ROT13-encoded payloads).
    texts.append(_rot13(base))

    seen, uniq = set(), []
    for t in texts:
        if t and t not in seen:
            seen.add(t)
            uniq.append(t)
    views.texts = uniq[:_MAX_VIEWS]
    views.flags = sorted(set(flags))
    return views
