"""Low-level, stateless detectors used by the redactors.

Everything in this module is a pure function or a compiled regex so it can be
unit-tested in isolation and reused by the HAR / raw-HTTP / curl code paths.
Standard library only (``re``, ``math``).

The public helpers fall into three groups:

* ``shannon_entropy`` / ``is_high_entropy`` / ``find_high_entropy`` -- entropy
  based detection of generic random-looking secrets (session ids, API keys...).
* ``luhn_valid`` / ``find_pans`` -- payment-card detection gated by a Luhn
  checksum to keep false positives down.
* the ``find_*`` span finders (JWT, AWS keys, emails, phones, IPs) -- pattern
  based detection of well-known token and PII shapes.

A "span" is a ``(start, end)`` tuple of indices into the scanned text.
"""

from __future__ import annotations

import math
import re
from typing import List, Tuple

Span = Tuple[int, int]


# ---------------------------------------------------------------------------
# Placeholders
# ---------------------------------------------------------------------------

def placeholder(kind: str) -> str:
    """Return the redaction marker for *kind*, e.g. ``<REDACTED:cookie>``."""
    return "<REDACTED:%s>" % kind


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy of *data* in bits per character.

    A uniformly random base64 string approaches ``log2(64) == 6.0`` bits/char
    and random hex approaches ``log2(16) == 4.0``.  Ordinary words and prose
    sit well below the thresholds we use, which is what lets us separate
    high-entropy secrets from human-readable text.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_TOKEN_CHARSET_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def is_high_entropy(
    token: str,
    min_len: int = 20,
    base64_threshold: float = 4.0,
    hex_threshold: float = 3.0,
) -> bool:
    """Heuristic: does *token* look like a random, machine-generated secret?

    A token qualifies when it is long enough, is drawn purely from a
    secret-like character set (hex or base64/base64url), and its Shannon
    entropy clears the threshold for that character set.  Hex uses a lower
    threshold because it has a smaller alphabet.
    """
    if len(token) < min_len:
        return False
    if not _TOKEN_CHARSET_RE.match(token):
        return False
    entropy = shannon_entropy(token)
    if _HEX_RE.match(token):
        return entropy >= hex_threshold
    return entropy >= base64_threshold


def find_high_entropy(
    text: str,
    min_len: int = 20,
    base64_threshold: float = 4.0,
    hex_threshold: float = 3.0,
) -> List[Span]:
    """Return spans of every high-entropy token embedded in *text*.

    Candidate tokens are maximal runs of ``[A-Za-z0-9+/=_-]`` (note: no dot, so
    dotted JWTs and hostnames are not treated as a single token here).  Each
    candidate is then confirmed with :func:`is_high_entropy`.
    """
    pattern = re.compile(r"[A-Za-z0-9+/=_-]{%d,}" % max(1, min_len))
    spans: List[Span] = []
    for match in pattern.finditer(text):
        token = match.group()
        if is_high_entropy(token, min_len, base64_threshold, hex_threshold):
            spans.append((match.start(), match.end()))
    return spans


# ---------------------------------------------------------------------------
# Luhn / payment cards
# ---------------------------------------------------------------------------

def luhn_valid(number: str) -> bool:
    """Return ``True`` if the digits in *number* satisfy the Luhn checksum.

    Non-digit characters (spaces, dashes) are ignored so grouped card numbers
    such as ``4111 1111 1111 1111`` validate directly.  The digit count must be
    a plausible PAN length (13-19) to avoid matching short numeric ids.
    """
    digits = [int(ch) for ch in number if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


_PAN_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")


def find_pans(text: str) -> List[Span]:
    """Return spans of Luhn-valid, card-shaped digit sequences in *text*."""
    spans: List[Span] = []
    for match in _PAN_RE.finditer(text):
        if luhn_valid(match.group()):
            spans.append((match.start(), match.end()))
    return spans


# ---------------------------------------------------------------------------
# Token / secret shapes
# ---------------------------------------------------------------------------

# JWT: three base64url segments separated by dots; the header always starts
# with "eyJ" (base64url of '{"'). The signature may be empty for alg=none.
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# AWS access key ids: long-term (AKIA) and temporary (ASIA) prefixes.
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")


def find_jwts(text: str) -> List[Span]:
    return [(m.start(), m.end()) for m in JWT_RE.finditer(text)]


def find_aws_keys(text: str) -> List[Span]:
    return [(m.start(), m.end()) for m in AWS_KEY_RE.finditer(text)]


# ---------------------------------------------------------------------------
# PII: emails, phones, IPs
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def find_emails(text: str) -> List[Span]:
    return [(m.start(), m.end()) for m in EMAIL_RE.finditer(text)]


# International numbers must carry an explicit "+" country code; North-American
# style numbers require separators/parentheses so plain dates (YYYY-MM-DD) and
# bare id numbers are not mistaken for phone numbers.
_PHONE_INTL_RE = re.compile(
    r"(?<![\w])\+\d{1,3}[ .-]?(?:\(?\d{2,4}\)?[ .-]?){2,4}\d{2,4}(?![\w])"
)
_PHONE_NANP_RE = re.compile(
    r"(?<![\w])(?:\+?1[ .-]?)?(?:\(\d{3}\)[ .-]?|\d{3}[ .-])\d{3}[ .-]\d{4}(?![\w])"
)


def find_phones(text: str) -> List[Span]:
    """Return spans of phone-number-shaped substrings (heuristic).

    Phone detection is intentionally conservative: a candidate must contain
    separators/parentheses or a ``+`` country code and carry 7-15 digits.
    """
    spans: List[Span] = []
    for regex in (_PHONE_INTL_RE, _PHONE_NANP_RE):
        for match in regex.finditer(text):
            digit_count = sum(ch.isdigit() for ch in match.group())
            if 7 <= digit_count <= 15:
                spans.append((match.start(), match.end()))
    return spans


_IPV4_RE = re.compile(
    r"(?<![\d.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![\d.])"
)
# Loose IPv6: requires 4+ hextet groups so clock values like 12:34:56 do not
# match. Compressed "::" forms are not fully covered (IP redaction is opt-in).
_IPV6_RE = re.compile(r"(?<![\w:])(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}(?![\w:])")


def find_ips(text: str) -> List[Span]:
    spans = [(m.start(), m.end()) for m in _IPV4_RE.finditer(text)]
    spans += [(m.start(), m.end()) for m in _IPV6_RE.finditer(text)]
    return spans
