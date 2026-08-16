"""Configuration for the redactors.

:class:`SanitizerConfig` bundles every tunable knob -- which header and
parameter names are sensitive, extra user regexes, an allow-list, whether to
redact IPs, and the entropy thresholds.  :func:`build_config` merges, in order
of increasing precedence: built-in defaults, an optional config dict (loaded
from a JSON file by the CLI), and explicit CLI overrides.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Set, Tuple

# Entropy defaults (bits/char). base64 has a larger alphabet than hex, so it
# needs a higher bar before a token is deemed "random".
DEFAULT_MIN_LEN = 20
DEFAULT_BASE64_THRESHOLD = 4.0
DEFAULT_HEX_THRESHOLD = 3.0

# Headers whose whole value is replaced, mapped to the placeholder label used.
# Cookie / Set-Cookie / Authorization / Proxy-Authorization get *structural*
# handling in core.py (names/schemes preserved) and are intentionally not here.
DEFAULT_HEADER_TYPES: Dict[str, str] = {
    "x-api-key": "apikey",
    "api-key": "apikey",
    "apikey": "apikey",
    "x-apikey": "apikey",
    "x-goog-api-key": "apikey",
    "x-functions-key": "apikey",
    "x-csrf-token": "csrf",
    "x-csrftoken": "csrf",
    "csrf-token": "csrf",
    "x-xsrf-token": "csrf",
    "xsrf-token": "csrf",
    "x-auth-token": "secret",
    "x-access-token": "secret",
    "x-refresh-token": "secret",
    "x-session-token": "secret",
    "x-amz-security-token": "secret",
    "authentication": "secret",
    "x-secret": "secret",
}

# Headers whose value is a URL and may carry a token in its query string.
URL_VALUED_HEADERS: Set[str] = {
    "referer",
    "location",
    "content-location",
    "x-original-url",
    "x-rewrite-url",
}

# Query-string / form-field names whose value is redacted regardless of shape.
PASSWORD_PARAMS: Set[str] = {
    "password", "passwd", "pwd", "pass", "new_password", "old_password",
}
SESSION_PARAMS: Set[str] = {
    "session", "sessionid", "session_id", "sid", "phpsessid", "jsessionid",
}
_OTHER_SENSITIVE_PARAMS: Set[str] = {
    "token", "access_token", "refresh_token", "id_token", "auth", "authorization",
    "api_key", "apikey", "key", "secret", "client_secret",
    "sig", "signature", "code", "otp", "totp", "mfa",
}
DEFAULT_SENSITIVE_PARAMS: Set[str] = (
    PASSWORD_PARAMS | SESSION_PARAMS | _OTHER_SENSITIVE_PARAMS
)


@dataclass
class SanitizerConfig:
    """All tunables for a redaction run."""

    sensitive_headers: Set[str] = field(default_factory=set)
    header_types: Dict[str, str] = field(default_factory=dict)
    sensitive_params: Set[str] = field(default_factory=set)
    extra_patterns: List[Tuple[str, Pattern]] = field(default_factory=list)
    allow_patterns: List[Pattern] = field(default_factory=list)
    redact_ips: bool = False
    min_entropy_len: int = DEFAULT_MIN_LEN
    entropy_base64: float = DEFAULT_BASE64_THRESHOLD
    entropy_hex: float = DEFAULT_HEX_THRESHOLD

    # -- lookups -----------------------------------------------------------
    def is_sensitive_header(self, lname: str) -> bool:
        return lname in self.sensitive_headers

    def header_type(self, lname: str) -> str:
        return self.header_types.get(lname, "secret")

    def is_url_header(self, lname: str) -> bool:
        return lname in URL_VALUED_HEADERS

    def is_sensitive_param(self, lname: str) -> bool:
        return lname in self.sensitive_params

    def param_type(self, lname: str) -> str:
        if lname in PASSWORD_PARAMS:
            return "password"
        if lname in SESSION_PARAMS:
            return "session"
        return "secret"

    def is_allowed(self, value: str) -> bool:
        """Return ``True`` if *value* matches an allow-list pattern."""
        return any(pattern.search(value) for pattern in self.allow_patterns)


def build_config(
    file_cfg: Optional[dict] = None,
    add_headers=(),
    add_params=(),
    add_patterns=(),
    allow=(),
    redact_ips: bool = False,
    min_len: Optional[int] = None,
    base64_threshold: Optional[float] = None,
    hex_threshold: Optional[float] = None,
) -> SanitizerConfig:
    """Merge defaults + file config + CLI overrides into a SanitizerConfig.

    Raises ``ValueError`` for malformed ``--add-pattern`` specs or bad regexes
    so the CLI can report a clean error and exit non-zero.
    """
    file_cfg = file_cfg or {}

    headers: Set[str] = set(DEFAULT_HEADER_TYPES)
    header_types: Dict[str, str] = dict(DEFAULT_HEADER_TYPES)
    params: Set[str] = set(DEFAULT_SENSITIVE_PARAMS)
    extra: List[Tuple[str, Pattern]] = []
    allow_pats: List[Pattern] = []

    min_entropy_len = DEFAULT_MIN_LEN
    entropy_base64 = DEFAULT_BASE64_THRESHOLD
    entropy_hex = DEFAULT_HEX_THRESHOLD
    ips = bool(redact_ips)

    # --- from config file -------------------------------------------------
    for name in file_cfg.get("sensitive_headers", []):
        lname = name.lower()
        headers.add(lname)
        header_types.setdefault(lname, "secret")
    for name in file_cfg.get("sensitive_params", []):
        params.add(name.lower())
    for item in file_cfg.get("extra_patterns", []):
        try:
            extra.append((item["name"], re.compile(item["regex"])))
        except (KeyError, re.error) as exc:
            raise ValueError("bad extra_patterns entry %r: %s" % (item, exc))
    for expr in file_cfg.get("allow", []):
        try:
            allow_pats.append(re.compile(expr))
        except re.error as exc:
            raise ValueError("bad allow regex %r: %s" % (expr, exc))
    entropy_cfg = file_cfg.get("entropy", {})
    min_entropy_len = int(entropy_cfg.get("min_len", min_entropy_len))
    entropy_base64 = float(entropy_cfg.get("base64", entropy_base64))
    entropy_hex = float(entropy_cfg.get("hex", entropy_hex))
    if file_cfg.get("redact_ips"):
        ips = True

    # --- from CLI (highest precedence) ------------------------------------
    for name in add_headers:
        lname = name.lower()
        headers.add(lname)
        header_types.setdefault(lname, "secret")
    for name in add_params:
        params.add(name.lower())
    for spec in add_patterns:
        if "=" not in spec:
            raise ValueError(
                "invalid --add-pattern (expected NAME=REGEX): %r" % spec)
        name, _, regex = spec.partition("=")
        try:
            extra.append((name.strip() or "custom", re.compile(regex)))
        except re.error as exc:
            raise ValueError("invalid regex in --add-pattern %r: %s" % (name, exc))
    for expr in allow:
        try:
            allow_pats.append(re.compile(expr))
        except re.error as exc:
            raise ValueError("invalid --allow regex %r: %s" % (expr, exc))
    if min_len is not None:
        min_entropy_len = min_len
    if base64_threshold is not None:
        entropy_base64 = base64_threshold
    if hex_threshold is not None:
        entropy_hex = hex_threshold

    return SanitizerConfig(
        sensitive_headers=headers,
        header_types=header_types,
        sensitive_params=params,
        extra_patterns=extra,
        allow_patterns=allow_pats,
        redact_ips=ips,
        min_entropy_len=min_entropy_len,
        entropy_base64=entropy_base64,
        entropy_hex=entropy_hex,
    )
