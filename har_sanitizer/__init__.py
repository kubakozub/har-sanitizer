"""har-sanitizer: redact secrets and PII from HTTP evidence.

A small, dependency-free tool for bug-bounty researchers who attach HTTP
captures (HAR exports, raw requests, curl commands) to vulnerability reports.
It replaces session tokens, credentials, API keys, and customer PII with clear
``<REDACTED:...>`` placeholders while preserving enough structure that the
request stays understandable and reproducible.

Library usage::

    from har_sanitizer import Redactor
    redactor = Redactor()
    cleaned = redactor.redact_curl("curl https://ex.com -H 'Cookie: s=secret'")
    print(cleaned)
    print(redactor.report())
"""

from .config import SanitizerConfig, build_config
from .core import Redaction, Redactor

__version__ = "1.0.0"

__all__ = [
    "Redactor",
    "Redaction",
    "SanitizerConfig",
    "build_config",
    "__version__",
]
