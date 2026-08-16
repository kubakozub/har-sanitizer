"""The redactors: HAR, raw HTTP, and curl.

:class:`Redactor` walks a supported input, replaces sensitive values with
``<REDACTED:...>`` placeholders, records what it did (type + location, never
the value), and can run a fail-closed audit of the produced output.

Design note -- targeted redaction plus a safety net:
    The structured redactor scrubs the *known* fields of each format.  It does
    not blindly deep-scan arbitrary/custom fields, because free-form blobs can
    be anything and mangling them would corrupt the evidence.  ``--strict``
    layers a full-text entropy audit on top (:meth:`residual_secrets`) so that
    a secret hiding in an unexpected place still fails the run closed.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from . import detectors
from .config import SanitizerConfig, build_config
from .detectors import placeholder

Span = Tuple[int, int]


@dataclass(frozen=True)
class Redaction:
    """A single redaction event.  Never stores the redacted value."""

    type: str
    location: str


# Priority of value-level detectors when their spans overlap (lower wins).
_JWT_PRIORITY = 1
_AWS_PRIORITY = 2
_EMAIL_PRIORITY = 3
_PAN_PRIORITY = 4
_PHONE_PRIORITY = 5
_IP_PRIORITY = 6
_ENTROPY_PRIORITY = 7

_KNOWN_AUTH_SCHEMES = {
    "bearer": "bearer",
    "basic": "basic",
    "digest": "authorization",
    "token": "authorization",
    "negotiate": "authorization",
}


class Redactor:
    """Redact secrets/PII from HAR, raw HTTP, or curl inputs."""

    def __init__(self, config: Optional[SanitizerConfig] = None):
        self.config = config or build_config()
        self.redactions: List[Redaction] = []
        self._value_detectors = self._build_value_detectors()

    # -- detector pipeline -------------------------------------------------
    def _build_value_detectors(self):
        """Build the ordered ``(type, priority, finder)`` list from config."""
        cfg = self.config
        detectors_list: List[Tuple[str, int, Callable[[str], List[Span]]]] = []

        # User-supplied patterns win over everything else (priority 0).
        for name, regex in cfg.extra_patterns:
            detectors_list.append(
                (name, 0, lambda text, rx=regex: [
                    (m.start(), m.end()) for m in rx.finditer(text)])
            )

        detectors_list.append(("jwt", _JWT_PRIORITY, detectors.find_jwts))
        detectors_list.append(("aws-key", _AWS_PRIORITY, detectors.find_aws_keys))
        detectors_list.append(("email", _EMAIL_PRIORITY, detectors.find_emails))
        detectors_list.append(("pan", _PAN_PRIORITY, detectors.find_pans))
        detectors_list.append(("phone", _PHONE_PRIORITY, detectors.find_phones))
        if cfg.redact_ips:
            detectors_list.append(("ip", _IP_PRIORITY, detectors.find_ips))
        detectors_list.append((
            "secret", _ENTROPY_PRIORITY,
            lambda text: detectors.find_high_entropy(
                text, cfg.min_entropy_len, cfg.entropy_base64, cfg.entropy_hex),
        ))
        return detectors_list

    # -- recording ---------------------------------------------------------
    def _record(self, type_: str, location: str) -> None:
        self.redactions.append(Redaction(type=type_, location=location))

    # -- free-text scrubbing ----------------------------------------------
    def scrub_text(self, text: str, location: str) -> str:
        """Replace every detected secret/PII value in *text* with a marker.

        Overlapping matches are resolved by detector priority so that, e.g., a
        whole JWT wins over the high-entropy sub-token inside it.
        """
        if not text:
            return text

        candidates: List[Tuple[int, int, int, str]] = []  # (pri, start, end, type)
        for type_, priority, finder in self._value_detectors:
            for start, end in finder(text):
                fragment = text[start:end]
                if self.config.is_allowed(fragment):
                    continue
                candidates.append((priority, start, end, type_))

        if not candidates:
            return text

        candidates.sort(key=lambda item: (item[0], item[1]))
        accepted: List[Tuple[int, int, str]] = []
        occupied: List[Span] = []
        for _priority, start, end, type_ in candidates:
            if any(start < o_end and o_start < end for o_start, o_end in occupied):
                continue
            occupied.append((start, end))
            accepted.append((start, end, type_))

        accepted.sort(key=lambda item: item[0])
        out: List[str] = []
        cursor = 0
        for start, end, type_ in accepted:
            out.append(text[cursor:start])
            out.append(placeholder(type_))
            self._record(type_, location)
            cursor = end
        out.append(text[cursor:])
        return "".join(out)

    # -- header / cookie helpers ------------------------------------------
    def redact_header_value(self, name: str, value: str, location: str) -> str:
        """Redact a single header value according to its name."""
        lname = name.lower().strip()
        if lname == "cookie":
            return self._redact_cookie_header(value, location)
        if lname == "set-cookie":
            return self._redact_set_cookie(value, location)
        if lname in ("authorization", "proxy-authorization"):
            return self._redact_authorization(value, location)
        if self.config.is_url_header(lname):
            return self._redact_url(value, location)
        if self.config.is_sensitive_header(lname):
            type_ = self.config.header_type(lname)
            self._record(type_, location)
            return placeholder(type_)
        # Not a known-sensitive header: still scan the value for tokens/PII.
        return self.scrub_text(value, location)

    def _redact_authorization(self, value: str, location: str) -> str:
        parts = value.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in _KNOWN_AUTH_SCHEMES:
            type_ = _KNOWN_AUTH_SCHEMES[parts[0].lower()]
            self._record(type_, location)
            return "%s %s" % (parts[0], placeholder(type_))
        self._record("authorization", location)
        return placeholder("authorization")

    def _redact_cookie_header(self, value: str, location: str) -> str:
        # "name1=v1; name2=v2" -> keep names, redact values.
        rendered = []
        for pair in value.split(";"):
            if "=" in pair:
                name, _, _val = pair.partition("=")
                rendered.append("%s=%s" % (name.strip(), placeholder("cookie")))
                self._record("cookie", location)
            elif pair.strip():
                rendered.append(pair.strip())
        return "; ".join(rendered)

    def _redact_set_cookie(self, value: str, location: str) -> str:
        # "name=value; Path=/; HttpOnly" -> redact the value, keep attributes.
        parts = [p.strip() for p in value.split(";")]
        if parts and "=" in parts[0]:
            name, _, _val = parts[0].partition("=")
            parts[0] = "%s=%s" % (name.strip(), placeholder("cookie"))
            self._record("cookie", location)
        return "; ".join(p for p in parts if p)

    # -- URL helpers -------------------------------------------------------
    def _redact_url(self, url: str, location: str) -> str:
        if not url:
            return url
        main, fragment = url, ""
        if "#" in main:
            main, _, frag = main.partition("#")
            fragment = "#" + frag
        if "?" in main:
            base, _, query = main.partition("?")
            new_query = self._redact_query(query, location)
            return "%s?%s%s" % (self._redact_url_base(base, location),
                                new_query, fragment)
        return self._redact_url_base(main, location) + fragment

    def _redact_query(self, query: str, location: str) -> str:
        rendered = []
        for pair in query.split("&"):
            if "=" in pair:
                name, _, val = pair.partition("=")
                rendered.append("%s=%s" % (
                    name,
                    self._redact_named_value(name, val, "%s?%s" % (location, name)),
                ))
            else:
                rendered.append(pair)
        return "&".join(rendered)

    _USERINFO_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*://)([^/@?#]+)@(.*)$")

    def _redact_url_base(self, base: str, location: str) -> str:
        match = self._USERINFO_RE.match(base)
        if match:
            scheme, userinfo, rest = match.group(1), match.group(2), match.group(3)
            if ":" in userinfo:
                user, _, _pw = userinfo.partition(":")
                userinfo = "%s:%s" % (user, placeholder("password"))
                self._record("password", location)
            else:
                userinfo = placeholder("secret")
                self._record("secret", location)
            base = "%s%s@%s" % (scheme, userinfo, rest)
        return self.scrub_text(base, location)

    def _redact_named_value(self, name: str, value: str, location: str) -> str:
        """Redact a name=value pair (query string or form field)."""
        lname = name.lower()
        if self.config.is_sensitive_param(lname):
            type_ = self.config.param_type(lname)
            self._record(type_, location)
            return placeholder(type_)
        return self.scrub_text(value, location)

    # ------------------------------------------------------------------
    # HAR
    # ------------------------------------------------------------------
    def redact_har(self, har: dict) -> dict:
        """Redact a parsed HAR object in place and return it."""
        log = har.get("log") if isinstance(har, dict) else None
        if not isinstance(log, dict):
            raise ValueError("missing top-level 'log' object")
        entries = log.get("entries")
        if not isinstance(entries, list):
            raise ValueError("'log.entries' is not a list")
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            base = "log.entries[%d]" % index
            request = entry.get("request")
            if isinstance(request, dict):
                self._redact_har_request(request, base + ".request")
            response = entry.get("response")
            if isinstance(response, dict):
                self._redact_har_response(response, base + ".response")
        return har

    def _redact_har_request(self, request: dict, base: str) -> None:
        if isinstance(request.get("url"), str):
            request["url"] = self._redact_url(request["url"], base + ".url")
        self._redact_har_headers(request.get("headers"), base + ".headers")
        self._redact_har_cookies(request.get("cookies"), base + ".cookies")
        self._redact_har_named_list(
            request.get("queryString"), base + ".queryString")
        post = request.get("postData")
        if isinstance(post, dict):
            if isinstance(post.get("text"), str):
                post["text"] = self.scrub_text(post["text"], base + ".postData.text")
            self._redact_har_named_list(
                post.get("params"), base + ".postData.params")

    def _redact_har_response(self, response: dict, base: str) -> None:
        self._redact_har_headers(response.get("headers"), base + ".headers")
        self._redact_har_cookies(response.get("cookies"), base + ".cookies")
        redirect = response.get("redirectURL")
        if isinstance(redirect, str) and redirect:
            response["redirectURL"] = self._redact_url(
                redirect, base + ".redirectURL")
        content = response.get("content")
        if isinstance(content, dict) and isinstance(content.get("text"), str):
            content["text"] = self.scrub_text(
                content["text"], base + ".content.text")

    def _redact_har_headers(self, headers, base: str) -> None:
        if not isinstance(headers, list):
            return
        for header in headers:
            if (isinstance(header, dict)
                    and isinstance(header.get("name"), str)
                    and isinstance(header.get("value"), str)):
                location = "%s[%s]" % (base, header["name"])
                header["value"] = self.redact_header_value(
                    header["name"], header["value"], location)

    def _redact_har_cookies(self, cookies, base: str) -> None:
        if not isinstance(cookies, list):
            return
        for cookie in cookies:
            if isinstance(cookie, dict) and "value" in cookie:
                name = cookie.get("name", "")
                cookie["value"] = placeholder("cookie")
                self._record("cookie", "%s[%s]" % (base, name))

    def _redact_har_named_list(self, items, base: str) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("value"), str):
                name = item.get("name", "")
                item["value"] = self._redact_named_value(
                    name, item["value"], "%s[%s]" % (base, name))

    # ------------------------------------------------------------------
    # Raw HTTP
    # ------------------------------------------------------------------
    def redact_raw(self, text: str) -> str:
        """Redact a raw HTTP request or response, preserving its layout."""
        newline = "\r\n" if "\r\n" in text else "\n"
        separator = newline + newline
        if separator in text:
            head, body = text.split(separator, 1)
            has_body = True
        else:
            head, body = text, ""
            has_body = False

        lines = head.split(newline)
        start_line = lines[0] if lines else ""
        rebuilt = [self._redact_start_line(start_line)]
        for line in lines[1:]:
            if ":" in line and not line[:1].isspace():
                name, _, value = line.partition(":")
                redacted = self.redact_header_value(
                    name.strip(), value.strip(), "raw.headers[%s]" % name.strip())
                rebuilt.append("%s: %s" % (name, redacted))
            else:
                rebuilt.append(line)
        new_head = newline.join(rebuilt)
        if has_body:
            return new_head + separator + self.scrub_text(body, "raw.body")
        return new_head

    def _redact_start_line(self, line: str) -> str:
        if line.startswith("HTTP/"):
            return line  # response status line: nothing sensitive
        parts = line.split(" ")
        if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
            target = " ".join(parts[1:-1])
            redacted = self._redact_url(target, "raw.request-line")
            return "%s %s %s" % (parts[0], redacted, parts[-1])
        return line

    # ------------------------------------------------------------------
    # curl
    # ------------------------------------------------------------------
    _CURL_DATA_FLAGS = {
        "-d", "--data", "--data-raw", "--data-binary",
        "--data-ascii", "--data-urlencode",
    }

    def redact_curl(self, command: str) -> str:
        """Redact a curl command string, keeping it copy-paste runnable."""
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            tokens = command.split()

        out: List[str] = []
        index = 0
        count = len(tokens)
        while index < count:
            token = tokens[index]
            low = token.lower()

            if token.startswith("--") and "=" in token:
                flag, _, val = token.partition("=")
                out.append("%s=%s" % (
                    flag, shlex.quote(self._redact_curl_value(flag.lower(), val))))
                index += 1
                continue

            if low in ("-h", "--header") and index + 1 < count:
                out.append(token)
                out.append(shlex.quote(self._redact_header_arg(tokens[index + 1])))
                index += 2
                continue
            if low in ("-b", "--cookie") and index + 1 < count:
                out.append(token)
                out.append(shlex.quote(
                    self._redact_cookie_header(tokens[index + 1], "curl.cookie")))
                index += 2
                continue
            if low in ("-u", "--user") and index + 1 < count:
                out.append(token)
                out.append(shlex.quote(self._redact_user_arg(tokens[index + 1])))
                index += 2
                continue
            if low in self._CURL_DATA_FLAGS and index + 1 < count:
                out.append(token)
                out.append(shlex.quote(
                    self.scrub_text(tokens[index + 1], "curl.data")))
                index += 2
                continue
            if "://" in token:
                out.append(shlex.quote(self._redact_url(token, "curl.url")))
                index += 1
                continue

            out.append(shlex.quote(token))
            index += 1
        return " ".join(out)

    def _redact_curl_value(self, flag: str, val: str) -> str:
        if flag == "--header":
            return self._redact_header_arg(val)
        if flag == "--cookie":
            return self._redact_cookie_header(val, "curl.cookie")
        if flag == "--user":
            return self._redact_user_arg(val)
        if flag == "--url":
            return self._redact_url(val, "curl.url")
        if flag in self._CURL_DATA_FLAGS:
            return self.scrub_text(val, "curl.data")
        return val

    def _redact_header_arg(self, header: str) -> str:
        if ":" in header:
            name, _, value = header.partition(":")
            return "%s: %s" % (name, self.redact_header_value(
                name.strip(), value.strip(), "curl.header[%s]" % name.strip()))
        return header

    def _redact_user_arg(self, value: str) -> str:
        if ":" in value:
            user, _, _pw = value.partition(":")
            self._record("password", "curl.user")
            return "%s:%s" % (user, placeholder("password"))
        self._record("secret", "curl.user")
        return placeholder("secret")

    # ------------------------------------------------------------------
    # Reporting and the strict fail-closed audit
    # ------------------------------------------------------------------
    def report(self) -> dict:
        """Aggregate the recorded redactions (types + locations, no values)."""
        by_type: Dict[str, int] = {}
        for redaction in self.redactions:
            by_type[redaction.type] = by_type.get(redaction.type, 0) + 1
        return {
            "total": len(self.redactions),
            "by_type": by_type,
            "items": [(r.type, r.location) for r in self.redactions],
        }

    def residual_secrets(self, text: str) -> List[Tuple[str, int]]:
        """Fail-closed audit: find secrets still present in produced output.

        Returns a list of ``(type, length)`` tuples -- length only, never the
        value.  An empty list means the output passed the strict check.
        """
        cfg = self.config
        hits: List[Tuple[str, int]] = []
        seen: List[Span] = []

        def _collect(spans, type_):
            for start, end in spans:
                fragment = text[start:end]
                if cfg.is_allowed(fragment):
                    continue
                if any(start < o_end and o_start < end for o_start, o_end in seen):
                    continue
                seen.append((start, end))
                hits.append((type_, end - start))

        _collect(detectors.find_jwts(text), "jwt")
        _collect(detectors.find_aws_keys(text), "aws-key")
        _collect(
            detectors.find_high_entropy(
                text, cfg.min_entropy_len, cfg.entropy_base64, cfg.entropy_hex),
            "high-entropy",
        )
        return hits
