"""Command-line interface for har-sanitizer.

Usage examples::

    har-sanitizer clean --input in.har -o out.har
    har-sanitizer clean --input in.har --report --strict
    har-sanitizer clean --curl "curl 'https://ex.com' -H 'Cookie: s=1'"
    cat request.txt | har-sanitizer clean --raw

The cleaned artifact is written to ``-o/--output`` (or stdout).  The redaction
report and strict-audit messages always go to stderr, so stdout stays a clean,
pipeable artifact.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, TextIO, Tuple

from . import __version__
from .config import build_config
from .core import Redactor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="har-sanitizer",
        description="Redact secrets and PII from HAR / raw HTTP / curl evidence "
                    "before attaching it to a vulnerability report.",
    )
    parser.add_argument(
        "--version", action="version", version="har-sanitizer %s" % __version__)
    subparsers = parser.add_subparsers(dest="command")

    clean = subparsers.add_parser(
        "clean", help="Redact an input and emit the cleaned artifact.")
    source = clean.add_argument_group("input (choose one; auto-detected by default)")
    source.add_argument(
        "-i", "--input", metavar="FILE",
        help="HAR/raw file to read ('-' for stdin).")
    source.add_argument(
        "--raw", action="store_true",
        help="Treat the input as a raw HTTP request/response (stdin).")
    source.add_argument(
        "--curl", metavar="COMMAND",
        help="Redact a curl command string given on the command line.")

    clean.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write the cleaned artifact here (default: stdout).")
    clean.add_argument(
        "--report", action="store_true",
        help="Print a summary of what was redacted (to stderr).")
    clean.add_argument(
        "--strict", action="store_true",
        help="Exit non-zero if any residual high-entropy secret remains "
             "(fail-closed).")

    tuning = clean.add_argument_group("customization")
    tuning.add_argument(
        "--config", metavar="FILE", help="JSON config file (see README).")
    tuning.add_argument(
        "--add-header", action="append", default=[], metavar="NAME",
        help="Additional header name to fully redact (repeatable).")
    tuning.add_argument(
        "--add-param", action="append", default=[], metavar="NAME",
        help="Additional query/form parameter name to redact (repeatable).")
    tuning.add_argument(
        "--add-pattern", action="append", default=[], metavar="NAME=REGEX",
        help="Extra regex to redact, labelled NAME (repeatable).")
    tuning.add_argument(
        "--allow", action="append", default=[], metavar="REGEX",
        help="Allow-list regex: matching values are left untouched (repeatable).")
    tuning.add_argument(
        "--redact-ips", action="store_true",
        help="Also redact IP addresses (off by default).")
    tuning.add_argument(
        "--min-entropy-len", type=int, metavar="N",
        help="Minimum token length for high-entropy detection (default 20).")
    tuning.add_argument(
        "--entropy-base64", type=float, metavar="BITS",
        help="Entropy threshold for base64 tokens (default 4.0).")
    tuning.add_argument(
        "--entropy-hex", type=float, metavar="BITS",
        help="Entropy threshold for hex tokens (default 3.0).")
    return parser


def _read_file_or_stdin(path: str, stdin: TextIO) -> str:
    if path == "-":
        return stdin.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _load_source(args, stdin: TextIO) -> Tuple[str, object]:
    """Return ``(kind, data)`` where kind is 'har', 'raw', or 'curl'."""
    if args.curl is not None:
        return "curl", args.curl
    if args.raw:
        return "raw", stdin.read()

    text = _read_file_or_stdin(args.input, stdin) if args.input else stdin.read()

    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict) and "log" in obj:
            return "har", obj
    if stripped.startswith("curl ") or stripped.startswith("curl\t"):
        return "curl", text
    return "raw", text


def _build_config_from_args(args):
    file_cfg = {}
    if args.config:
        with open(args.config, "r", encoding="utf-8") as handle:
            file_cfg = json.load(handle)
    return build_config(
        file_cfg=file_cfg,
        add_headers=args.add_header,
        add_params=args.add_param,
        add_patterns=args.add_pattern,
        allow=args.allow,
        redact_ips=args.redact_ips,
        min_len=args.min_entropy_len,
        base64_threshold=args.entropy_base64,
        hex_threshold=args.entropy_hex,
    )


def _print_report(redactor: Redactor, stream: TextIO) -> None:
    report = redactor.report()
    print("redaction report", file=stream)
    print("  total redactions: %d" % report["total"], file=stream)
    if report["by_type"]:
        print("  by type:", file=stream)
        for type_, count in sorted(report["by_type"].items()):
            print("    %-12s %d" % (type_, count), file=stream)
    if report["items"]:
        print("  locations:", file=stream)
        for type_, location in report["items"]:
            print("    [%s] %s" % (type_, location), file=stream)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "command", None) != "clean":
        parser.print_help(sys.stderr)
        return 2

    try:
        config = _build_config_from_args(args)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("config error: %s" % exc, file=sys.stderr)
        return 2

    redactor = Redactor(config)

    try:
        kind, data = _load_source(args, sys.stdin)
    except OSError as exc:
        print("input error: %s" % exc, file=sys.stderr)
        return 2

    if kind == "har":
        try:
            redactor.redact_har(data)
        except ValueError as exc:
            print("not a valid HAR file: %s" % exc, file=sys.stderr)
            return 2
        output = json.dumps(data, indent=2, ensure_ascii=False)
    elif kind == "raw":
        output = redactor.redact_raw(data)
    else:
        output = redactor.redact_curl(data)

    if args.output and args.output != "-":
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
            if not output.endswith("\n"):
                handle.write("\n")
        print("wrote cleaned artifact (%d redaction(s)) to %s"
              % (len(redactor.redactions), args.output), file=sys.stderr)
    else:
        sys.stdout.write(output)
        if not output.endswith("\n"):
            sys.stdout.write("\n")

    if args.report:
        _print_report(redactor, sys.stderr)

    if args.strict:
        residual = redactor.residual_secrets(output)
        if residual:
            print("STRICT FAIL: %d residual high-entropy token(s) remain after "
                  "redaction (fail-closed)." % len(residual), file=sys.stderr)
            for type_, length in residual:
                print("  - %s (length %d)" % (type_, length), file=sys.stderr)
            return 2
        print("STRICT OK: no residual high-entropy tokens detected.",
              file=sys.stderr)

    return 0
