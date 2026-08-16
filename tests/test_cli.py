"""End-to-end tests that drive the CLI entry point (``main``)."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from har_sanitizer import cli

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.har")
PLANTED_SECRET = "Kx8fJ2mQ9pLwR4vT7nB6sZ3hG5dY1cW0aEuIoP5tN2"


@contextlib.contextmanager
def run_cli(argv, stdin_text=""):
    """Run ``cli.main(argv)`` capturing stdout/stderr and feeding stdin."""
    out, err = io.StringIO(), io.StringIO()
    real_stdin = cli.sys.stdin
    cli.sys.stdin = io.StringIO(stdin_text)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        yield code, out.getvalue(), err.getvalue()
    finally:
        cli.sys.stdin = real_stdin


class CliFileTests(unittest.TestCase):
    def test_clean_har_to_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "clean.har")
            with run_cli(["clean", "--input", FIXTURE, "-o", out_path]) as (code, _o, _e):
                self.assertEqual(code, 0)
            with open(out_path, "r", encoding="utf-8") as handle:
                cleaned = json.load(handle)  # still valid HAR JSON
            blob = json.dumps(cleaned)
            self.assertIn("<REDACTED:cookie>", blob)
            self.assertIn("<REDACTED:bearer>", blob)
            self.assertNotIn("jane.doe@example.com", blob)

    def test_clean_har_to_stdout(self):
        with run_cli(["clean", "--input", FIXTURE]) as (code, out, _err):
            self.assertEqual(code, 0)
            parsed = json.loads(out)
            self.assertIn("log", parsed)
            self.assertIn("<REDACTED:email>", out)


class CliReportTests(unittest.TestCase):
    def test_report_goes_to_stderr_with_types(self):
        with run_cli(["clean", "--input", FIXTURE, "--report"]) as (code, out, err):
            self.assertEqual(code, 0)
            # stdout stays a clean artifact
            json.loads(out)
            self.assertIn("redaction report", err)
            for type_ in ("cookie", "bearer", "email", "pan"):
                self.assertIn(type_, err)

    def test_report_does_not_leak_values(self):
        with run_cli(["clean", "--input", FIXTURE, "--report"]) as (_code, _out, err):
            self.assertNotIn("jane.doe@example.com", err)
            self.assertNotIn("dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", err)


class CliStrictTests(unittest.TestCase):
    def test_strict_passes_on_clean_input(self):
        with run_cli(["clean", "--input", FIXTURE, "--strict"]) as (code, _out, err):
            self.assertEqual(code, 0)
            self.assertIn("STRICT OK", err)

    def test_strict_fails_when_secret_planted(self):
        with open(FIXTURE, "r", encoding="utf-8") as handle:
            har = json.load(handle)
        har["log"]["_internalNote"] = "leftover=" + PLANTED_SECRET
        with tempfile.TemporaryDirectory() as tmp:
            planted = os.path.join(tmp, "planted.har")
            with open(planted, "w", encoding="utf-8") as handle:
                json.dump(har, handle)
            with run_cli(["clean", "--input", planted, "--strict"]) as (code, _out, err):
                self.assertEqual(code, 2)
                self.assertIn("STRICT FAIL", err)
                self.assertNotIn(PLANTED_SECRET, err)  # length only, no value


class CliRawCurlTests(unittest.TestCase):
    def test_raw_via_stdin(self):
        raw = ("POST /login HTTP/1.1\r\n"
               "Cookie: sid=8f9a7b6c5d4e3f2a1b0c9d8e7f6a5b4c\r\n\r\n"
               "user=jane.doe@example.com")
        with run_cli(["clean", "--raw"], stdin_text=raw) as (code, out, _err):
            self.assertEqual(code, 0)
            self.assertIn("<REDACTED:cookie>", out)
            self.assertIn("<REDACTED:email>", out)

    def test_curl_argument(self):
        cmd = ("curl 'https://ex.com/a' "
               "-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzIjoieCJ9.sig_x'")
        with run_cli(["clean", "--curl", cmd]) as (code, out, _err):
            self.assertEqual(code, 0)
            self.assertIn("<REDACTED:bearer>", out)

    def test_autodetect_curl_from_stdin(self):
        cmd = "curl https://ex.com -H 'X-Api-Key: AKIAIOSFODNN7EXAMPLE'"
        with run_cli(["clean"], stdin_text=cmd) as (code, out, _err):
            self.assertEqual(code, 0)
            self.assertIn("<REDACTED:apikey>", out)


class CliCustomizationTests(unittest.TestCase):
    def test_add_header_and_allow(self):
        raw = ("GET / HTTP/1.1\r\n"
               "X-Internal-Trace: abc123def456ghi789jkl\r\n\r\n")
        with run_cli(["clean", "--raw", "--add-header", "X-Internal-Trace"],
                     stdin_text=raw) as (code, out, _err):
            self.assertEqual(code, 0)
            self.assertIn("X-Internal-Trace: <REDACTED:secret>", out)

    def test_invalid_add_pattern_exits_nonzero(self):
        with run_cli(["clean", "--input", FIXTURE, "--add-pattern", "nope"]) as (code, _o, err):
            self.assertEqual(code, 2)
            self.assertIn("config error", err)


if __name__ == "__main__":
    unittest.main()
