"""Tests for the HAR redactor, the report, and the strict fail-closed audit."""

import json
import os
import unittest

from har_sanitizer import Redactor, build_config
from har_sanitizer.core import Redactor as CoreRedactor

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.har")

# A random-looking token used to prove the strict audit catches leftovers that
# the structured redactor never traverses (see test_strict_* below).
PLANTED_SECRET = "Kx8fJ2mQ9pLwR4vT7nB6sZ3hG5dY1cW0aEuIoP5tN2"

# Secret values that live in the fixture and must NOT appear in the output.
COOKIE_VALUE = "8f9a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"
JWT_SIGNATURE = "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
EMAIL_VALUE = "jane.doe@example.com"
PAN_VALUE = "4111 1111 1111 1111"
STRIPE_KEY = "EXAMPLEapikey9f8e7d6c5b4a3f2e1d0cEFGH"


def load_fixture():
    with open(FIXTURE, "r", encoding="utf-8") as handle:
        return json.load(handle)


class HarRedactionTests(unittest.TestCase):
    def setUp(self):
        self.har = load_fixture()
        self.redactor = Redactor()
        self.redactor.redact_har(self.har)
        self.output = json.dumps(self.har)

    def test_output_is_still_valid_har_json(self):
        reparsed = json.loads(self.output)
        self.assertIn("log", reparsed)
        self.assertEqual(len(reparsed["log"]["entries"]), 1)
        # structural fields survive
        entry = reparsed["log"]["entries"][0]
        self.assertEqual(entry["request"]["method"], "POST")
        self.assertEqual(entry["response"]["status"], 200)

    def test_cookie_header_redacted(self):
        headers = {h["name"]: h["value"]
                   for h in self.har["log"]["entries"][0]["request"]["headers"]}
        self.assertNotIn(COOKIE_VALUE, headers["Cookie"])
        self.assertIn("<REDACTED:cookie>", headers["Cookie"])
        # cookie *names* are preserved so the request stays understandable
        self.assertIn("sessionid=", headers["Cookie"])
        self.assertIn("csrftoken=", headers["Cookie"])

    def test_authorization_bearer_redacted_scheme_preserved(self):
        headers = {h["name"]: h["value"]
                   for h in self.har["log"]["entries"][0]["request"]["headers"]}
        self.assertEqual(headers["Authorization"], "Bearer <REDACTED:bearer>")
        self.assertNotIn(JWT_SIGNATURE, self.output)

    def test_api_key_header_redacted(self):
        headers = {h["name"]: h["value"]
                   for h in self.har["log"]["entries"][0]["request"]["headers"]}
        self.assertEqual(headers["X-Api-Key"], "<REDACTED:apikey>")

    def test_email_in_body_redacted(self):
        body = self.har["log"]["entries"][0]["request"]["postData"]["text"]
        self.assertNotIn(EMAIL_VALUE, body)
        self.assertIn("<REDACTED:email>", body)

    def test_pan_in_body_redacted(self):
        body = self.har["log"]["entries"][0]["request"]["postData"]["text"]
        self.assertNotIn("4111", body)
        self.assertIn("<REDACTED:pan>", body)
        # non-sensitive content is preserved
        self.assertIn("please refund", body)

    def test_query_token_and_url_secret_redacted(self):
        url = self.har["log"]["entries"][0]["request"]["url"]
        self.assertNotIn(STRIPE_KEY, url)
        self.assertIn("<REDACTED:secret>", url)
        # non-sensitive query params are preserved
        self.assertIn("view=full", url)

    def test_response_email_redacted(self):
        text = self.har["log"]["entries"][0]["response"]["content"]["text"]
        self.assertNotIn("support@example.com", text)
        self.assertIn("<REDACTED:email>", text)

    def test_no_original_secret_survives_anywhere(self):
        for secret in (COOKIE_VALUE, JWT_SIGNATURE, EMAIL_VALUE, STRIPE_KEY,
                       "support@example.com", "renewed9a8b7c6d5e4f3a2b1c0d9e8f7a"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, self.output)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.redactor = Redactor()
        self.redactor.redact_har(load_fixture())
        self.report = self.redactor.report()

    def test_report_lists_expected_types(self):
        for expected in ("cookie", "bearer", "apikey", "email", "pan", "secret"):
            with self.subTest(type=expected):
                self.assertIn(expected, self.report["by_type"])

    def test_report_total_matches_items(self):
        self.assertEqual(self.report["total"], len(self.report["items"]))
        self.assertEqual(self.report["total"], sum(self.report["by_type"].values()))

    def test_report_records_locations(self):
        locations = [loc for _type, loc in self.report["items"]]
        self.assertTrue(any("headers[Authorization]" in loc for loc in locations))
        self.assertTrue(any("postData.text" in loc for loc in locations))

    def test_report_never_contains_secret_values(self):
        blob = json.dumps(self.report)
        for secret in (COOKIE_VALUE, JWT_SIGNATURE, EMAIL_VALUE, STRIPE_KEY):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, blob)


class StrictAuditTests(unittest.TestCase):
    def test_strict_passes_on_clean_output(self):
        redactor = Redactor()
        har = load_fixture()
        redactor.redact_har(har)
        output = json.dumps(har, indent=2)
        self.assertEqual(redactor.residual_secrets(output), [])

    def test_strict_fails_when_secret_missed(self):
        # Plant a high-entropy secret in a nonstandard field the structured
        # redactor does not traverse; the strict audit must still catch it.
        redactor = Redactor()
        har = load_fixture()
        har["log"]["_internalNote"] = "leftover=" + PLANTED_SECRET
        redactor.redact_har(har)
        output = json.dumps(har, indent=2)
        residual = redactor.residual_secrets(output)
        self.assertTrue(residual)
        # audit reports type + length only, never the value
        self.assertNotIn(PLANTED_SECRET, json.dumps(residual))

    def test_allow_list_suppresses_residual(self):
        config = build_config(allow=[PLANTED_SECRET])
        redactor = CoreRedactor(config)
        text = "leftover=" + PLANTED_SECRET
        self.assertEqual(redactor.residual_secrets(text), [])


class RawAndCurlTests(unittest.TestCase):
    def test_raw_request_redacted_and_structure_kept(self):
        raw = (
            "GET /account?token=EXAMPLEapikey9f8e7d6c5b4a3f2e1d0cEFGH HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "Cookie: sessionid=8f9a7b6c5d4e3f2a1b0c9d8e7f6a5b4c\r\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_abc\r\n"
            "\r\n"
            "{\"email\":\"jane.doe@example.com\"}"
        )
        out = Redactor().redact_raw(raw)
        self.assertIn("Host: api.example.com", out)  # request line/headers intact
        self.assertIn("GET /account?token=<REDACTED:secret> HTTP/1.1", out)
        self.assertIn("Cookie: sessionid=<REDACTED:cookie>", out)
        self.assertIn("Authorization: Bearer <REDACTED:bearer>", out)
        self.assertIn("<REDACTED:email>", out)
        self.assertNotIn("jane.doe@example.com", out)

    def test_curl_command_redacted_and_runnable(self):
        cmd = (
            "curl 'https://api.example.com/v2/account?access_token=EXAMPLEshortkey5a4b3c2d1e0f' "
            "-H 'Cookie: sessionid=8f9a7b6c5d4e3f2a1b0c9d8e7f6a5b4c' "
            "-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_abc' "
            "-u admin:s3cr3tPassw0rd "
            "--data '{\"email\":\"jane.doe@example.com\"}'"
        )
        out = Redactor().redact_curl(cmd)
        self.assertIn("<REDACTED:cookie>", out)
        self.assertIn("<REDACTED:bearer>", out)
        self.assertIn("<REDACTED:email>", out)
        self.assertIn("admin:<REDACTED:password>", out)
        self.assertNotIn("s3cr3tPassw0rd", out)
        self.assertNotIn("jane.doe@example.com", out)
        self.assertTrue(out.startswith("curl "))


if __name__ == "__main__":
    unittest.main()
