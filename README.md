# har-sanitizer

[![tests](https://github.com/kubakozub/har-sanitizer/actions/workflows/tests.yml/badge.svg)](https://github.com/kubakozub/har-sanitizer/actions/workflows/tests.yml)

**Redact secrets and PII from HTTP evidence before you attach it to a bug report.**

`har-sanitizer` takes the HTTP proof you want to include in a HackerOne /
Bugcrowd write-up — a HAR export, a raw request/response, or a `curl` command —
and replaces session tokens, credentials, API keys, and customer PII with clear
`<REDACTED:...>` placeholders. It keeps enough structure that the request stays
understandable and reproducible, so your report is still convincing without
leaking **your** session or the **target's** customer data.

- **Zero dependencies.** Pure Python 3.9+ standard library.
- **Fully offline.** No network, no telemetry, nothing phones home.
- **Fail-closed.** `--strict` exits non-zero if a high-entropy secret survives.

---

## Why this matters

A HAR captured from your browser or proxy is a *complete* recording of a
session. Pasted into a report unedited, it routinely leaks:

- **Your own session** — `Cookie`, `Authorization: Bearer …`, CSRF tokens.
  Anyone who reads the report (triager, program staff, later an attacker if the
  report is disclosed) can replay your authenticated session.
- **The target's customer data** — emails, phone numbers, and full card
  numbers (PANs) sitting in request/response bodies. Handing that to a third
  party can turn your finding into a **privacy incident you caused**.
- **Live credentials** — API keys, AWS access keys, and other high-entropy
  secrets embedded in URLs, headers, and JSON.

Redacting by hand is error-prone and easy to forget under deadline. This tool
makes "scrub the evidence" a single, repeatable, fail-closed step.

---

## Install

```bash
# From a checkout
pip install .

# Or run straight from source, no install required
python -m har_sanitizer clean --help
```

Because it is standard-library only, you can also just copy the `har_sanitizer/`
folder next to your scripts.

---

## Quick start

```bash
# Clean a HAR export from Burp / Chrome DevTools
har-sanitizer clean --input capture.har -o capture.clean.har

# See exactly what was removed (report goes to stderr)
har-sanitizer clean --input capture.har -o capture.clean.har --report

# Fail-closed: non-zero exit if any secret slips through
har-sanitizer clean --input capture.har -o capture.clean.har --strict

# Sanitize a curl command copied from DevTools ("Copy as cURL")
har-sanitizer clean --curl "curl 'https://api…' -H 'Cookie: …'"

# Sanitize a raw request/response on stdin
pbpaste | har-sanitizer clean --raw
```

Input type is auto-detected: JSON with a `log` object → HAR, text beginning with
`curl ` → curl, otherwise raw HTTP. `--raw` / `--curl` / `--input` force it.

---

## Before / after

**curl** (structure preserved — the command still runs):

```text
# before
curl 'https://api.acme.com/v2/me?access_token=EXAMPLEapikey9f8e7d6c5b4a3f2e1d0c' \
  -H 'Cookie: sessionid=8f9a7b6c5d4e3f2a1b0c9d8e7f6a; csrftoken=Zm9vYmFyQ1NSRg' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4' \
  --data '{"email":"jane.doe@example.com","card":"4111 1111 1111 1111"}'

# after
curl 'https://api.acme.com/v2/me?access_token=<REDACTED:secret>' \
  -H 'Cookie: sessionid=<REDACTED:cookie>; csrftoken=<REDACTED:cookie>' \
  -H 'Authorization: Bearer <REDACTED:bearer>' \
  --data '{"email":"<REDACTED:email>","card":"<REDACTED:pan>"}'
```

**raw HTTP** (headers, method, and path shape all survive):

```text
# before
GET /account?api_key=EXAMPLEapikey9f8e7d6c5b4a3f2e1d0c HTTP/1.1
Host: api.acme.com
Cookie: sessionid=8f9a7b6c5d4e3f2a1b0c9d8e7f6a5b4c
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmNHl0

{"email":"jane.doe@example.com"}

# after
GET /account?api_key=<REDACTED:secret> HTTP/1.1
Host: api.acme.com
Cookie: sessionid=<REDACTED:cookie>
Authorization: Bearer <REDACTED:bearer>

{"email":"<REDACTED:email>"}
```

Note how names and non-secret values are kept (`sessionid=`, `csrftoken=`,
`Bearer`, `view=full`, the JSON keys) so a reviewer can still follow the
request — only the sensitive values are gone.

---

## What it detects

**Headers** (value replaced, name/scheme kept where useful):

| Header | Handling |
| --- | --- |
| `Cookie` | each cookie value → `<REDACTED:cookie>`, names kept |
| `Set-Cookie` | value redacted, attributes (`Path`, `HttpOnly`, …) kept |
| `Authorization`, `Proxy-Authorization` | scheme kept (`Bearer`/`Basic`), credential redacted |
| `X-Api-Key`, `Api-Key`, `X-CSRF-Token`, `X-XSRF-Token`, … | value → `<REDACTED:apikey>` / `<REDACTED:csrf>` |
| `Referer`, `Location`, `Content-Location` | treated as URLs; query secrets redacted |
| any name in your custom deny-list | value → `<REDACTED:secret>` |

**Values** (in URLs, query strings, bodies, and non-sensitive header values):

- **Bearer / JWT tokens** — `eyJ….eyJ….sig`
- **AWS access keys** — `AKIA…` / `ASIA…`
- **Generic high-entropy secrets** — long base64/hex tokens over a Shannon
  entropy threshold (session ids, API keys, signing secrets)
- **URL user-info credentials** — `https://user:pass@host` → password redacted
- **Sensitive query/form fields** — `token`, `password`, `api_key`, `secret`,
  `code`, `otp`, … (configurable)
- **Emails**
- **Phone numbers** — conservative: needs `+` country code or clear separators
- **Payment cards (PANs)** — 13–19 digits **gated by a Luhn checksum** to cut
  false positives
- **IP addresses** — opt-in via `--redact-ips`

---

## Modes

### `--report`
Prints a summary of *what* was redacted — type and location, **never the
value** — to stderr, so stdout stays a clean, pipeable artifact.

```text
redaction report
  total redactions: 12
  by type:
    apikey       1
    bearer       1
    cookie       5
    email        2
    pan          1
    secret       2
  locations:
    [bearer] log.entries[0].request.headers[Authorization]
    [email]  log.entries[0].request.postData.text
    [pan]    log.entries[0].request.postData.text
    …
```

### `--strict` (fail-closed)
After redaction, `har-sanitizer` re-scans the **entire produced artifact** for
any residual high-entropy token, leftover JWT, or AWS key. If it finds one it
prints the type and length (never the value) and exits non-zero:

```text
STRICT FAIL: 1 residual high-entropy token(s) remain after redaction (fail-closed).
  - high-entropy (length 42)
```

This is a deliberate safety net. The structured redactor scrubs the known
fields of each format; `--strict` catches anything hiding in a place it didn't
traverse (a nonstandard HAR extension field, an odd body encoding, …). Wire it
into a pre-submit check:

```bash
har-sanitizer clean -i capture.har -o capture.clean.har --strict || {
  echo "Refusing to ship: evidence still contains a secret." >&2
  exit 1
}
```

---

## Customization

Add header/parameter names, extra regexes, and an allow-list — via flags:

```bash
har-sanitizer clean -i in.har -o out.har \
  --add-header X-Internal-Trace \
  --add-param  employee_id \
  --add-pattern 'internal-id=INT-\d{6}' \
  --allow 'AKIAEXAMPLE[A-Z0-9]+' \
  --redact-ips
```

…or with a JSON config file (`--config rules.json`):

```json
{
  "sensitive_headers": ["x-internal-trace"],
  "sensitive_params": ["employee_id"],
  "extra_patterns": [{ "name": "internal-id", "regex": "INT-\\d{6}" }],
  "allow": ["AKIAEXAMPLE[A-Z0-9]+"],
  "redact_ips": true,
  "entropy": { "base64": 4.0, "hex": 3.0, "min_len": 20 }
}
```

CLI flags take precedence over the file; both extend the built-in defaults.
Values matching an `--allow` pattern are left untouched (useful for well-known
public test keys you *want* to keep in the report).

---

## Use as a library

```python
from har_sanitizer import Redactor

redactor = Redactor()
clean = redactor.redact_curl("curl https://ex.com -H 'Cookie: s=secret'")
print(clean)                       # curl https://ex.com -H 'Cookie: s=<REDACTED:cookie>'
print(redactor.report()["by_type"])  # {'cookie': 1}
print(redactor.residual_secrets(clean))  # [] -> passes the strict audit
```

---

## Limitations

Redaction is **best-effort pattern matching, not a guarantee.** Always eyeball
the output before you attach it.

- Detection is heuristic. High-entropy detection can miss a short or
  low-entropy secret, and can over-redact an innocent long token. Phone
  detection is intentionally conservative and will miss unusual formats.
- The tool does not decode or scrub secrets hidden inside base64 blobs,
  compressed bodies, or binary content beyond treating them as opaque text.
- It redacts values in the fields it understands; genuinely custom/nonstandard
  fields are only covered by the `--strict` full-text audit.
- Preserved structure (cookie names, auth scheme, JSON keys, non-sensitive
  params) is deliberate — review it to be sure none of *those* are sensitive in
  your specific target.

When in doubt, redact more, and read the diff.

---

## Responsible disclosure

This tool exists to make **responsible** disclosure easier. Share only the
minimum evidence needed to reproduce a bug, never real customer data or live
credentials, and follow the scope and rules of the program you are reporting to.
Sanitize first; ship second.

---

## Development

```bash
python -m unittest discover      # run the test suite (stdlib unittest, no deps)
```

## License

[MIT](LICENSE) © 2026 Jakub Kozub
