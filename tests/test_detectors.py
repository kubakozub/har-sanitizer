"""Unit tests for the low-level detectors (entropy, Luhn, patterns)."""

import unittest

from har_sanitizer import detectors


class ShannonEntropyTests(unittest.TestCase):
    def test_empty_string_is_zero(self):
        self.assertEqual(detectors.shannon_entropy(""), 0.0)

    def test_single_symbol_is_zero(self):
        self.assertEqual(detectors.shannon_entropy("aaaaaa"), 0.0)

    def test_two_equiprobable_symbols_is_one_bit(self):
        self.assertAlmostEqual(detectors.shannon_entropy("ab"), 1.0)
        self.assertAlmostEqual(detectors.shannon_entropy("aabb"), 1.0)

    def test_four_equiprobable_symbols_is_two_bits(self):
        self.assertAlmostEqual(detectors.shannon_entropy("abcd"), 2.0)

    def test_random_hex_is_high(self):
        self.assertGreater(
            detectors.shannon_entropy("8f9a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"), 3.0)


class HighEntropyTests(unittest.TestCase):
    def test_random_token_flagged(self):
        self.assertTrue(
            detectors.is_high_entropy("Kx8fJ2mQ9pLwR4vT7nB6sZ3hG5dY1cW0aEuIoP5tN2"))

    def test_short_token_not_flagged(self):
        self.assertFalse(detectors.is_high_entropy("shorttoken"))

    def test_repetitive_long_token_not_flagged(self):
        self.assertFalse(detectors.is_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

    def test_words_with_spaces_not_flagged(self):
        # candidate scanner never crosses the space, so no span qualifies
        self.assertEqual(
            detectors.find_high_entropy("the quick brown fox jumps over it"), [])

    def test_finds_span_of_embedded_secret(self):
        secret = "Kx8fJ2mQ9pLwR4vT7nB6sZ3hG5dY1cW0aEuIoP5tN2"
        text = "prefix " + secret + " suffix"
        spans = detectors.find_high_entropy(text)
        self.assertEqual(len(spans), 1)
        start, end = spans[0]
        self.assertEqual(text[start:end], secret)


class LuhnTests(unittest.TestCase):
    def test_valid_visa(self):
        self.assertTrue(detectors.luhn_valid("4111111111111111"))

    def test_valid_with_separators(self):
        self.assertTrue(detectors.luhn_valid("4111 1111 1111 1111"))
        self.assertTrue(detectors.luhn_valid("4111-1111-1111-1111"))

    def test_invalid_checksum(self):
        self.assertFalse(detectors.luhn_valid("4111111111111121"))
        self.assertFalse(detectors.luhn_valid("1234567890123456"))

    def test_too_short_rejected(self):
        self.assertFalse(detectors.luhn_valid("123"))

    def test_find_pans_only_returns_valid(self):
        text = "good 4111 1111 1111 1111 bad 1234 5678 9012 3456"
        spans = detectors.find_pans(text)
        self.assertEqual(len(spans), 1)
        start, end = spans[0]
        self.assertEqual(text[start:end], "4111 1111 1111 1111")


class PatternTests(unittest.TestCase):
    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF123_-x"
        spans = detectors.find_jwts("token=" + jwt + ";")
        self.assertEqual(len(spans), 1)

    def test_aws_access_key(self):
        self.assertEqual(len(detectors.find_aws_keys("AKIAIOSFODNN7EXAMPLE")), 1)
        self.assertEqual(len(detectors.find_aws_keys("ASIAY34FZKBOKMYRLENK")), 1)
        self.assertEqual(len(detectors.find_aws_keys("not a key AKIA123")), 0)

    def test_email(self):
        spans = detectors.find_emails("mail jane.doe@example.co.uk now")
        self.assertEqual(len(spans), 1)

    def test_phone_formats_detected(self):
        for number in ["+1 415 555 2671", "(415) 555-2671", "415-555-2671",
                       "+44 20 7946 0958"]:
            with self.subTest(number=number):
                self.assertTrue(detectors.find_phones("call " + number + " ok"))

    def test_date_not_detected_as_phone(self):
        self.assertEqual(detectors.find_phones("on 2026-08-16 at noon"), [])

    def test_ipv4_validated(self):
        self.assertEqual(len(detectors.find_ips("host 192.168.1.1 up")), 1)
        self.assertEqual(len(detectors.find_ips("bad 999.999.1.1 nope")), 0)


if __name__ == "__main__":
    unittest.main()
