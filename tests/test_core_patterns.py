"""Core regex patterns: whole PEM private-key blocks and checksum-valid IBANs.

Pure (stdlib only, no GLiNER). ``PRIVATE_KEY`` must cover the header, base64 body and
footer, including the PKCS#8 ``BEGIN PRIVATE KEY`` header. ``iban_spans`` must return
only mod-97-valid IBANs, compact or grouped in fours.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from erebus.core.patterns import SECRET_PATTERNS, iban_spans

_passed = 0

_PKCS8 = ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7\n"
          "-----END PRIVATE KEY-----")
_RSA = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----"
_OPENSSH = ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n"
            "-----END OPENSSH PRIVATE KEY-----")


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _private_key_matches(text):
    pattern = next(p for p, label in SECRET_PATTERNS if label == "PRIVATE_KEY")
    return [m.group(0) for m in re.finditer(pattern, text)]


def _ibans(text):
    return [(text[s:e], label) for s, e, label in iban_spans(text)]


def test_private_key():
    for name, pem in (("PKCS#8", _PKCS8), ("RSA", _RSA), ("OPENSSH", _OPENSSH)):
        check(f"{name}: the whole PEM block is one PRIVATE_KEY match",
              _private_key_matches(f"key:\n{pem}\nthanks") == [pem])
    check("header without a footer still matches the header",
          _private_key_matches("-----BEGIN RSA PRIVATE KEY----- is here")
          == ["-----BEGIN RSA PRIVATE KEY-----"])
    check("two blocks give two matches, the text between them untouched",
          _private_key_matches(f"{_PKCS8}\nand\n{_RSA}") == [_PKCS8, _RSA])
    check("a public key is not a private key",
          _private_key_matches("-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----") == [])


def test_iban():
    check("compact NL IBAN", _ibans("Transfer to NL91ABNA0417164300 by Friday")
          == [("NL91ABNA0417164300", "IBAN")])
    for iban in ("NL91 ABNA 0417 1643 00", "DE89 3704 0044 0532 0130 00",
                 "FR14 2004 1010 0505 0001 3M02 606", "GB82 WEST 1234 5698 7654 32",
                 "BE68 5390 0754 7034"):
        check(f"grouped IBAN {iban[:4]}", _ibans(f"IBAN {iban}.") == [(iban, "IBAN")])
    check("a trailing all-caps word is not swallowed",
          _ibans("pay BE68 5390 0754 7034 BY Friday") == [("BE68 5390 0754 7034", "IBAN")])
    check("a bad checksum is not an IBAN", _ibans("NL00ABNA0417164300") == [])
    check("an uppercase sha256 is not an IBAN",
          _ibans("AB12" + "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B78") == [])
    check("an IBAN glued inside a longer word is not matched",
          _ibans("xNL91ABNA0417164300") == [] and _ibans("NL91ABNA0417164300x") == [])
    check("two IBANs give two spans in order",
          [s for s, _e, _l in iban_spans("NL91ABNA0417164300 / DE89370400440532013000")] == [0, 21])
    check("no IBAN in clean text", iban_spans("nothing to see here") == [])


def main():
    print("\n=== Core patterns: PEM blocks and IBANs ===\n")
    test_private_key()
    test_iban()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
