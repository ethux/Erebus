"""Core regex patterns: whole PEM private-key blocks and checksum-valid IBANs.

Pure (stdlib only, no GLiNER). ``PRIVATE_KEY`` must cover the header, base64 body and
footer, including the PKCS#8 ``BEGIN PRIVATE KEY`` header, and the base64 lines after a
header with no footer. ``iban_spans`` must return
only mod-97-valid IBANs, compact or grouped in fours.
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from erebus.core.patterns import SECRET_PATTERNS, iban_spans

_passed = 0

_PKCS8 = ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7\n"
          "-----END PRIVATE KEY-----")
_RSA = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----"
_OPENSSH = ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n"
            "-----END OPENSSH PRIVATE KEY-----")
_ENCRYPTED = ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
              "DEK-Info: AES-128-CBC,3F17F5316E2BAC89\n\nMIIEowIBAAKCAQEA0Z3VS5JJ\n"
              "-----END RSA PRIVATE KEY-----")


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
    for name, pem in (("PKCS#8", _PKCS8), ("RSA", _RSA), ("OPENSSH", _OPENSSH),
                      ("encrypted RSA", _ENCRYPTED)):
        check(f"{name}: the whole PEM block is one PRIVATE_KEY match",
              _private_key_matches(f"key:\n{pem}\nthanks") == [pem])
    check("header without a footer still matches the header",
          _private_key_matches("-----BEGIN RSA PRIVATE KEY----- is here")
          == ["-----BEGIN RSA PRIVATE KEY-----"])
    head = "-----BEGIN PRIVATE KEY-----"
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7"
    check("no footer: the base64 lines after the header are part of the match",
          _private_key_matches(f"key:\n{head}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n")
          == [f"{head}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"])
    check("no footer: the body stops at the first line that is not base64",
          _private_key_matches(f"{head}\n{body}\nplease rotate it\nMIIE")
          == [f"{head}\n{body}"])
    check("no footer: CRLF and indented lines are taken too",
          _private_key_matches(f"  {head}\r\n  MIIEvQIBADANBg\r\n  BKcwggSjAgEA\r\nok?")
          == [f"{head}\r\n  MIIEvQIBADANBg\r\n  BKcwggSjAgEA"])
    check("no footer: an escaped PEM in a JSON or .env value is taken to its end",
          _private_key_matches(f'KEY="{head}\\nMIIEvQIBADANBg\\nBKcwggSjAgEA\\n"')
          == [f"{head}\\nMIIEvQIBADANBg\\nBKcwggSjAgEA"])
    encrypted = _ENCRYPTED.rsplit("\n", 1)[0]
    check("no footer: an encrypted key keeps its Proc-Type, DEK-Info and body",
          _private_key_matches(f"{encrypted}\n\nthat is all") == [encrypted])
    check("two blocks give two matches, the text between them untouched",
          _private_key_matches(f"{_PKCS8}\nand\n{_RSA}") == [_PKCS8, _RSA])
    check("a public key is not a private key",
          _private_key_matches("-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----") == [])
    # Many headers with no footer used to rescan to the end of the text per header
    # (quadratic, GIL held): 4000 took 3.3 s. Linear now takes a few milliseconds.
    for unit in ("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY----- x\n",
                 "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n",
                 "-----BEGIN PRIVATE KEY-----\n" + "A" * 64 + " x\n\n\n"):
        text = unit * 4000
        started = time.perf_counter()
        hits = _private_key_matches(text)
        elapsed = time.perf_counter() - started
        check(f"4000 footerless headers ({len(text) // 1000} KB) scan in {elapsed:.3f}s (< 0.5s)",
              elapsed < 0.5 and len(hits) == 4000)


def test_iban():
    check("compact NL IBAN", _ibans("Transfer to NL91ABNA0417164300 by Friday")
          == [("NL91ABNA0417164300", "IBAN")])
    for iban in ("NL91 ABNA 0417 1643 00", "DE89 3704 0044 0532 0130 00",
                 "FR14 2004 1010 0505 0001 3M02 606", "GB82 WEST 1234 5698 7654 32",
                 "BE68 5390 0754 7034"):
        check(f"grouped IBAN {iban[:4]}", _ibans(f"IBAN {iban}.") == [(iban, "IBAN")])
    check("a trailing all-caps word is not swallowed",
          _ibans("pay BE68 5390 0754 7034 BY Friday") == [("BE68 5390 0754 7034", "IBAN")])
    for text, iban in (("BETAAL AAN BE68 5390 0754 7034 VOOR DE HUUR", "BE68 5390 0754 7034"),
                       ("Pay ES91 2100 0418 4502 0005 1332 ASAP OK", "ES91 2100 0418 4502 0005 1332"),
                       ("BE68 5390 0754 7034 TEST DATA", "BE68 5390 0754 7034")):
        check(f"two swallowed trailing words are dropped: {text!r}", _ibans(text) == [(iban, "IBAN")])
    check("two grouped IBANs separated by one space are both found",
          _ibans("BE68 5390 0754 7034 BE68 5390 0754 7034")
          == [("BE68 5390 0754 7034", "IBAN"), ("BE68 5390 0754 7034", "IBAN")])
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
