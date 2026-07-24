"""Unit tests for the gateway per-scope crypto core (T005/T013/T014).

Verifies the isolation/erase/rotation guarantees the whole design leans on, with
no Postgres or network:
  SC-003 - same value tokenizes to non-correlatable handles across scopes
  SC-004 - one scope cannot decrypt another scope's ciphertext
  SC-008 - KEK rotation preserves restore; crypto-erase makes data unrecoverable
  FR-040 - crypto-erase
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway.crypto.envelope import ScopeCrypto
from erebus.gateway.crypto.keyprovider import CryptoErased, LocalKms

_passed = 0


def check(name: str, cond: bool) -> None:
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def raises(fn) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


def main() -> None:
    print("\n=== Gateway per-scope crypto (T005/T013/T014) ===\n")

    kms = LocalKms()
    a, a_wrapped = ScopeCrypto.create(kms, "org1/payments/oncall")
    b, _ = ScopeCrypto.create(kms, "org1/payments/billing")

    # Round trip within a scope.
    nonce, ct = a.encrypt(b"Jan Modaal")
    check("round-trip decrypt returns plaintext", a.decrypt(nonce, ct) == b"Jan Modaal")

    # SC-004: another scope cannot decrypt scope A's ciphertext.
    check("cross-scope decrypt fails (SC-004)", raises(lambda: b.decrypt(nonce, ct)))

    # KMS-level isolation: scope B's KEK cannot unwrap scope A's wrapped DEK.
    check("cross-scope DEK unwrap refused", raises(lambda: kms.unwrap_dek("org1/payments/billing", a_wrapped)))

    # SC-003: same value -> same handle in one scope, different handle across scopes.
    check("blind index is stable within a scope", a.blind_index("Acme BV") == a.blind_index("Acme BV"))
    check("blind index folds casing/whitespace", a.blind_index("Acme BV") == a.blind_index("  acme   bv "))
    check("blind index differs across scopes (SC-003)", a.blind_index("Acme BV") != b.blind_index("Acme BV"))
    check("blind index differs for different values", a.blind_index("Acme BV") != a.blind_index("Globex"))

    # SC-008: KEK rotation preserves restore of previously wrapped DEKs.
    kms.rotate_kek("org1/payments/oncall")
    a_reopened = ScopeCrypto.open(kms, "org1/payments/oncall", a_wrapped)
    check("prior data still decrypts after KEK rotation (SC-008)", a_reopened.decrypt(nonce, ct) == b"Jan Modaal")

    # FR-040: crypto-erase makes the scope's data permanently unrecoverable.
    kms.destroy_kek("org1/payments/oncall")
    check("crypto-erase blocks reopen (FR-040)",
          raises(lambda: ScopeCrypto.open(kms, "org1/payments/oncall", a_wrapped)))
    check("crypto-erase raises CryptoErased",
          isinstance(_capture(lambda: kms.unwrap_dek("org1/payments/oncall", a_wrapped)), CryptoErased))
    # Other scopes remain unaffected by another scope's erase.
    check("other scope unaffected by erase", b.decrypt(*b.encrypt(b"x")) == b"x")

    print(f"\n{_passed}/{_passed} passed\n")


def _capture(fn):
    try:
        fn()
    except Exception as exc:
        return exc
    return None


if __name__ == "__main__":
    main()
