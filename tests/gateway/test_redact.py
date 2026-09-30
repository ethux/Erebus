"""Error redaction shared by the laptop catalog and the sync worker (spec 015 "Architecture").

Pure: ``erebus.cataloging.redact`` imports no store or config, masks emails, phones,
secret assignments, DSNs, conninfo keys, hosts and addresses and Postgres ``DETAIL``
lines; ``sanitize_log`` also masks every quoted literal (driver messages quote the
offending value). The laptop store keeps its ``sanitize_error`` name.
"""
import ast
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.cataloging import redact

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add("." * node.level + (node.module or ""))
    return names


def main():
    print("\n=== Error redaction (spec 015) ===\n")
    s = redact.sanitize_error
    check("keeps the laptop masking of emails and secrets",
          s("password=super-secret for jan@example.test") == "password=[REDACTED] for [EMAIL]")
    out = s("connection failed: postgresql://sync:Pw-9x@db.acme.example:5432/crm?sslmode=require")
    check("masks a DSN whole", "Pw-9x" not in out and "db.acme.example" not in out and "[DSN]" in out)
    out = s("invalid connection option host=db.acme.example user=sync dbname=crm port=5432")
    check("masks conninfo values", all(v not in out for v in ("db.acme.example", "=sync", "=crm", "5432")))
    out = s('connection to server at "db.acme.example" (10.1.2.3), port 5432 failed')
    check("masks a host name and an IPv4 address", "db.acme.example" not in out and "10.1.2.3" not in out)
    out = s("could not connect to fd00:1234::17 on port 3306")
    check("masks an IPv6 address", "fd00:1234::17" not in out)
    out = s('duplicate key value violates unique constraint "x"\nDETAIL:  Key (name)=(Zyx Qorbel) already exists.')
    check("masks a DETAIL line", "Zyx Qorbel" not in out and "DETAIL: [REDACTED]" in out)
    check("caps the length", len(s("x" * 2000)) <= 500)
    check("accepts an exception", s(ValueError("token=abc123")) == "token=[REDACTED]")

    log = redact.sanitize_log
    out = log('invalid input syntax for type integer: "Zyx Qorbel"')
    check("sanitize_log masks double-quoted literals", "Zyx Qorbel" not in out and '"[VALUE]"' in out)
    out = log("(1366, \"Incorrect string value: 'Qorbel' for column 'name'\")")
    check("sanitize_log masks single-quoted literals", "Qorbel" not in out)
    check("sanitize_log still applies sanitize_error", "[EMAIL]" in log("mail jan@example.test failed"))

    from erebus.cataloging import store
    check("the laptop store re-exports sanitize_error", store.sanitize_error is redact.sanitize_error)
    path = Path(redact.__file__)
    check("redact.py imports no store or config",
          not any(n.endswith(("store", "config")) or "gateway" in n for n in _imports(path)))
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
