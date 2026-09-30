"""The laptop catalog rule set is unchanged by the move into field_rules (spec 015 D2, SC-10).

``fixtures/laptop_field_rules_golden.json`` was generated from ``erebus/cataloging/scan.py``
before the rules moved: every field name x connector hint x sample value the editor scan
can see, with the category, confidence and reason it produced. The pure module and the
scan entry points must still give exactly those outputs. Pure: no store, no model.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.cataloging import field_rules, scan

_GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "laptop_field_rules_golden.json")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _enc(out):
    return "|".join("" if x is None else str(x) for x in out)


def _mismatches(golden, category_fn, classify_fn):
    outputs = golden["outputs"]
    bad = []
    for fi, f in enumerate(golden["fields"]):
        for hi, h in enumerate(golden["hints"]):
            if _enc(category_fn(f, h)) != outputs[golden["category_from_field"][fi][hi]]:
                bad.append(("category", f, h))
            for vi, v in enumerate(golden["values"]):
                if _enc(classify_fn(f, v, h)) != outputs[golden["classify_value"][fi][hi][vi]]:
                    bad.append(("classify", f, h, v))
    return bad


def main():
    print("\n=== Laptop field rules golden (spec 015 D2, SC-10) ===\n")
    with open(_GOLDEN, encoding="utf-8") as fh:
        golden = json.load(fh)
    cases = len(golden["fields"]) * len(golden["hints"]) * (len(golden["values"]) + 1)
    check(f"the golden covers {cases} cases", cases > 10000)
    check("the role table is unchanged", golden["role_to_category"] == field_rules.LAPTOP_ROLE_TO_CATEGORY)
    check("the model label table is unchanged", golden["label_to_category"] == field_rules.LAPTOP_LABEL_TO_CATEGORY)
    bad = _mismatches(golden, field_rules.laptop_category_from_field, field_rules.laptop_classify_value)
    check("field_rules gives the golden output for every case", not bad)
    bad = _mismatches(golden, scan._category_from_field, scan.classify_value)
    check("the editor scan gives the golden output for every case", not bad)
    check("the editor scan uses the pure module's rules", scan.classify_value is field_rules.laptop_classify_value)
    check("the gateway labels never reach the laptop role table",
          "organization" not in field_rules.LAPTOP_ROLE_TO_CATEGORY)
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
