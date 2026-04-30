"""
Measure PII detection quality across different pipeline configurations.

Reads a labeled corpus (by default ~/.erebus/benchmark/corpus.jsonl) and
runs each example through:

  * GLiNER + regex + blacklist       (baseline)
  * baseline + piiranha              (small CPU NER)
  * baseline + openai-pf             (large GPU NER)
  * baseline + gemma                 (LLM contextual, layers on top)
  * baseline + piiranha + gemma      (CPU NER + contextual)
  * baseline + openai-pf + gemma     (GPU NER + contextual)

Only one NER verifier runs at a time, so 'piiranha + openai-pf' is not
a valid combination since they overlap in purpose.

Reports recall, precision, F1, and p50/p95 latency per configuration.

Corpus format (one JSON object per line):
    {
      "text": "Contact Jan Jansen at jan@example.com",
      "expected": ["Jan Jansen", "jan@example.com"]
    }

The corpus path lives outside the repo on purpose - it usually contains
real PII or domain-specific identifiers the user doesn't want checked in.
"""
import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from .config import ensure_erebus_dir
from .filter import tokenize

DEFAULT_CORPUS_PATH = Path.home() / ".erebus" / "benchmark" / "corpus.jsonl"


def _load_corpus(path: Path) -> list[dict]:
    cases = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise SystemExit(f"{path}:{i}: invalid JSON - {e}")
        if "text" not in obj or "expected" not in obj:
            raise SystemExit(f"{path}:{i}: missing 'text' or 'expected' field")
        cases.append(obj)
    return cases


def _score(expected: list[str], tokens_map: dict) -> tuple[int, int, int]:
    """Return (tp, fp, fn) counts for a single example.

    tp: expected span that ended up in the token map (case-insensitive match)
    fn: expected span that wasn't tokenized
    fp: tokenized value not in the expected set
    """
    expected_lower = {e.strip().lower() for e in expected if e.strip()}
    detected_lower = {v.strip().lower() for v in tokens_map.values()}
    tp = len(expected_lower & detected_lower)
    fn = len(expected_lower - detected_lower)
    fp = len(detected_lower - expected_lower)
    return tp, fp, fn


def _run_config(cases: list[dict], verifiers: list[str], llm_model: str) -> dict:
    """Run every case through `tokenize` and tally scores + latencies."""
    latencies = []
    tp = fp = fn = 0
    for case in cases:
        t0 = time.perf_counter()
        _sanitized, tokens = tokenize(
            case["text"],
            verifiers=verifiers,
            verifier_llm_model=llm_model,
        )
        latencies.append((time.perf_counter() - t0) * 1000)
        a, b, c = _score(case["expected"], tokens)
        tp += a
        fp += b
        fn += c

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    latencies.sort()
    def pct(p):
        if not latencies:
            return 0.0
        i = max(0, min(len(latencies) - 1, int(len(latencies) * p) - 1))
        return latencies[i]
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "p50_ms": pct(0.50), "p95_ms": pct(0.95),
        "mean_ms": statistics.mean(latencies) if latencies else 0.0,
    }


def _print_row(name: str, r: dict):
    print(
        f"  {name:<32}"
        f"  R={r['recall']:.2f}  P={r['precision']:.2f}  F1={r['f1']:.2f}"
        f"   p50={r['p50_ms']:>6.0f}ms  p95={r['p95_ms']:>6.0f}ms"
        f"   tp={r['tp']}  fp={r['fp']}  fn={r['fn']}"
    )


def _seed_corpus(path: Path):
    """Write a tiny example corpus so first-run users have something to work with."""
    ensure_erebus_dir()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        print(f"Corpus already exists at {path}")
        return
    sample = [
        {"text": "Please email jan.jansen@example.com about the deal.",
         "expected": ["jan.jansen@example.com"]},
        {"text": "Call Maria Rodriguez tomorrow at +31 6 12345678.",
         "expected": ["Maria Rodriguez", "+31 6 12345678"]},
        {"text": "The engineer who runs the Rotterdam office is responsible.",
         "expected": ["the engineer who runs the Rotterdam office"]},
        {"text": "IBAN NL91ABNA0417164300, route via compliance.",
         "expected": ["NL91ABNA0417164300"]},
        {"text": "Nothing sensitive in this message at all.",
         "expected": []},
    ]
    path.write_text("\n".join(json.dumps(s) for s in sample) + "\n", encoding="utf-8")
    print(f"Seeded {len(sample)} example cases at {path}")
    print("Edit it with your own labeled data (one JSON object per line).")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="erebus-benchmark",
        description="Measure PII detection across pipeline configurations.",
    )
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS_PATH,
                        help=f"path to labeled corpus (default: {DEFAULT_CORPUS_PATH})")
    parser.add_argument("--llm-model", default="gemma3:1b",
                        help="Ollama tag for the LLM verifier (default: gemma3:1b)")
    parser.add_argument("--only", default=None,
                        help="run a single config: baseline, piiranha, openai-pf, gemma, piiranha+gemma, openai-pf+gemma")
    parser.add_argument("--seed", action="store_true",
                        help="write a tiny example corpus to the default path and exit")
    args = parser.parse_args()

    if args.seed:
        _seed_corpus(args.corpus)
        return 0

    if not args.corpus.exists():
        print(f"No corpus at {args.corpus}. Run `erebus-benchmark --seed` to create one.")
        return 1

    cases = _load_corpus(args.corpus)
    if not cases:
        print("Corpus is empty.")
        return 1

    configs = [
        ("baseline (GLiNER+regex+blacklist)", []),
        ("+ piiranha", ["piiranha"]),
        ("+ openai-pf", ["openai-pf"]),
        ("+ gemma", ["gemma"]),
        ("+ piiranha + gemma", ["piiranha", "gemma"]),
        ("+ openai-pf + gemma", ["openai-pf", "gemma"]),
    ]
    if args.only:
        wanted = args.only.lower()
        name_map = {
            "baseline": "baseline (GLiNER+regex+blacklist)",
            "piiranha": "+ piiranha",
            "openai-pf": "+ openai-pf",
            "gemma": "+ gemma",
            "piiranha+gemma": "+ piiranha + gemma",
            "openai-pf+gemma": "+ openai-pf + gemma",
        }
        target = name_map.get(wanted)
        if not target:
            print(f"Unknown --only value: {wanted}")
            return 1
        configs = [(n, v) for n, v in configs if n == target]

    print(f"\nerebus-benchmark: {len(cases)} cases from {args.corpus}")
    print("-" * 70)
    for name, verifiers in configs:
        res = _run_config(cases, verifiers, args.llm_model)
        _print_row(name, res)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
