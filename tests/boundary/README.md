# Boundary gateway tests

These tests ARE the privacy contract (spec FR-009/FR-010). One module per channel;
every phase of the 004 restructure must add or update the tests for the boundary
surface it touches.

## Two non-negotiable assertion rules

1. **Assert only on real-world artifacts** — disk bytes, executed command arguments,
   DB rows, exported files. NEVER assert on the model-side view of content: an AI
   operator (or a test reading a sanitized payload) structurally cannot tell a leaked
   real value from a token. Use the artifact assertions in `helpers.py`.

2. **Fixture tokens are synthetic** — token-shaped strings in these tests must never
   be live-map tokens or real values. Mint through a temp-scope DB or use obviously
   fake suffixes. Never "fix" a fixture by replacing it with a value from a real
   token map.

## Mutation spot-checks (SC-007 evidence)

| Comment out (wiring) | Must fail |
|----------------------|-----------|
| (filled in as phases land — see tasks.md T035) | |
