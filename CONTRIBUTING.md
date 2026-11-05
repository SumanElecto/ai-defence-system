# Contributing

## Setup

Use Python 3.13 through 3.15.2. Install the pinned dependencies and run the test suite from the repository root:

```bash
python -m pip install -r requirements.txt
python -m pytest -v
```

Provider tests use mocks and do not require API credentials. Do not put credentials, real personal data, or sensitive prompts in source, tests, issues, or pull requests.

## Security-Sensitive Changes

- Keep trusted requests and untrusted external content separate throughout analysis and model calls.
- Preserve fail-closed behavior, explicit tool allowlists, per-call approval, and argument validation.
- Treat model output, tool output, and dataset prompts as untrusted data.
- Do not tune detection behavior against `data/cyber_intent_holdout.csv`; use the documented evaluator only for final evaluation.
- Add or update focused tests for behavior changes, then run the full suite before opening a pull request.

For vulnerability reports, follow [SECURITY.md](SECURITY.md) rather than opening a public issue with sensitive details.
