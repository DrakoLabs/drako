# Contributing to Drako

Thank you for your interest in contributing to Drako! We are building a local-first, deterministic Authority Kernel for AI Agents, and community contributions are welcome across the kernel, protocol guards, framework adapters, static rules, and documentation.

## License

By contributing to Drako, you agree that your contributions will be licensed under the [Apache License 2.0 (Apache-2.0)](LICENSE).

## How to Contribute

1. **Report Bugs**: Use our [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md) to report reproducible issues.
2. **Suggest Features**: Propose new static rules, protocol guards, or framework adapters using the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md).
3. **Submit Pull Requests**: Bug fixes, new rules, conformance tests, documentation updates, and framework adapters are all welcome.

## Development Setup

We recommend Python 3.10+ and an isolated virtual environment.

```bash
git clone https://github.com/DrakoLabs/drako.git
cd drako
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,proxy,typescript]"
```

## Running Tests & Verification

All pull requests must pass the offline test suite and linter with zero warnings:

```bash
pytest tests/ -q
ruff check src/ tests/
```

For `AGENT-HOOKS-0.1` conformance testing (optional `[guardian]` extra):

```bash
pip install -e ".[dev,guardian]"
pytest tests/test_kernel_ctk.py -v
```

## Submitting a Pull Request

1. Fork the repository.
2. Create a focused branch (`git checkout -b fix/my-change` or `git checkout -b feat/my-feature`).
3. Ensure tests and `ruff check src/ tests/` pass cleanly.
4. Push to your branch and open a Pull Request describing the motivation, changes, and verification steps.

## Adding New Static Rules

If you are contributing a new rule to the offline scanner:
- Place Python rule logic under `src/drako/cli/policies/` (or TypeScript rules under `src/drako/cli/policies/typescript/`).
- Include standard rule metadata (`policy_id`, `category`, `severity`, `title`, `impact`, `attack_scenario`, `references`, and a runnable v4 `fix_snippet`).
- Add `vulnerable.py` and `safe.py` fixtures under `tests/fixtures/rules/<RULE-ID>/` and verify with `pytest tests/test_rule_fixtures.py`.
- Keep `docs/rules/index.md` and `README.md` rule counts aligned (`pytest tests/test_docs_census.py`).
