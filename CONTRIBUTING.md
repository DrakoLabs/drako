# Contributing to AgentMesh

Thank you for your interest in contributing to AgentMesh! We are building the foundational Trust Layer for AI Agents, and community contributions are essential to strengthening our governance platform.

## License

By contributing to AgentMesh, you agree that your contributions will be licensed under the [Business Source License 1.1 (BUSL-1.1)](LICENSE). This means your code is source-available: anyone can view it and use it, but no one can offer a competing commercial hosted service based on it. After 4 years, each version converts to Apache 2.0.

## How to Contribute

1. **Report Bugs**: Use our [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md) to report reproducible issues.
2. **Suggest Features**: Help us map out new compliance standards or governance policies using the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md).
3. **Submit Pull Requests**: All PRs are welcome! Bug fixes, new policies, documentation updates, or framework integrations.

## Development Setup

We recommend using Python 3.10+ and a virtual environment.

```bash
git clone https://github.com/angelnicolasc/agentmesh.git
cd agentmesh
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

## Running Tests

We maintain a strict testing culture. All PRs must pass the test suite:

```bash
pytest
```

## Submitting a Pull Request

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/amazing-policy`).
3. Commit your changes.
4. Push to your branch (`git push origin feature/amazing-policy`).
5. Open a Pull Request and describe the changes in detail.

## Adding New Policies

If you are contributing a new policy to the Policy Engine:
- Ensure the policy logic goes into `src/agentmesh/cli/policies/`.
- Include standard policy metadata (ID, severity, description).
- Explain any EU AI Act mappings the policy fulfills.
- Add corresponding unit tests.

Welcome aboard! 🛡️
