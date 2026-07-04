# Contributing to DataGuard Fortress

Thank you for your interest in DataGuard Fortress! We welcome contributions from the community.

## How to Contribute

1. **Fork** the repository on GitHub
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
3. **Make your changes** following the guidelines below
4. **Run the tests** to ensure nothing is broken:
   ```bash
   pip install -e ".[dev]"
   pytest tests/
   ```
5. **Run the linter** to ensure code quality:
   ```bash
   ruff check src/ tests/
   ruff format --check src/ tests/
   ```
6. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add new PII preset for phone numbers
   fix: correct rate limiter overflow condition
   docs: update API documentation
   ```
7. **Push** and open a Pull Request

## Development Setup

```bash
git clone https://github.com/RVRNM/dataguard-fortress.git
cd dataguard-fortress
pip install -e ".[dev]"
```

## Code Quality Expectations

- All tests must pass before merging
- Ruff linting and formatting must be clean
- Type annotations are required for all public APIs
- New features must include tests
- Security-related changes must include a note in the PR description

## Pull Request Process

1. Ensure your PR description clearly describes the problem and solution
2. Add or update tests as needed
3. Update documentation (README, docstrings) if the API changes
4. Request review from a maintainer
5. Address any review feedback

## Reporting Issues

- **Bug reports:** Include the version, configuration, steps to reproduce, and expected vs actual behavior
- **Feature requests:** Describe the use case and proposed solution
- **Security issues:** See [SECURITY.md](SECURITY.md) for responsible disclosure

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 license.
