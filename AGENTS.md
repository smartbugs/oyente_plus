# Repository Guidelines

This guide aligns with CLAUDE.md and describes how to work in this repo efficiently and safely.

## Project Structure & Module Organization
- `oyente/`: Core analyzer (CLI in `oyente/oyente.py`, symexec, detectors, helpers).
- `tests/`: Unit, integration, property, performance tests; fixtures and mocks.
- `samples/`: Reference bytecode/contracts for manual checks.
- `docs/`: Roadmap, testing guide, PRD.
- `scripts/`: Dev helpers (e.g., `setup-venv.sh`, `update-libs.sh`).

## Build, Test, and Development Commands
- `make setup`: Install deps with Poetry for dev.
- `make all`: Format, lint, type-check, unit+integration tests. Run before every commit.
- `make format | lint | type-check`: Black, Ruff, mypy respectively.
- `make test` or `make test TEST=path::Class::test_name`: Run tests (unit by default).
- `make test-integration` / `make test-cov`: Integration tests / coverage.
- `pre-commit run -a`: Run all hooks on all files (must pass before commit).
- Quick run: `python oyente/oyente.py -s tests/integration/fixtures/contracts/simple_safe.sol`.
- Dependency bumps: `make libs-bump-latest | libs-bump-dev | libs-bump-all` (uses `scripts/update-libs.sh`).
- Solidity version: `solc-select use <version>` (e.g., `0.8.19`) if compilation mismatches.

## Coding Style & Naming Conventions
- Formatting: Black (120 cols). Linting: Ruff. Types: mypy must be clean.
- Add type hints and Google-style docstrings to new/changed public APIs.
- Naming: Classes `PascalCase`; functions/vars `snake_case`; constants `UPPER_SNAKE_CASE`.
- Security: Never use `shell=True`; validate inputs; no secrets in code.

## Testing Guidelines
- Framework: pytest. Markers in `pyproject.toml` (`unit`, `integration`, etc.).
- Default `pytest`/`make test` runs unit tests; integration is opt-in.
- Name tests `test_<feature>_<expected>()` and add tests for all changes.
- Coverage targets enforced via CI; use `make test-cov` locally when adding features.
- See `docs/testing.md` for structure, fixtures, and examples.

## Commit & Pull Request Guidelines
- Commits: Imperative, concise subject (e.g., "Fix coverage drop", "Add Dockerfile variants").
- Before committing: `make all && pre-commit run -a` must pass.
- PRs must: pass `make all`; run `pre-commit run -a`; include description, rationale, and reproduction steps; link issues; attach CLI logs/screenshots; update docs and tests.

## Security & Configuration Tips
- Use `solc-select` to match compiler versions for tests and local runs.
- Avoid filesystem/network in unit tests; prefer mocks (see `tests/mocks/`).

## Troubleshooting
- Version mismatch errors: switch compiler with `solc-select use <version>` (e.g., `0.8.19`).
