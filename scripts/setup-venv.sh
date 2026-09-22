#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
POETRY_VERSION="${POETRY_VERSION:-2.4.3}"
POETRY_ENV="$PROJECT_ROOT/.poetry-venv"
POETRY="$POETRY_ENV/bin/poetry"

cd "$PROJECT_ROOT"

echo "Installing Oyente+ development dependencies"
echo "Python: $(python3 --version)"

# Poetry is a build tool, not a project dependency. Keep it in its own
# environment so resolving project dependencies cannot modify Poetry.
if [[ ! -x "$POETRY" ]] || [[ "$($POETRY --version)" != "Poetry (version $POETRY_VERSION)" ]]; then
    rm -rf "$POETRY_ENV"
    python3 -m venv "$POETRY_ENV"
    "$POETRY_ENV/bin/python" -m pip install --upgrade pip
    "$POETRY_ENV/bin/python" -m pip install "poetry==$POETRY_VERSION"
fi

echo "Poetry: $($POETRY --version)"

# Keep the project environment predictable and local to the checkout.
export POETRY_VIRTUALENVS_IN_PROJECT=true
"$POETRY" env use "$(command -v python3)"
"$POETRY" check --lock
"$POETRY" sync --with dev --no-interaction

if [[ -z "${CI:-}" ]]; then
    "$POETRY" run pre-commit install
fi

echo "Setup complete"
echo "Project environment: $PROJECT_ROOT/.venv"
echo "Run commands with: $POETRY run <command>"
