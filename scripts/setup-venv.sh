#!/bin/bash
# Setup virtual environment for Oyente+ development using Poetry
set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Change to project root to ensure venv is created there
cd "$PROJECT_ROOT"

echo "🚀 Setting up Python development environment with Poetry..."

# Create virtual environment with the current Python version
echo "📦 Creating virtual environment with $(python3 --version)..."
python3 -m venv "$PROJECT_ROOT/venv"
source "$PROJECT_ROOT/venv/bin/activate"

# Upgrade pip and install Poetry in the venv
echo "📦 Installing pip, wheel, and Poetry..."
pip install --upgrade pip wheel
pip install "poetry>=2.0.0"

POETRY_VERSION=$(poetry --version)
echo "✅ Installed $POETRY_VERSION"

echo "📦 Installing all dependencies with Poetry..."
# In CI with matrix builds, skip initial install to allow per-version lock regeneration
if [ "$CI_SKIP_INSTALL" = "true" ]; then
    echo "Skipping dependency installation (will be done after lock regeneration)"
else
    # Clear any existing lock issues and install fresh
    poetry install --with dev --no-interaction --verbose
fi

echo "🔗 Setting up pre-commit hooks..."
# Only install pre-commit hooks if not in CI environment
if [ -z "$CI" ]; then
    poetry run pre-commit install
else
    echo "Skipping pre-commit hook installation in CI environment"
fi

echo "✅ Setup complete!"
echo ""
echo "To activate the environment, run:"
echo "   source $PROJECT_ROOT/venv/bin/activate"
echo ""
echo "Or run commands directly with:"
echo "   poetry run <command>"
echo ""
echo "Available make targets:"
echo "   make test      # Run pytest tests"
echo "   make test-cov  # Run tests with coverage"
echo "   make lint      # Run code linting"
echo "   make format    # Format code with Black"
echo "   make all       # Run all quality checks"
echo ""
echo "Pre-commit hooks are installed and will run automatically on commit."
echo "To run manually: poetry run pre-commit run --all-files"
