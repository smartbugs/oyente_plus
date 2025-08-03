#!/bin/bash
# Setup virtual environment for Oyente+ development using Poetry
set -e

echo "🚀 Setting up Python development environment with Poetry..."

echo "📦 Setting up Python venv with with Poetry..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip wheel
pip install poetry

echo "📦 Installing all dependencies with Poetry..."
poetry install --with dev,test,lint

echo "✅ Setup complete!"
echo ""
echo "To activate the environment, run:"
echo "   poetry shell"
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
