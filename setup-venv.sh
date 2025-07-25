#!/bin/bash
# Setup virtual environment for Oyente+ development
set -e

echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "Upgrading pip and installing build tools..."
pip install --upgrade pip wheel

echo "Installing Oyente+ and dependencies from pyproject.toml..."
pip install -e .

echo "Installing development dependencies..."
pip install -e .[dev]

echo "Setup complete! Activate the environment with: source venv/bin/activate"
