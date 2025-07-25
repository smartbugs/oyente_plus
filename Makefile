# Variables for better maintainability
PYTHON := python3
SRC_DIRS := oyente/ tests/
VENV_DIR := venv

# Virtual environment detection
VENV_ACTIVE := $(shell echo $$VIRTUAL_ENV)
ifeq ($(VENV_ACTIVE),)
    VENV_PYTHON := $(VENV_DIR)/bin/python
else
    VENV_PYTHON := $(PYTHON)
endif

.DEFAULT_GOAL := help
.PHONY: help format lint type-check test all clean install install-dev setup

help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development Setup

setup: ## Create virtual environment and install dependencies using setup-venv.sh
	@echo "🚀 Setting up development environment..."
	@./setup-venv.sh && echo "✅ Setup complete" || (echo "❌ Setup failed" && exit 1)

install: ## Install production dependencies (requires existing venv)
	@echo "Installing production dependencies..."
	@$(VENV_PYTHON) -m pip install -e . && echo "✅ Installation complete" || (echo "❌ Installation failed" && exit 1)

install-dev: ## Install development dependencies (requires existing venv)
	@echo "Installing development dependencies..."
	@$(VENV_PYTHON) -m pip install -e ".[dev]" && echo "✅ Development installation complete" || (echo "❌ Development installation failed" && exit 1)

##@ Code Quality

format: ## Format code with Black
	@echo "🔧 Formatting code with Black..."
	@black $(SRC_DIRS) && echo "✅ Code formatting complete" || (echo "❌ Formatting failed" && exit 1)

lint: ## Check code with Ruff
	@echo "🔍 Linting code with Ruff..."
	@ruff check $(SRC_DIRS) && echo "✅ Linting complete" || (echo "❌ Linting failed" && exit 1)

type-check: ## Type check with mypy
	@echo "🔎 Type checking with mypy..."
	@mypy oyente/ && echo "✅ Type checking complete" || (echo "❌ Type checking failed" && exit 1)

##@ Testing

test: ## Run tests
	@echo "🧪 Running tests..."
	@$(VENV_PYTHON) oyente/run_tests.py && echo "✅ Tests complete" || (echo "❌ Tests failed" && exit 1)

##@ Comprehensive

all: format lint type-check test ## Run all quality checks and tests
	@echo "✅ All checks passed successfully"

##@ Maintenance

clean: ## Clean up temporary files and caches
	@echo "🧹 Cleaning up..."
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	@rm -f bytecode bytecode.disasm
	@echo "✅ Cleanup complete"

clean-all: clean ## Remove virtual environment and all generated files
	@rm -rf $(VENV_DIR)
	@echo "✅ Virtual environment and caches removed"