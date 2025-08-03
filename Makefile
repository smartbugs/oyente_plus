# Variables for better maintainability
PYTHON := python3
SRC_DIRS := oyente/ tests/
VENV_DIR := venv

# Poetry and virtual environment detection
POETRY := poetry
VENV_ACTIVE := $(shell echo $$VIRTUAL_ENV)
ifeq ($(VENV_ACTIVE),)
    POETRY_RUN := $(POETRY) run
else
    POETRY_RUN := 
endif

.DEFAULT_GOAL := help
.PHONY: help format lint type-check test all clean install install-dev setup

help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development Setup

setup: ## Create virtual environment and install all dependencies using Poetry
	@echo "🚀 Setting up development environment..."
	@$(POETRY) install --with dev,test,lint && echo "✅ Setup complete" || (echo "❌ Setup failed" && exit 1)

install: ## Install production dependencies only
	@echo "📦 Installing production dependencies..."
	@$(POETRY) install --only main && echo "✅ Installation complete" || (echo "❌ Installation failed" && exit 1)

install-dev: ## Install all dependencies including dev/test/lint groups
	@echo "🔧 Installing all dependencies..."
	@$(POETRY) install --with dev,test,lint && echo "✅ Development installation complete" || (echo "❌ Development installation failed" && exit 1)

##@ Code Quality

format: ## Format code with Black
	@echo "🔧 Formatting code with Black..."
	@$(POETRY_RUN) black $(SRC_DIRS) && echo "✅ Code formatting complete" || (echo "❌ Formatting failed" && exit 1)

lint: ## Check code with Ruff
	@echo "🔍 Linting code with Ruff..."
	@$(POETRY_RUN) ruff check $(SRC_DIRS) && echo "✅ Linting complete" || (echo "❌ Linting failed" && exit 1)

type-check: ## Type check with mypy
	@echo "🔎 Type checking with mypy..."
	@$(POETRY_RUN) mypy oyente/ && echo "✅ Type checking complete" || (echo "❌ Type checking failed" && exit 1)

##@ Testing

test: ## Run pytest tests
	@echo "🧪 Running pytest tests..."
	@$(POETRY_RUN) pytest && echo "✅ Tests complete" || (echo "❌ Tests failed" && exit 1)

test-legacy: ## Run legacy EVM tests
	@echo "🧪 Running legacy EVM tests..."
	@$(POETRY_RUN) python oyente/run_tests.py && echo "✅ Legacy tests complete" || (echo "❌ Legacy tests failed" && exit 1)

test-cov: ## Run tests with coverage
	@echo "🧪 Running tests with coverage..."
	@$(POETRY_RUN) pytest --cov=oyente --cov-report=term-missing --cov-report=html:htmlcov --cov-report=xml:coverage.xml && echo "✅ Tests with coverage complete" || (echo "❌ Tests with coverage failed" && exit 1)

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
