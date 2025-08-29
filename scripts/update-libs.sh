#!/usr/bin/env bash

# Update all top-level Poetry dependencies to latest, one-by-one,
# validating after each update with tests and hooks. Stops on failure.
#
# Usage:
#   update-libs.sh [OPTIONS]
#
# Options:
#   -i, --include-dev   Include dev dependencies (in addition to main)
#   -d, --dev-only      Update only dev dependencies
#   -n, --dry-run       Show which packages would be updated
#   -h, --help          Show this help message
#
set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default values
INCLUDE_DEV=false
DEV_ONLY=false
DRY_RUN=false

# Function to display help
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Update all top-level Poetry dependencies to latest with validation.

Options:
    -i, --include-dev   Include dev dependencies (in addition to main)
    -d, --dev-only      Update only dev dependencies
    -n, --dry-run       Show which packages would be updated
    -h, --help          Show this help message

Examples:
    $(basename "$0")                 # Update main dependencies only
    $(basename "$0") --include-dev   # Update main and dev dependencies
    $(basename "$0") --dev-only      # Update dev dependencies only
    $(basename "$0") --dry-run       # Preview updates without making changes
EOF
    exit 0
}

# Parse command line arguments using getopt
GETOPT_ARGS=$(getopt -o idnh -l include-dev,dev-only,dry-run,help -n "$(basename "$0")" -- "$@")
if [[ $? -ne 0 ]]; then
    echo "Error: Invalid arguments" >&2
    show_help
    exit 1
fi

eval set -- "$GETOPT_ARGS"

while true; do
    case "$1" in
        -i|--include-dev)
            INCLUDE_DEV=true
            shift
            ;;
        -d|--dev-only)
            DEV_ONLY=true
            INCLUDE_DEV=true
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

# Check for unexpected arguments
if [[ $# -gt 0 ]]; then
    echo "Error: Unexpected arguments: $*" >&2
    show_help
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT_DIR"

if ! command -v poetry >/dev/null 2>&1; then
  echo "Error: poetry not found in PATH" >&2
  exit 1
fi
if ! command -v make >/dev/null 2>&1; then
  echo "Error: make not found in PATH" >&2
  exit 1
fi

PYPROJECT=pyproject.toml
if [[ ! -f "$PYPROJECT" ]]; then
  echo "Error: $PYPROJECT not found in repository root" >&2
  exit 1
fi

# Validate package name for security
validate_package_name() {
  local name="$1"
  if [[ ! "$name" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "Error: Invalid package name: $name" >&2
    exit 1
  fi
}

# Escape special regex characters for safe pattern matching
escape_regex() {
  local input="$1"
  printf '%s\n' "$input" | sed 's/[[\.*^$()+?{|\\]/\\&/g'
}

extract_deps() {
  local section_start="$1"   # e.g., ^\[tool\.poetry\.dependencies\]
  local section_end='^\['    # next section header
  sed -n "/$section_start/,/$section_end/p" "$PYPROJECT" \
    | tail -n +2 \
    | grep -E '^[A-Za-z0-9_.-]+\s*=' \
    | cut -d'=' -f1 \
    | sed 's/[[:space:]]*$//' \
    | grep -v '^python$' || true
}

is_git_dep() {
  local name="$1"
  validate_package_name "$name"
  local escaped_name=$(escape_regex "$name")
  if grep -E "^$escaped_name\s*=.*\bgit\b" -q "$PYPROJECT"; then
    return 0
  else
    return 1
  fi
}

get_current_version() {
  local pkg="$1"
  validate_package_name "$pkg"
  poetry show "$pkg" 2>/dev/null | grep -E '^ version' | awk '{print $3}' || echo "unknown"
}

get_latest_version() {
  local pkg="$1"
  validate_package_name "$pkg"
  local escaped_pkg=$(escape_regex "$pkg")
  # Check if package appears in outdated list
  local outdated_line=$(poetry show --outdated 2>/dev/null | grep -E "^$escaped_pkg ")
  if [[ -n "$outdated_line" ]]; then
    # Extract the third column (latest version) from outdated output
    echo "$outdated_line" | awk '{print $3}'
  else
    # If not outdated, current version is latest
    get_current_version "$pkg"
  fi
}

MAIN_DEPS=( $(extract_deps '^\[tool\.poetry\.dependencies\]') )
DEV_DEPS=()
if $INCLUDE_DEV; then
  mapfile -t DEV_DEPS < <(extract_deps '^\[tool\.poetry\.group\.dev\.dependencies\]')
fi

filter_non_git() {
  local -n _in=$1
  local -a out=()
  for pkg in "${_in[@]}"; do
    if is_git_dep "$pkg"; then
      echo -e "${YELLOW}⚠ Skipping git dependency: $pkg${NC}" >&2
      continue
    fi
    out+=("$pkg")
  done
  printf '%s\n' "${out[@]}"
}

MAIN_DEPS=( $(filter_non_git MAIN_DEPS) )
if $INCLUDE_DEV; then
  DEV_DEPS=( $(filter_non_git DEV_DEPS) )
fi

print_dep_list() {
  local -n deps=$1
  local dep_type="$2"

  if [[ ${#deps[@]} -eq 0 ]]; then
    echo -e "${CYAN}No $dep_type dependencies to update${NC}"
    return
  fi

  echo -e "\n${BOLD}${BLUE}$dep_type dependencies to update:${NC}"
  for pkg in "${deps[@]}"; do
    local current=$(get_current_version "$pkg")
    local latest=$(get_latest_version "$pkg")
    if [[ "$current" == "$latest" ]] || [[ "$latest" == "unknown" ]]; then
      echo -e "  ${GREEN}✓${NC} ${BOLD}$pkg${NC} ${CYAN}$current${NC} (already latest)"
    else
      echo -e "  ${MAGENTA}→${NC} ${BOLD}$pkg${NC} ${CYAN}$current${NC} → ${GREEN}$latest${NC}"
    fi
  done
}

if ! $DEV_ONLY && [[ ${#MAIN_DEPS[@]} -gt 0 ]]; then
  print_dep_list MAIN_DEPS "Main"
fi
if $INCLUDE_DEV && [[ ${#DEV_DEPS[@]} -gt 0 ]]; then
  print_dep_list DEV_DEPS "Dev"
fi

if $DRY_RUN; then
  echo -e "\n${YELLOW}Dry run complete. No changes made.${NC}"
  exit 0
fi

updated_pkgs=()

update_one() {
  local name="$1"
  validate_package_name "$name"
  echo -e "\n${BOLD}${CYAN}=== Updating $name to latest ===${NC}"
  poetry add "$name@latest"
  echo -e "${BLUE}Running validation: make all${NC}"
  make all
  echo -e "${BLUE}Running hooks: pre-commit run -a${NC}"
  if command -v pre-commit >/dev/null 2>&1; then
    pre-commit run -a || {
      echo -e "${RED}pre-commit failed after updating $name${NC}" >&2
      exit 1
    }
  else
    poetry run pre-commit run -a || {
      echo -e "${RED}pre-commit failed after updating $name (via poetry run)${NC}" >&2
      exit 1
    }
  fi
  updated_pkgs+=("$name")
}

if ! $DEV_ONLY; then
  for pkg in "${MAIN_DEPS[@]}"; do
    update_one "$pkg"
  done
fi

if $INCLUDE_DEV; then
  for pkg in "${DEV_DEPS[@]}"; do
    update_one "$pkg"
  done
fi

echo -e "\n${GREEN}${BOLD}All done. Updated packages: ${updated_pkgs[*]:-<none>}${NC}"
