"""
Test data factories for Oyente+ testing.

This package provides factory classes for generating test objects
using the factory_boy library for consistent and maintainable test data.
"""

from .analysis import AnalysisFactory
from .contract import ContractFactory
from .vulnerability import VulnerabilityFactory

__all__ = [
    "AnalysisFactory",
    "ContractFactory",
    "VulnerabilityFactory",
]
