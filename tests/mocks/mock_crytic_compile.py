"""
Mock crytic-compile functionality for testing.

This module provides mock implementations for crytic-compile operations,
allowing tests to run without actual compilation and in isolation.
"""

from __future__ import annotations

import json
from typing import Union
from unittest.mock import patch


class MockSourceUnit:
    """Mock source unit for crytic-compile."""

    def __init__(self, contracts: dict[str, str], libraries: Union[dict[str, str], None] = None):
        self._contracts = contracts
        self._libraries = libraries or {}
        self.contracts_names = list(contracts.keys())
        # Filter out libraries from contract names
        self.contracts_names_without_libraries = [name for name in self.contracts_names if name not in self._libraries]

    def bytecode_runtime(self, name: str) -> str:
        """Return runtime bytecode for contract."""
        return self._contracts.get(name, "")

    def is_library(self, name: str) -> bool:
        """Check if a contract is a library."""
        return name in self._libraries


class MockCompilerVersion:
    """Mock compiler version information."""

    def __init__(self, compiler: str = "solc", version: str = "0.8.19", optimized: bool = False):
        self.compiler = compiler
        self.version = version
        self.optimized = optimized


class MockFilename:
    """Mock filename object."""

    def __init__(self, path: str):
        self.used = path


class MockCompilationUnit:
    """Mock compilation unit for crytic-compile."""

    def __init__(
        self, contracts: dict[str, str], filename: str = "test.sol", libraries: Union[dict[str, str], None] = None
    ):
        self.compiler_version = MockCompilerVersion()
        self.source_units = {MockFilename(filename): MockSourceUnit(contracts, libraries)}
        self._libraries = libraries or {}


class MockCryticCompile:
    """Mock CryticCompile class for testing."""

    def __init__(
        self,
        source: str = "test.sol",
        contracts: Union[dict[str, str], None] = None,
        filename: str = "test.sol",
        libraries: Union[dict[str, str], None] = None,
        solc_remaps: str = "",
        solc_args: str = "",
        target_contracts: Union[list[str], None] = None,
        **kwargs,
    ):
        if contracts is None:
            contracts = {"SimpleToken": CommonBytecodes.SIMPLE_STORAGE}

        self.compilation_units = {filename: MockCompilationUnit(contracts, filename, libraries)}
        self._contracts = contracts
        self._libraries = libraries or {}
        self._target_contracts = target_contracts
        self.source = source

        # Call counting for cache testing
        self.call_count = 0
        self.compilation_count = 0

    def get_contract_name(self, filename: str) -> list[str]:
        """Get contract names for a file."""
        self.call_count += 1
        contract_names = list(self._contracts.keys())

        # Apply target contract filtering if specified
        if self._target_contracts:
            filtered_names = [name for name in contract_names if name in self._target_contracts]
            if not filtered_names:
                raise MockInvalidCompilationError(f"Target contracts {self._target_contracts} not found")
            return filtered_names

        return contract_names

    def get_contracts(self) -> dict[str, str]:
        """Get all contracts with optional filtering."""
        self.call_count += 1
        if self._target_contracts:
            return {name: bytecode for name, bytecode in self._contracts.items() if name in self._target_contracts}
        return self._contracts.copy()

    def is_library(self, contract_name: str) -> bool:
        """Check if a contract is a library."""
        return contract_name in self._libraries

    def get_libraries(self) -> dict[str, str]:
        """Get all libraries."""
        return self._libraries.copy()

    def compile(self) -> None:
        """Mock compilation process."""
        self.compilation_count += 1


class MockInvalidCompilationError(Exception):
    """Mock InvalidCompilation exception."""

    def __init__(self, message: str = "Compilation failed"):
        super().__init__(message)
        self.message = message


def create_mock_crytic_compile(
    contracts: Union[dict[str, str], None] = None,
    libraries: Union[dict[str, str], None] = None,
    target_contracts: Union[list[str], None] = None,
    should_fail: bool = False,
    failure_message: str = "Compilation failed",
):
    """
    Create a mock CryticCompile instance.

    Args:
        contracts: Dictionary of contract name to bytecode
        libraries: Dictionary of library name to bytecode
        target_contracts: List of target contract names to filter
        should_fail: Whether compilation should fail
        failure_message: Error message if compilation fails
    """
    if should_fail:
        raise MockInvalidCompilationError(failure_message)

    return MockCryticCompile(contracts=contracts, libraries=libraries, target_contracts=target_contracts)


def patch_crytic_compile(
    contracts: Union[dict[str, str], None] = None,
    libraries: Union[dict[str, str], None] = None,
    target_contracts: Union[list[str], None] = None,
    should_fail: bool = False,
    failure_message: str = "Compilation failed",
):
    """
    Decorator to patch crytic_compile with mock implementation.

    Usage:
        @patch_crytic_compile({
            'SimpleToken': '608060405234801561001057600080fd5b50'
        }, libraries={'Math': '608060405234801561001057600080fd5b50'})
        def test_something(mock_compile):
            # Test code here
            pass
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            with (
                patch("crytic_compile.CryticCompile") as mock_class,
                patch("crytic_compile.InvalidCompilation", MockInvalidCompilationError),
            ):

                if should_fail:
                    mock_class.side_effect = MockInvalidCompilationError(failure_message)
                else:
                    mock_instance = create_mock_crytic_compile(
                        contracts=contracts, libraries=libraries, target_contracts=target_contracts
                    )
                    mock_class.return_value = mock_instance

                return func(mock_instance if not should_fail else None, *args, **kwargs)

        return wrapper

    return decorator


# Common contract bytecodes for testing
class CommonBytecodes:
    """Common contract bytecodes for testing."""

    SIMPLE_STORAGE = "608060405234801561001057600080fd5b5060ef8061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80632a1afcd914603757806360fe47b114604c575b600080fd5b603d60005481565b60405190815260200160405180910390f35b605c6057366004605e565b600055565b005b600060208284031215606f57600080fd5b503591905056fea26469706673582212208b13ed8b7e6a93e89c1e7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c64736f6c634300081300"

    ERC20_TOKEN = "608060405234801561001057600080fd5b506040516105d03803806105d083398101604081905261002f9161007c565b60008054338252600160208190526040808420849055929092558151928352917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a350610095565b60006020828403121561008e57600080fd5b5051919050565b61052c806100a46000396000f3fe608060405234801561001057600080fd5b50600436106100575760003560e01c8063095ea7b31461005c57806318160ddd1461007f57806323b872dd1461009157806370a08231146100a4578063a9059cbb146100cd575b600080fd5b61006f61006a3660046103e8565b6100e0565b60405190151581526020015b60405180910390f35b6000545b604051908152602001610076565b61006f61009f366004610412565b61014d565b6100836100b236600461044e565b6001600160a01b031660009081526001602052604090205490565b61006f6100db3660046103e8565b6101ee565b3360008181526002602090815260408083206001600160a01b038716808552925280832085905551919290917f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92590610139908690815260200190565b60405180910390a35060015b92915050565b6001600160a01b0383166000908152600260209081526040808320338452909152812054821180156101975750506001600160a01b038416600090815260016020526040902054829010155b80156101b557506001600160a01b03831660009081526001602052604090205481115b156101e0576101c48382610470565b6001600160a01b0385166000908152600260209081526040808320338452909152902055506101e7565b5060006101e7565b6001600160a01b038416600090815260016020526040812054610208610251565b1161021557506000610145565b61021f8382610470565b6001600160a01b03808616600090815260016020526040808220939093559085168152208054849003905550600192915050565b60009081526002602090815260408083203384529091529020549056fea26469706673582212200a4e7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c64736f6c634300081300"  # noqa: S105

    VULNERABLE_BANK = "608060405234801561001057600080fd5b50610382806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e1a7d4d1461003b578063d0e30db014610050575b600080fd5b61004e610049366004610294565b610058565b005b61004e610186565b6001600160a01b03331660009081526020819052604090205481111561008557610085610252565b6001600160a01b03331660009081526020819052604090205481116100a957610185565b604051600090339083908381818185875af1925050503d80600081146100eb576040519150601f19603f3d011682016040523d82523d6000602084013e6100f0565b606091505b50509050806101405760405162461bcd60e51b815260206004820152601060248201526f2a3930b739b332b9103330b4b632b21760811b60448201526064015b60405180910390fd5b6001600160a01b033316600090815260208190526040812080548492906101689084906102ad565b909155505050565b6040805160208101909152600080825261018933610058565b5050565b6001600160a01b03331660009081526020819052604081208054349290610186908490610268565b9050565b6040805160208101909152600080825261018933610058565b5050565b600060208284031215610206578283fd5b5035919050565b60008219821115610221576102216102c4565b500190565b600082821015610238576102386102c4565b500390565b634e487b7160e01b600052602260045260246000fd5b60405162461bcd60e51b815260206004820152601460248201527314dc99585d1a5bdb9194d85b1b195c881b1a5cdd60621b6044820152606401610137565b634e487b7160e01b600052601160045260246000fdfea26469706673582212207e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e8b7e7c5b1e8b7e7c5b1e8b7e7c64736f6c634300081300"

    # Library bytecodes for testing library linking
    MATH_LIBRARY = "608060405234801561001057600080fd5b50610234806100206000396000f3fe60806040526004361061004e5760003560e01c80631e093b2f146100535780635c30aa6b14610093578063b5f0e464146100b3578063e4ae8b28146100d3578063f05f5ee7146100f3575b600080fd5b34801561005f57600080fd5b5061007361006e366004610190565b610113565b60405190151581526020015b60405180910390f35b34801561009f57600080fd5b506100736100ae366004610190565b61012e565b3480156100bf57600080fd5b506100736100ce366004610190565b610141565b3480156100df57600080fd5b506100736100ee366004610190565b610154565b3480156100ff57600080fd5b5061010861016c565b60405190815260200161008a565b60008161011f83610175565b6101299190610205565b905092915050565b600081610129838361017f565b600081610129838361018a565b600081610129838361017f565b60006000610168565b60008181831161016957600080fd5b92915050565b6000610169565b600081831161016957600080fd5b6000818311610169576000610184565b50600090565b600060208284031215610182578081fd5b5035919050565b634e487b7160e01b600052601160045260246000fd5b6000828210156101a7576101a7610191565b500390565b6000816101bb576101bb610191565b50600090565b60008160001904831182151516156101db576101db610191565b500290565b60008261020057634e487b7160e01b600052601260045260246000fd5b500490565b6000821982111561021857610218610191565b50019056fea26469706673582212209e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c64736f6c634300081300"

    STRING_UTILS_LIBRARY = "608060405234801561001057600080fd5b50610156806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80630b1bc62b1461003b578063f3a4fb8514610065575b600080fd5b61004e610049366004610097565b610085565b60405161005c91906100ee565b60405180910390f35b610078610073366004610097565b610085565b60405161005c9190610101565b60008051602061010683398151915260006100a08383610085565b9050600181146100af57600080fd5b50919050565b600060208083528351808285015260005b818110156100e2578581018301518582016040015282016100c6565b50600060408282840101525060407f601f196073196c6c6972656574722020746120796c73696e656b6e6f69746964006040820152016100855600a2646970667358221220b4e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b7e7c5b1e8b736f6c634300081300"


def create_standard_json_output(contracts: dict[str, str]) -> str:
    """Create standard JSON compilation output."""
    output = {"sources": {}, "contracts": {}}

    for contract_name, bytecode in contracts.items():
        source_file = f"{contract_name}.sol"
        output["sources"][source_file] = {"id": 0, "ast": {}}
        output["contracts"][source_file] = {contract_name: {"evm": {"deployedBytecode": {"object": bytecode}}}}

    return json.dumps(output)


# Fixture for common test scenarios
def get_test_contracts() -> dict[str, dict[str, str]]:
    """Get common test contract scenarios."""
    return {
        "simple_storage": {"SimpleStorage": CommonBytecodes.SIMPLE_STORAGE},
        "erc20_token": {"ERC20Token": CommonBytecodes.ERC20_TOKEN},
        "vulnerable_bank": {"VulnerableBank": CommonBytecodes.VULNERABLE_BANK},
        "multiple_contracts": {
            "SimpleStorage": CommonBytecodes.SIMPLE_STORAGE,
            "ERC20Token": CommonBytecodes.ERC20_TOKEN,
        },
    }


def get_test_libraries() -> dict[str, dict[str, str]]:
    """Get common test library scenarios."""
    return {
        "math_library": {"Math": CommonBytecodes.MATH_LIBRARY},
        "string_utils": {"StringUtils": CommonBytecodes.STRING_UTILS_LIBRARY},
        "multiple_libraries": {
            "Math": CommonBytecodes.MATH_LIBRARY,
            "StringUtils": CommonBytecodes.STRING_UTILS_LIBRARY,
        },
    }


def get_contracts_with_libraries() -> tuple[dict[str, str], dict[str, str]]:
    """Get contracts that use libraries."""
    contracts = {
        "Calculator": CommonBytecodes.SIMPLE_STORAGE,  # Mock using storage for simplicity
        "TokenWithUtils": CommonBytecodes.ERC20_TOKEN,
    }
    libraries = {
        "Math": CommonBytecodes.MATH_LIBRARY,
        "StringUtils": CommonBytecodes.STRING_UTILS_LIBRARY,
    }
    return contracts, libraries
