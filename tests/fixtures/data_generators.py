"""
Test data generators and factories for Oyente+ testing.

This module provides factory classes and functions to generate test data
including contracts, bytecode, analysis results, and vulnerability patterns.
"""

from __future__ import annotations

import random
from typing import Any

import factory
from faker import Faker


fake = Faker()


# Contract source code factories
class SolidityContractFactory:
    """Factory for generating Solidity contract source code."""

    @staticmethod
    def simple_storage() -> str:
        """Generate a simple storage contract."""
        return """
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private storedData;

    function set(uint256 x) public {
        storedData = x;
    }

    function get() public view returns (uint256) {
        return storedData;
    }
}
"""

    @staticmethod
    def token_contract() -> str:
        """Generate a basic ERC20-like token contract."""
        return """
pragma solidity ^0.8.0;

contract BasicToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) {
        balances[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] >= _value, "Insufficient balance");
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }
}
"""

    @staticmethod
    def vulnerable_reentrancy() -> str:
        """Generate a contract vulnerable to reentrancy attacks."""
        return """
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Vulnerability: external call before state update
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= _amount;
    }
}
"""

    @staticmethod
    def integer_overflow() -> str:
        """Generate a contract vulnerable to integer overflow."""
        return """
pragma solidity ^0.7.0;  // Pre-0.8.0 for overflow vulnerability

contract IntegerOverflow {
    mapping(address => uint8) public balances;

    function deposit(uint8 _amount) public {
        // Vulnerability: can overflow
        balances[msg.sender] += _amount;
    }

    function transfer(address _to, uint8 _amount) public {
        require(balances[msg.sender] >= _amount);
        // Vulnerability: can underflow
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
    }
}
"""

    @staticmethod
    def timestamp_dependency() -> str:
        """Generate a contract with timestamp dependency."""
        return """
pragma solidity ^0.8.0;

contract TimestampLottery {
    uint256 public constant TICKET_PRICE = 1 ether;
    address public winner;

    function buyTicket() public payable {
        require(msg.value == TICKET_PRICE, "Wrong ticket price");

        // Vulnerability: using block.timestamp for randomness
        if (block.timestamp % 10 == 0) {
            winner = msg.sender;
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
"""

    @staticmethod
    def delegatecall_vulnerability() -> str:
        """Generate a contract vulnerable to delegatecall attacks."""
        return """
pragma solidity ^0.8.0;

contract Proxy {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function forward(address _target, bytes memory _data) public {
        // Vulnerability: unchecked delegatecall
        (bool success, ) = _target.delegatecall(_data);
        require(success, "Delegatecall failed");
    }
}
"""

    @staticmethod
    def complex_defi() -> str:
        """Generate a complex DeFi-like contract."""
        return """
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract DeFiVault {
    mapping(address => mapping(address => uint256)) public deposits;
    mapping(address => uint256) public totalDeposited;

    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdrawal(address indexed user, address indexed token, uint256 amount);

    function deposit(address _token, uint256 _amount) external {
        require(_amount > 0, "Amount must be greater than 0");
        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "Transfer failed");

        deposits[msg.sender][_token] += _amount;
        totalDeposited[_token] += _amount;

        emit Deposit(msg.sender, _token, _amount);
    }

    function withdraw(address _token, uint256 _amount) external {
        require(deposits[msg.sender][_token] >= _amount, "Insufficient balance");

        deposits[msg.sender][_token] -= _amount;
        totalDeposited[_token] -= _amount;

        require(IERC20(_token).transfer(msg.sender, _amount), "Transfer failed");

        emit Withdrawal(msg.sender, _token, _amount);
    }
}
"""


# Bytecode generators
class BytecodeFactory:
    """Factory for generating EVM bytecode patterns."""

    @staticmethod
    def simple_bytecode() -> str:
        """Generate simple bytecode sequence."""
        # PUSH1 0x01, PUSH1 0x02, ADD, PUSH1 0x00, MSTORE, STOP
        return "600160020160005260006020f3"

    @staticmethod
    def with_jumps() -> str:
        """Generate bytecode with JUMP instructions."""
        # Contains JUMPI and JUMP patterns
        return "6080604052348015600f57600080fd5b50603e8061001e6000396000f3fe6080604052600080fdfea265627a7a72315820"

    @staticmethod
    def with_storage() -> str:
        """Generate bytecode with SSTORE operations."""
        # Contains SSTORE and SLOAD patterns
        return "60806040526001600055348015601457600080fd5b5060358060226000396000f3fe6080604052600080fd"

    @staticmethod
    def with_external_calls() -> str:
        """Generate bytecode with external call patterns."""
        # Contains CALL, DELEGATECALL patterns
        return "608060405260043610610041576000357c01000000000000000000000000000000000000000000000000000000009004806341c0e1b514610046575b600080fd5b61004e610050565b005b3373ffffffffffffffffffffffffffffffffffffffff16ff00"

    @staticmethod
    def random_bytecode(length: int = 100) -> str:
        """Generate random bytecode of specified length."""
        return "".join(random.choice("0123456789abcdef") for _ in range(length * 2))  # noqa: S311

    @staticmethod
    def from_opcodes(opcodes: list[str]) -> str:
        """Generate bytecode from list of opcodes."""
        opcode_map = {
            "STOP": "00",
            "ADD": "01",
            "MUL": "02",
            "SUB": "03",
            "DIV": "04",
            "PUSH1": "60",
            "PUSH2": "61",
            "PUSH32": "7f",
            "POP": "50",
            "MLOAD": "51",
            "MSTORE": "52",
            "SLOAD": "54",
            "SSTORE": "55",
            "JUMP": "56",
            "JUMPI": "57",
            "CALL": "f1",
            "RETURN": "f3",
            "REVERT": "fd",
            "SELFDESTRUCT": "ff",
        }

        bytecode = ""
        for opcode in opcodes:
            if opcode.startswith("PUSH"):
                # Handle PUSH with value
                parts = opcode.split()
                if len(parts) > 1:
                    bytecode += opcode_map.get(parts[0], "00")
                    bytecode += parts[1].replace("0x", "").zfill(2)
                else:
                    bytecode += opcode_map.get(opcode, "00")
                    bytecode += "00"
            else:
                bytecode += opcode_map.get(opcode, "00")

        return bytecode


# Analysis result factories
class AnalysisResultFactory(factory.Factory):
    """Factory for generating analysis results."""

    class Meta:
        model = dict

    gas = factory.Faker("random_int", min=21000, max=1000000)
    gas_mem = factory.Faker("random_int", min=0, max=100000)
    money_flow = factory.LazyFunction(list)
    reentrancy_bug = factory.LazyFunction(list)
    money_concurrency_bug = factory.LazyFunction(list)
    time_dependency_bug = factory.LazyFunction(list)
    assertion_failure = factory.LazyFunction(list)
    integer_overflow = factory.LazyFunction(list)
    integer_underflow = factory.LazyFunction(list)
    callstack_attack = factory.LazyFunction(list)
    parity_multisig_bug_2 = factory.LazyFunction(list)
    buggy_paths = factory.LazyFunction(list)
    normal_paths = factory.LazyFunction(list)

    @classmethod
    def with_vulnerabilities(cls, vulnerabilities: list[str]) -> dict[str, Any]:
        """Create analysis result with specific vulnerabilities."""
        result = cls()
        for vuln in vulnerabilities:
            if vuln == "reentrancy":
                result["reentrancy_bug"] = [100, 200, 300]  # Program counters
            elif vuln == "integer_overflow":
                result["integer_overflow"] = [150, 250]
            elif vuln == "timestamp":
                result["time_dependency_bug"] = [400]
            elif vuln == "money_flow":
                result["money_flow"] = [{"from": "0x123", "to": "0x456", "amount": "1000000000000000000"}]

        return result


# Vulnerability pattern factories
class VulnerabilityPatternFactory:
    """Factory for generating vulnerability patterns."""

    @staticmethod
    def reentrancy_pattern() -> dict[str, Any]:
        """Generate reentrancy vulnerability pattern."""
        return {
            "type": "reentrancy",
            "severity": "high",
            "program_counters": [100, 150, 200],
            "source_mapping": "150:25:0",
            "description": "State change after external call",
            "affected_function": "withdraw(uint256)",
        }

    @staticmethod
    def integer_overflow_pattern() -> dict[str, Any]:
        """Generate integer overflow pattern."""
        return {
            "type": "integer_overflow",
            "severity": "medium",
            "program_counters": [50, 75],
            "source_mapping": "75:15:0",
            "description": "Potential integer overflow in arithmetic operation",
            "affected_function": "deposit(uint8)",
        }

    @staticmethod
    def timestamp_dependency_pattern() -> dict[str, Any]:
        """Generate timestamp dependency pattern."""
        return {
            "type": "timestamp_dependency",
            "severity": "low",
            "program_counters": [300],
            "source_mapping": "200:50:0",
            "description": "Contract relies on block.timestamp for critical logic",
            "affected_function": "buyTicket()",
        }


# Test scenario factories
class TestScenarioFactory:
    """Factory for generating complete test scenarios."""

    @staticmethod
    def simple_analysis_scenario() -> dict[str, Any]:
        """Generate a simple analysis scenario."""
        return {
            "contract_source": SolidityContractFactory.simple_storage(),
            "expected_vulnerabilities": [],
            "expected_gas_usage": {"min": 21000, "max": 50000},
            "description": "Simple storage contract with no vulnerabilities",
        }

    @staticmethod
    def vulnerable_scenario(vulnerability_type: str) -> dict[str, Any]:
        """Generate a scenario with specific vulnerability."""
        scenarios = {
            "reentrancy": {
                "contract_source": SolidityContractFactory.vulnerable_reentrancy(),
                "expected_vulnerabilities": ["reentrancy"],
                "expected_patterns": [VulnerabilityPatternFactory.reentrancy_pattern()],
                "description": "Bank contract vulnerable to reentrancy attacks",
            },
            "integer_overflow": {
                "contract_source": SolidityContractFactory.integer_overflow(),
                "expected_vulnerabilities": ["integer_overflow", "integer_underflow"],
                "expected_patterns": [VulnerabilityPatternFactory.integer_overflow_pattern()],
                "description": "Token contract vulnerable to integer overflow/underflow",
            },
            "timestamp": {
                "contract_source": SolidityContractFactory.timestamp_dependency(),
                "expected_vulnerabilities": ["timestamp_dependency"],
                "expected_patterns": [VulnerabilityPatternFactory.timestamp_dependency_pattern()],
                "description": "Lottery contract with timestamp dependency",
            },
        }

        return scenarios.get(
            vulnerability_type,
            {
                "contract_source": SolidityContractFactory.simple_storage(),
                "expected_vulnerabilities": [],
                "expected_patterns": [],
                "description": "Unknown vulnerability type",
            },
        )


# Utility functions for test data generation
def generate_random_address() -> str:
    """Generate a random Ethereum address."""
    return "0x" + "".join(random.choice("0123456789abcdef") for _ in range(40))  # noqa: S311


def generate_random_hash() -> str:
    """Generate a random 32-byte hash."""
    return "0x" + "".join(random.choice("0123456789abcdef") for _ in range(64))  # noqa: S311


def generate_mock_blockchain_state() -> dict[str, Any]:
    """Generate mock blockchain state for testing."""
    return {
        "block_number": random.randint(1000000, 15000000),  # noqa: S311
        "timestamp": random.randint(1600000000, 1700000000),  # noqa: S311
        "difficulty": random.randint(1000000000, 3000000000),  # noqa: S311
        "gas_limit": 30000000,
        "coinbase": generate_random_address(),
        "accounts": {
            generate_random_address(): {
                "balance": str(random.randint(0, 10**20)),  # noqa: S311
                "nonce": random.randint(0, 100),  # noqa: S311
            }
            for _ in range(5)
        },
    }
