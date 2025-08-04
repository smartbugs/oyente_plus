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


# Symbolic execution specific factories
class SymbolicExecutionFactory:
    """Factory for generating symbolic execution test data."""

    @staticmethod
    def basic_parameter_state() -> dict[str, Any]:
        """Generate basic Parameter state for testing."""
        return {
            "stack": [1, 2, 3],
            "calls": [],
            "memory": [0x40, 0x80],
            "visited": [0, 10, 20],
            "overflow_pcs": [],
            "mem": {"0x40": "0x80"},
            "analysis": {"gas": 21000, "paths": 1},
            "sha3_list": {},
            "global_state": {"Ia": "0x1234", "balance": 1000},
            "path_conditions_and_vars": {"vars": ["x", "y"], "conditions": []},
        }

    @staticmethod
    def complex_parameter_state() -> dict[str, Any]:
        """Generate complex Parameter state with realistic data."""
        return {
            "stack": list(range(10)),
            "calls": [
                {"target": "0x123", "value": 1000, "gas": 21000},
                {"target": "0x456", "value": 0, "gas": 5000},
            ],
            "memory": list(range(0, 1000, 32)),
            "visited": list(range(0, 100, 5)),
            "overflow_pcs": [50, 75, 125],
            "mem": {f"0x{i:02x}": f"0x{i*2:02x}" for i in range(10)},
            "analysis": {
                "gas": 150000,
                "paths": 5,
                "depth": 10,
                "vulnerabilities": ["reentrancy", "overflow"],
            },
            "sha3_list": {
                "hash1": "data1",
                "hash2": "data2",
            },
            "global_state": {
                "Ia": generate_random_address(),
                "Iv": random.randint(0, 10**20),  # noqa: S311
                "balance": random.randint(0, 10**18),  # noqa: S311
                "storage": {f"slot_{i}": f"value_{i}" for i in range(5)},
            },
            "path_conditions_and_vars": {
                "vars": [f"var_{i}" for i in range(5)],
                "conditions": [f"condition_{i}" for i in range(3)],
            },
        }

    @staticmethod
    def disassembly_lines_simple() -> list[str]:
        """Generate simple disassembly lines for testing."""
        return [
            "0: PUSH1 0x80",
            "2: PUSH1 0x40",
            "4: MSTORE",
            "5: PUSH1 0x01",
            "7: PUSH1 0x00",
            "9: SSTORE",
            "10: STOP",
        ]

    @staticmethod
    def disassembly_lines_with_jumps() -> list[str]:
        """Generate disassembly with jump instructions."""
        return [
            "0: PUSH1 0x80",
            "2: PUSH1 0x40",
            "4: MSTORE",
            "5: CALLVALUE",
            "6: DUP1",
            "7: ISZERO",
            "8: PUSH1 0x15",
            "10: JUMPI",
            "11: PUSH1 0x00",
            "13: DUP1",
            "14: REVERT",
            "15: JUMPDEST",
            "16: POP",
            "17: PUSH1 0x04",
            "19: CALLDATASIZE",
            "20: LT",
            "21: PUSH1 0x2b",
            "23: JUMPI",
            "24: PUSH1 0x00",
            "26: CALLDATALOAD",
            "27: PUSH1 0x20",
            "29: SHR",
            "30: PUSH4 0x60fe47b1",
            "35: EQ",
            "36: PUSH1 0x30",
            "38: JUMPI",
            "39: JUMPDEST",
            "40: PUSH1 0x00",
            "42: DUP1",
            "43: REVERT",
            "44: JUMPDEST",
            "45: PUSH1 0x36",
            "47: STOP",
            "48: JUMPDEST",
            "49: PUSH1 0x00",
            "51: SLOAD",
            "52: SWAP1",
            "53: JUMP",
        ]

    @staticmethod
    def vulnerability_detection_scenario(vuln_type: str) -> dict[str, Any]:
        """Generate vulnerability detection scenario."""
        scenarios = {
            "reentrancy": {
                "disasm_lines": [
                    "0: PUSH1 0x80",
                    "2: PUSH1 0x40",
                    "4: MSTORE",
                    "5: CALLER",
                    "6: PUSH1 0x00",
                    "8: DUP1",
                    "9: DUP1",
                    "10: DUP1",
                    "11: DUP5",
                    "12: GAS",
                    "13: CALL",  # External call before state change
                    "14: SWAP1",
                    "15: POP",
                    "16: CALLER",
                    "17: PUSH1 0x00",
                    "19: DUP2",
                    "20: DUP2",
                    "21: SLOAD",
                    "22: SUB",
                    "23: SWAP1",
                    "24: SSTORE",  # State change after external call - reentrancy vulnerability
                    "25: POP",
                    "26: STOP",
                ],
                "expected_pcs": [13, 24],  # CALL and SSTORE PCs
                "expected_warnings": ["State change after external call detected"],
                "vulnerable": True,
            },
            "integer_overflow": {
                "disasm_lines": [
                    "0: PUSH1 0xff",
                    "2: PUSH1 0x01",
                    "4: ADD",  # 255 + 1 = overflow
                    "5: PUSH1 0x00",
                    "7: SSTORE",
                    "8: STOP",
                ],
                "expected_pcs": [4],  # ADD PC
                "expected_warnings": ["Potential integer overflow in arithmetic operation"],
                "vulnerable": True,
            },
            "safe": {
                "disasm_lines": [
                    "0: PUSH1 0x80",
                    "2: PUSH1 0x40",
                    "4: MSTORE",
                    "5: PUSH1 0x01",
                    "7: PUSH1 0x00",
                    "9: SSTORE",
                    "10: STOP",
                ],
                "expected_pcs": [],
                "expected_warnings": [],
                "vulnerable": False,
            },
        }

        return scenarios.get(vuln_type, scenarios["safe"])


class SymbolicExecutionResultFactory(factory.Factory):
    """Factory for generating symbolic execution results."""

    class Meta:
        model = dict

    # Basic execution metrics
    gas_used = factory.Faker("random_int", min=21000, max=1000000)
    paths_explored = factory.Faker("random_int", min=1, max=50)
    depth_reached = factory.Faker("random_int", min=1, max=100)
    execution_time = factory.Faker("random_int", min=100, max=5000)  # milliseconds

    # Vulnerability results
    vulnerabilities = factory.LazyFunction(
        lambda: {
            "integer_overflow": [],
            "integer_underflow": [],
            "reentrancy": [],
            "time_dependency": [],
            "money_concurrency": [],
            "callstack": [],
            "assertion_failure": [],
            "parity_multisig_bug_2": [],
        }
    )

    # Coverage information
    evm_code_coverage = factory.Faker("random_int", min=50, max=100)
    basic_blocks_covered = factory.LazyFunction(list)
    instructions_covered = factory.LazyFunction(list)


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
