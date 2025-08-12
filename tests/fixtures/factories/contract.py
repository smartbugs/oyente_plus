"""
Contract factory for generating test contract objects.

This module provides factory classes for creating contract-related
test data including source code, compilation results, and metadata.
"""

from __future__ import annotations

from typing import Any

import factory
from faker import Faker


fake = Faker()


class ContractFactory(factory.Factory):
    """Factory for generating contract test objects."""

    class Meta:
        model = dict

    # Basic contract properties
    name = factory.Faker("word")
    pragma_version = factory.Iterator(["^0.8.0", "^0.7.6", "^0.8.19", ">=0.7.0 <0.9.0"])

    # Source code (will be generated based on contract type)
    source_code = factory.LazyAttribute(lambda obj: _generate_basic_contract(obj.name))

    # Compilation results
    bytecode = factory.Faker("hexify", text="^" * 200)  # Random 200-char hex string
    abi = factory.LazyFunction(lambda: [])  # Default empty ABI

    # Metadata
    compiler_version = factory.Faker("numerify", text="0.8.##")
    optimization_enabled = factory.Faker("boolean")
    optimization_runs = factory.Iterator([200, 1000, 10000])

    # File information
    file_path = factory.LazyAttribute(lambda obj: f"contracts/{obj.name}.sol")
    size_bytes = factory.Faker("random_int", min=500, max=50000)

    @classmethod
    def simple_storage(cls, **kwargs: Any) -> dict[str, Any]:
        """Create a simple storage contract."""
        defaults = {
            "name": "SimpleStorage",
            "source_code": """
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private storedData;

    function set(uint256 x) public {
        storedData = x;
    }

    function get() public view returns (uint256) {
        return storedData;
    }
}""",
            "abi": [
                {"inputs": [{"name": "x", "type": "uint256"}], "name": "set", "outputs": [], "type": "function"},
                {"inputs": [], "name": "get", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
            ],
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def erc20_token(cls, **kwargs: Any) -> dict[str, Any]:
        """Create an ERC20 token contract."""
        defaults = {
            "name": "BasicToken",
            "source_code": """
pragma solidity ^0.8.0;

contract BasicToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    string public name;
    string public symbol;

    constructor(uint256 _initialSupply, string memory _name, string memory _symbol) {
        balances[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
        name = _name;
        symbol = _symbol;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] >= _value, "Insufficient balance");
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }
}""",
            "abi": [
                {
                    "inputs": [
                        {"name": "_initialSupply", "type": "uint256"},
                        {"name": "_name", "type": "string"},
                        {"name": "_symbol", "type": "string"},
                    ],
                    "name": "constructor",
                    "type": "constructor",
                },
                {
                    "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
                    "name": "transfer",
                    "outputs": [{"name": "", "type": "bool"}],
                    "type": "function",
                },
            ],
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def vulnerable_reentrancy(cls, **kwargs: Any) -> dict[str, Any]:
        """Create a reentrancy-vulnerable contract."""
        defaults = {
            "name": "VulnerableBank",
            "source_code": """
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
}""",
            "vulnerabilities": ["reentrancy"],
            "severity": "high",
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def integer_overflow(cls, **kwargs: Any) -> dict[str, Any]:
        """Create an integer overflow vulnerable contract."""
        defaults = {
            "name": "IntegerOverflow",
            "pragma_version": "^0.7.0",  # Pre-0.8.0 for overflow
            "source_code": """
pragma solidity ^0.7.0;

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
}""",
            "vulnerabilities": ["integer_overflow", "integer_underflow"],
            "severity": "medium",
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def timestamp_dependency(cls, **kwargs: Any) -> dict[str, Any]:
        """Create a timestamp dependency vulnerable contract."""
        defaults = {
            "name": "TimestampLottery",
            "source_code": """
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
}""",
            "vulnerabilities": ["timestamp_dependency"],
            "severity": "low",
        }
        defaults.update(kwargs)
        return cls(**defaults)

    @classmethod
    def complex_defi(cls, **kwargs: Any) -> dict[str, Any]:
        """Create a complex DeFi contract."""
        defaults = {
            "name": "DeFiVault",
            "source_code": """
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
}""",
            "complexity": "high",
            "size_bytes": 5000,
        }
        defaults.update(kwargs)
        return cls(**defaults)


class CompilationResultFactory(factory.Factory):
    """Factory for generating compilation results."""

    class Meta:
        model = dict

    success = factory.Faker("boolean", chance_of_getting_true=90)  # 90% success rate
    bytecode = factory.Faker("hexify", text="^" * 200)
    abi = factory.LazyFunction(list)

    # Error information for failed compilations
    errors = factory.Maybe(
        "success",
        yes_declaration=factory.LazyFunction(list),  # No errors on success
        no_declaration=factory.List([factory.Faker("sentence", nb_words=8)]),  # Error messages
    )

    warnings = factory.List([factory.Faker("sentence", nb_words=6)], size=factory.Faker("random_int", min=0, max=3))

    # Compilation metadata
    compiler_version = factory.Faker("numerify", text="0.8.##")
    optimization = factory.Faker("boolean")
    gas_estimates = factory.LazyFunction(
        lambda: {
            "creation": fake.random_int(min=100000, max=1000000),
            "external": fake.random_int(min=21000, max=500000),
            "internal": fake.random_int(min=1000, max=50000),
        }
    )


def _generate_basic_contract(name: str) -> str:
    """Generate basic contract source code."""
    return f"""
pragma solidity ^0.8.0;

contract {name} {{
    uint256 public value;

    function setValue(uint256 _value) public {{
        value = _value;
    }}

    function getValue() public view returns (uint256) {{
        return value;
    }}
}}"""
