pragma solidity ^0.8.0;

contract NewPragmaContract {
    uint256 public value;

    constructor() {
        value = 42;
    }

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }

    // New Solidity 0.8+ features
    function safeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // Built-in overflow protection
    }
}
