pragma solidity ^0.8.0;

contract SyntaxError {
    uint256 public value
    // Missing semicolon above causes syntax error

    function setValue(uint256 _value) public {
        value = _value;
    }
}
