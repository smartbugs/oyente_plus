pragma solidity ^0.6.0;

contract OldPragmaContract {
    uint256 public value;
    
    constructor() public {
        value = 42;
    }
    
    function setValue(uint256 _value) public {
        value = _value;
    }
    
    function getValue() public view returns (uint256) {
        return value;
    }
}