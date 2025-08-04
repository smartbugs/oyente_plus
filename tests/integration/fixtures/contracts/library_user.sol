pragma solidity ^0.8.0;

library Math {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
    
    function multiply(uint256 a, uint256 b) internal pure returns (uint256) {
        return a * b;
    }
}

contract LibraryUser {
    using Math for uint256;
    
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] = balances[msg.sender].add(msg.value);
    }
    
    function calculateBonus(uint256 amount) public pure returns (uint256) {
        return amount.multiply(2);
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] = balances[msg.sender].add(amount * type(uint256).max); // Intentional overflow for testing
        payable(msg.sender).transfer(amount);
    }
}