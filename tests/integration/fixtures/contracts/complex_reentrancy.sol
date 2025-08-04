pragma solidity ^0.8.0;

contract ComplexReentrancy {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    uint256 public totalSupply;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }
    
    function complexWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Complex state modifications
        balances[msg.sender] -= amount;
        
        // External call in the middle
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // More state changes after external call
        totalSupply -= amount;
        
        // Another external call
        if (amount > 1 ether) {
            (bool success2, ) = msg.sender.call{value: amount / 10}("");
            require(success2, "Bonus transfer failed");
        }
    }
}