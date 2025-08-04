pragma solidity ^0.8.0;

contract ReentrancyLocations {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Line 10
    function vulnerableFunction() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // Line 14 - External call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // Line 17 - State change after external call  
        balances[msg.sender] = 0;
    }
}