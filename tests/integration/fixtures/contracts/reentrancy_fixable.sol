pragma solidity ^0.8.0;

contract ReentrancyFixable {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Vulnerable function that can be fixed
    function vulnerableWithdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // External call before state change - FIXABLE
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;
    }
}