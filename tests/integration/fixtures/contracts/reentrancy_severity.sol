pragma solidity ^0.8.0;

contract ReentrancySeverity {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Critical severity - direct fund drainage
    function criticalVuln() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
    
    // Medium severity - limited impact
    function mediumVuln() public {
        uint256 amount = balances[msg.sender];
        require(amount <= 0.1 ether, "Amount too large");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}