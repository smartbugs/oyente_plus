pragma solidity ^0.8.0;

contract ReentrancyGuarded {
    mapping(address => uint256) public balances;
    bool private locked;
    
    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function safeWithdraw() public nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}