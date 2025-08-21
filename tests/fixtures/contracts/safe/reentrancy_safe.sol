pragma solidity ^0.8.0;

contract ReentrancySafe {
    mapping(address => uint256) public balances;
    bool private locked;
    
    modifier noReentrancy() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    function withdraw() public noReentrancy {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        balances[msg.sender] = 0;  // State change before external call
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}