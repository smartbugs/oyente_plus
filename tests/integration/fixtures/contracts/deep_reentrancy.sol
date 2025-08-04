pragma solidity ^0.8.0;

contract DeepReentrancy {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function deepCall1() public {
        deepCall2();
    }
    
    function deepCall2() public {
        deepCall3();
    }
    
    function deepCall3() public {
        uint256 amount = balances[msg.sender];
        if (amount > 0) {
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            balances[msg.sender] = 0;
        }
    }
}