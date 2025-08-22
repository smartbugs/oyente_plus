pragma solidity ^0.8.0;

contract ReentrancyStateChanges {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdrawWithStateChanges() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Multiple state changes after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
        totalSupply -= amount;
    }
}
