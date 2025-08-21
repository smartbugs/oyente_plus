pragma solidity ^0.8.0;

/**
 * @title CrossFunctionReentrancy
 * @dev Example contract with cross-function reentrancy vulnerability
 */
contract CrossFunctionReentrancy {
    mapping(address => uint256) public balances;
    bool private locked;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable to cross-function reentrancy
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // External call that can re-enter other functions
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call
        balances[msg.sender] = 0;
    }

    // This function can be called during reentrancy
    function emergencyWithdraw() public {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
