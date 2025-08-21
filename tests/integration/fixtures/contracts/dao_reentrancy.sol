pragma solidity ^0.8.0;

/**
 * @title DAOReentrancy
 * @dev Example contract with classic DAO-style reentrancy vulnerability
 * This contract is intentionally vulnerable for testing purposes only
 */
contract DAOReentrancy {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @dev Deposit Ether into the contract
     */
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev Withdraw all balance - VULNERABLE to reentrancy
     * This function has the classic DAO vulnerability pattern:
     * 1. External call before state update
     * 2. No reentrancy guard
     */
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance to withdraw");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens AFTER external call
        balances[msg.sender] = 0;

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @dev Get contract balance
     */
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @dev Get user balance
     */
    function getUserBalance(address user) public view returns (uint256) {
        return balances[user];
    }
}
