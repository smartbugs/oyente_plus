pragma solidity ^0.8.0;

contract FirstContract {
    uint256 public value1;
    
    function setValue1(uint256 _value) public {
        value1 = _value;
    }
    
    function getValue1() public view returns (uint256) {
        return value1;
    }
}

contract SecondContract {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // Potential vulnerability for testing
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;
    }
}

contract ThirdContract {
    uint256 public counter;
    
    function increment() public {
        counter++;
    }
    
    function getCounter() public view returns (uint256) {
        return counter;
    }
}