//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract MoneyDispatcher {
  mapping(address => uint256) public deposits;

  function deposit() external payable {
    deposits[msg.sender] += msg.value;
  }

  function transferFundsWithSend(address payable to, uint256 amount) public {
    bool success = to.send(amount);
    deposits[msg.sender] -= amount;
  }

  function transferFundsWithTransfer(address payable to, uint256 amount)
    public
  {
    to.transfer(amount);
    deposits[msg.sender] -= amount;
  }

  function transferFundsWithCall(address payable to, uint256 amount) public {
    (bool success, bytes memory returnData) = to.call{ value: amount }("");
    deposits[msg.sender] -= amount;
  }
}
