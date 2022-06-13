//SPDX-License-Identifier: MIT
pragma solidity <0.8.0;

import "@openzeppelin/contracts/math/SafeMath.sol";

contract NumberOverflows {
  using SafeMath for uint256;
  mapping(address => uint256) public balances;

  receive() external payable {
    balances[msg.sender] += msg.value;
  }

  function withdraw(uint256 _amount) public {
    assert(balances[msg.sender].sub(_amount) >= 0);
    balances[msg.sender] = balances[msg.sender].sub(_amount);

    // assert(balances[msg.sender] - _amount >= 0);
    // balances[msg.sender] -= _amount;

    payable(msg.sender).transfer(_amount);
  }
}
