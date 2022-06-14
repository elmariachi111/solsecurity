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

  // DO NOT USE!
  //https://programtheblockchain.com/posts/2018/04/27/avoiding-integer-overflows-safemath-isnt-enough/
  function batchTransfer(address[] memory receivers, uint256 value) public {
    uint256 amount = receivers.length * value;
    //instead: uint256 amount = value.mul(receivers.length);

    require(balances[msg.sender] >= amount);

    balances[msg.sender] = balances[msg.sender].sub(amount);
    for (uint256 i = 0; i < receivers.length; i++) {
      balances[receivers[i]] = balances[receivers[i]].add(value);
    }
  }
}
