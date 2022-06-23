//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bequeather {
  event Received(uint256 amount);

  address payable public _heir;

  constructor(address payable heir) {
    _heir = heir;
  }

  receive() external payable {
    emit Received(msg.value);
  }

  function farewell() public {
    selfdestruct(_heir);
  }
}
