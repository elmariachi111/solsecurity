//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import "@openzeppelin/contracts/utils/Strings.sol";

contract HighNoon {
  mapping(address => uint256) public wins;
  uint256 public gameStartsAt;

  constructor(uint256 gameStartsAt_) {
    gameStartsAt = gameStartsAt_;
  }

  function draw() public {
    require(block.timestamp > gameStartsAt, "not started");
    if (block.timestamp % 43 == 0) {
      wins[msg.sender]++;
    } else {
      revert("good luck next time");
    }
  }
}
