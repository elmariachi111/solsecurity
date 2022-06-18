//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract HighNoon {
  uint256 private _gameStartsAt;
  bool public gameover = false;

  constructor(uint256 gameStartsAt) {
    _gameStartsAt = gameStartsAt;
  }

  function draw() public {
    require(block.timestamp > _gameStartsAt, "not started");
    require(!gameover, "someone else has won");
    if (block.timestamp % 43 == 0) {
      gameover = true;
      //payable(msg.sender).transfer(1 ether);
    } else {
      revert("good luck next time");
    }
  }
}
