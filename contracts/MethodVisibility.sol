//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract MethodVisibility {
  address private owner;
  bool public paused = false;

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  modifier notPaused() {
    require(paused == false);
    _;
  }

  function initialize() public {
    owner = msg.sender;
  }

  function togglePause(bool _newVal) public onlyOwner {
    paused = _newVal;
  }

  function withdraw() external onlyOwner notPaused {
    payable(msg.sender).transfer(address(this).balance);
  }

  function claim() public onlyOwner {
    this.withdraw();
  }
}
