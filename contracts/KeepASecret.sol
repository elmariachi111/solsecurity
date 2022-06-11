//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract KeepASecret {
  bytes32 private         _secret;
  address payable private _owner;
  
  constructor() {
    _secret = keccak256(abi.encodePacked(block.timestamp));
  }

  receive() external payable {}

  function guessSecret(bytes32 yourSecret) external {
    require (_secret == yourSecret, "guess again");
    _secret = keccak256(abi.encodePacked(block.timestamp));
    _owner = payable(msg.sender);
    _owner.transfer(address(this).balance);
  }
}