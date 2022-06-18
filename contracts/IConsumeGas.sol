//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract IConsumeGas {
  mapping(address => bytes32) heavy;

  receive() external payable {
    for (uint256 i = 0; i < 10; i++) {
      heavy[msg.sender] = keccak256(abi.encodePacked(i));
    }
  }
}
