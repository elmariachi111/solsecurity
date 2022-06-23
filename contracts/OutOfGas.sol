//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract OutOfGas {
  address payable[] public recipients;

  constructor() {
    recipients.push(payable(msg.sender));
  }

  receive() external payable {
    uint256 len = recipients.length;
    uint256 share = msg.value / len;

    for (uint256 i = 0; i < len; i++) {
      recipients[i].transfer(share);
    }
  }

  function addRecipient(address recipient) public {
    recipients.push(payable(recipient));
  }

  function addManyRecipients(address[] memory recipients_) public {
    uint256 len = recipients_.length;
    for (uint256 i = 0; i < len; i++) {
      addRecipient(recipients_[i]);
    }
  }
}
