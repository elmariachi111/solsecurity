//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SignedDepositor {
  struct Deposit {
    uint256 amount;
    int96 purpose;
  }

  event GrantReceived(uint256 amount);
  event Deposited(address depositor, uint256 amount, int96 purpose);

  mapping(address => Deposit[]) public _deposits;

  fallback() external payable {
    emit GrantReceived(msg.value);
  }

  function deposit(int96 purpose) external payable {
    _deposits[msg.sender].push(
      Deposit({ amount: msg.value, purpose: purpose })
    );
    emit Deposited(msg.sender, msg.value, purpose);
  }
}
