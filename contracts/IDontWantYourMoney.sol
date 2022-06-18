//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract IDontWantYourMoney {
  error NoMoneyAccepted();

  receive() external payable {
    revert NoMoneyAccepted();
  }
}
