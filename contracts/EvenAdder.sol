//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract EvenAdder {
  error NotAnEvenNumber(uint256 givenNumber);

  uint256 public value;

  constructor(uint256 initialValue) {
    value = initialValue;
  }

  function addEvenNumber(uint256 evenNumber) public returns (uint256) {
    if (evenNumber % 2 != 0) {
      revert NotAnEvenNumber(evenNumber);
    }

    value += evenNumber;
    return value;
  }
}
