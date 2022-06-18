//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import { EvenAdder } from "./EvenAdder.sol";

contract AdderClient {
  function addWithContractInterface(EvenAdder adder, uint256 value) public {
    adder.addEvenNumber(value);
  }

  function addWithLowLevelCall(address adder, uint256 value) public {
    bytes memory payload = abi.encodeWithSignature(
      "addEvenNumber(uint256)",
      value
    );
    (bool success, bytes memory returnData) = adder.call(payload);
  }
}
