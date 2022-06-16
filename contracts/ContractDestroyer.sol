//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { VariableShadowing } from "./VariableShadowing.sol";

contract ContractDestroyer is VariableShadowing {
  function destroy() public {
    selfdestruct(payable(msg.sender));
  }
}
