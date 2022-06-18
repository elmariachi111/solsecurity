//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract VariableShadowing {
  bool public alive = true;
  uint256 public value = 0;

  function selfdestruct(address payable beneficiary) internal {
    alive = false;
  }

  function addValue(uint256 x) public {
    value += x;
  }
}

// contract ContractDestroyer is VariableShadowing {
//   function destroy() public {
//     selfdestruct(payable(msg.sender));
//   }
// }
