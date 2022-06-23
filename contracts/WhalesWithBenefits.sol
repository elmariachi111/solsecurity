//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract WhalesWithBenefits {
  struct Member {
    bytes32 passport;
    uint256 funds;
  }

  mapping(address => Member) public memberMap;
  address[] public members;

  function memberCount() public view returns (uint256) {
    return members.length;
  }

  function allWhaleMembers() public view returns (address[] memory) {
    uint256 len = members.length;
    address[] memory _whales = new address[](5);
    uint256 whaleIdx = 0;
    for (uint256 i = 0; i < len; i++) {
      Member memory mem = memberMap[members[i]];
      if (mem.funds > 1 ether) {
        _whales[whaleIdx++] = members[i];
      }
      if (whaleIdx == 5) return _whales;
    }
    address[] memory onlyWhales = new address[](whaleIdx);
    if (whaleIdx > 0) {
      for (uint256 i = 0; i < whaleIdx; i++) {
        onlyWhales[i] = _whales[i];
      }
    }
    return onlyWhales;
  }

  function signup(address newMember, uint256 funds) external {
    address[] memory membersWithMoreThanOneEth = allWhaleMembers();

    require(
      membersWithMoreThanOneEth.length <= 5,
      "we already have 5 whales aboard"
    );
    memberMap[newMember] = Member({
      passport: keccak256(abi.encodePacked(newMember)),
      funds: funds
    });

    members.push(newMember);
  }
}
