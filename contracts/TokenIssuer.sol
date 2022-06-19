//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract TokenIssuer {
  uint256 internal constant ISSUANCE = 1_000_000;
  mapping(address => uint256) internal balances;

  event TokensIssued(
    address indexed caller,
    address indexed to,
    uint256 amount,
    uint256 balance
  );

  function issueTokens(address to) public returns (uint256) {
    balances[to] += ISSUANCE;

    emit TokensIssued(msg.sender, to, ISSUANCE, balances[to]);
    return balances[to];
  }
}
