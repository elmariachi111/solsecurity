//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import "./TokenIssuer.sol";

contract TokenGranter {
  TokenIssuer private _issuer;

  constructor(TokenIssuer issuer) {
    _issuer = issuer;
  }

  function grantTokens() external returns (uint256) {
    return _issuer.issueTokens(msg.sender);
  }
}
