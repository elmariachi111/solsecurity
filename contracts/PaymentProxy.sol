//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract PaymentProxy {
  mapping(address => uint256) public balances;
  mapping(address => uint256) public nonces;
  mapping(bytes32 => bool) public signatureUsed;

  receive() external payable {
    balances[msg.sender] += msg.value;
  }

  function payWithSignature(
    address from,
    address to,
    uint256 amount,
    bytes memory signature
  ) public {
    (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
    uint256 nonce = nonces[from];

    bytes32 message = prefixed(
      keccak256(abi.encodePacked(from, to, amount, nonce))
    );
    address recovered = ecrecover(message, v, r, s);
    require(
      from == address(recovered),
      string(abi.encodePacked("bad signature"))
    );
    require(
      balances[from] > 0 && balances[from] - amount >= 0,
      "insufficient funds"
    );

    balances[from] -= amount;
    balances[to] += amount;
    nonces[from] = nonce + 1;
  }

  //https://swcregistry.io/docs/SWC-117
  function payWithMalleableSignature(
    address from,
    address to,
    uint256 amount,
    bytes memory signature,
    uint256 nonce
  ) public {
    (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);

    bytes32 message = prefixed(
      keccak256(abi.encodePacked(from, to, amount, nonce))
    );
    bytes32 sigid = keccak256(abi.encodePacked(message, signature));
    require(!signatureUsed[sigid], "signature already used");

    address recovered = ecrecover(message, v, r, s);
    require(
      from == address(recovered),
      string(abi.encodePacked("bad signature"))
    );
    require(
      balances[from] > 0 && balances[from] - amount >= 0,
      "insufficient funds"
    );

    signatureUsed[sigid] = true;
    balances[from] -= amount;
    balances[to] += amount;
  }

  function splitSignature(bytes memory sig)
    internal
    pure
    returns (
      uint8 v,
      bytes32 r,
      bytes32 s
    )
  {
    require(sig.length == 65);

    assembly {
      // first 32 bytes, after the length prefix.
      r := mload(add(sig, 32))
      // second 32 bytes.
      s := mload(add(sig, 64))
      // final byte (first byte of the next 32 bytes).
      v := byte(0, mload(add(sig, 96)))
    }

    return (v, r, s);
  }

  function prefixed(bytes32 hash) internal pure returns (bytes32) {
    return
      keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
  }
}
