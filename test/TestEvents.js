const {
  expectEvent
} = require('@openzeppelin/test-helpers');
const { web3 } = require('@openzeppelin/test-helpers/src/setup');

const TokenIssuer = artifacts.require("TokenIssuer.sol");
const TokenGranter = artifacts.require("TokenGranter.sol");

contract("Events", accounts => {
  it("called events are visible on responses", async () => {
    const issuer = await TokenIssuer.new();
    const granter = await TokenGranter.new(issuer.address);

    const result = await granter.grantTokens();
    const issuanceEvents = await issuer.getPastEvents("TokensIssued", "earliest");

    //console.log(issuer.address, accounts[0], issuanceEvents);

    await expectEvent.inTransaction(
      result.receipt.transactionHash,
      issuer,
      "TokensIssued",
      { amount: "1000000", to: accounts[0] }
    )
  });


});
