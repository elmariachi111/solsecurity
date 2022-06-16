const { expect } = require("chai");
const chai = require("chai")
const { solidity } = require("ethereum-waffle");
chai.use(solidity);

const ContractDestroyer = artifacts.require("ContractDestroyer.sol");

contract("ContractDestroyer", accounts => {
  it("can call self destruct but nothing happens", async () => {
    const instance = await ContractDestroyer.new();
    await instance.addValue(42);

    await instance.destroy();
    const val = await instance.value();
    expect(val.toNumber()).to.equal(42);

  });
});
