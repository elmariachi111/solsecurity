const { expect } = require("chai");
const {
  expectRevert
} = require('@openzeppelin/test-helpers');

const AdderClient = artifacts.require("AdderClient.sol");
const EvenAdder = artifacts.require("EvenAdder.sol");

contract("AdderClient", accounts => {
  it("just works with even numbers", async () => {
    const adderClient = await AdderClient.new();
    const evenAdder = await EvenAdder.new(0);

    await adderClient.addWithContractInterface(evenAdder.address, 2);
    const newVal = await evenAdder.value();
    expect(newVal.toNumber()).to.equal(2);
  });

  it("reverts when called by its interface", async () => {
    const adderClient = await AdderClient.new();
    const evenAdder = await EvenAdder.new(0);

    await expectRevert(adderClient.addWithContractInterface(evenAdder.address, 3), "Custom error");
  });

  it("doesnt revert when called by lowlevel call", async () => {
    const adderClient = await AdderClient.new();
    const evenAdder = await EvenAdder.new(0);

    await adderClient.addWithLowLevelCall(evenAdder.address, 3);
  });

  it("doesnt revert on low level calls to random addresses", async () => {
    const adderClient = await AdderClient.new();

    const { address: someAddress } = web3.eth.accounts.create();
    await adderClient.addWithLowLevelCall(someAddress, 3);
  });

});
