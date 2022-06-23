const OutOfGas = artifacts.require("OutOfGas.sol");
const {
  expectRevert
} = require('@openzeppelin/test-helpers');

contract("OutOfGas", accounts => {
  it("can send to one address ", async () => {
    const oog = await OutOfGas.new();

    await web3.eth.sendTransaction({
      from: accounts[0],
      to: oog.address,
      value: web3.utils.toWei("1", "ether")
    });

  });

  it("can add 100 accounts", async () => {
    const oog = await OutOfGas.new();

    const oneHundredMembers = [...Array(100).keys()].map(i => web3.eth.accounts.create("test accounts").address);
    await oog.addManyRecipients(oneHundredMembers);
  });

  it("can't add 2000 accounts", async () => {
    const oog = await OutOfGas.new();

    const twoThousandMembers = [...Array(2000).keys()].map(i => web3.eth.accounts.create("test accounts").address);
    await expectRevert(oog.addManyRecipients(twoThousandMembers), "after consuming all gas");
  });

  it("can send to several addresses ", async () => {
    const oog = await OutOfGas.new();

    await oog.addRecipient(web3.eth.accounts.create("test accounts").address);

    await web3.eth.sendTransaction({
      from: accounts[0],
      to: oog.address,
      value: web3.utils.toWei("1", "ether")
    });

    await oog.addRecipient(web3.eth.accounts.create("test accounts").address);
    await web3.eth.sendTransaction({
      from: accounts[0],
      to: oog.address,
      value: web3.utils.toWei("1", "ether")
    });

    await oog.addRecipient(web3.eth.accounts.create("test accounts").address);
    await expectRevert.unspecified(web3.eth.sendTransaction({
      from: accounts[0],
      to: oog.address,
      value: web3.utils.toWei("1", "ether")
    }));
  });
});
