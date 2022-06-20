const { expect } = require("chai");
const {
  expectRevert
} = require('@openzeppelin/test-helpers');
const { web3 } = require("@openzeppelin/test-helpers/src/setup");

const PaymentProxy = artifacts.require("PaymentProxy.sol");

const createProxy = async (account) => {
  const proxy = await PaymentProxy.new();

  await web3.eth.sendTransaction({
    from: account,
    to: proxy.address,
    value: web3.utils.toWei("1", "ether")
  });

  const funds = await proxy.balances(account);
  expect(web3.utils.fromWei(funds, 'ether')).to.equal("1");

  return proxy;
}

contract("Signatures", accounts => {
  it("can reuse a signature to release funds twice", async () => {
    const proxy = await createProxy(accounts[0]);
    const nonce = 0;
    const amount = web3.utils.toWei("0.25", "ether");

    const msg = web3.utils.soliditySha3(accounts[0], accounts[1], amount);
    const signature = await web3.eth.sign(msg, accounts[0]);

    const bal0 = await proxy.balances(accounts[1])
    expect(web3.utils.fromWei(bal0, 'ether')).to.equal("0");

    await proxy.payWithSignature(accounts[0], accounts[1], amount, signature, {
      from: accounts[2]
    });

    await proxy.payWithSignature(accounts[0], accounts[1], amount, signature, {
      from: accounts[2]
    });

    const bal = await proxy.balances(accounts[1])
    expect(web3.utils.fromWei(bal, 'ether')).to.equal("0.5");

  })

});
