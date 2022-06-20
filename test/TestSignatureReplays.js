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

const createMalledSig = (signature) => {
  const r = signature.slice(0, 66)
  const s = web3.utils.toBN('0x' + signature.slice(66, 130))
  const v = web3.utils.hexToNumber('0x' + signature.slice(130, 132))

  const secp256k1n = web3.utils.toBN("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

  const newS = secp256k1n.sub(s);
  newV = v == 27 ? 28 : 27;

  const sx = web3.utils.toHex(newS).substr(2);
  const vx = web3.utils.toHex(newV).substr(2);
  const newSig = r + sx + vx;
  return newSig;
}

contract("Signatures", accounts => {

  it("can use a signature to claim funds", async () => {
    const proxy = await createProxy(accounts[0]);
    const nonce = 0;
    const amount = web3.utils.toWei("0.25", "ether");

    const msg = web3.utils.soliditySha3(accounts[0], accounts[1], amount, nonce);
    const signature = await web3.eth.sign(msg, accounts[0]);

    await proxy.payWithSignature(accounts[0], accounts[1], amount, signature, {
      from: accounts[2]
    });

    // await proxy.payWithSignature(accounts[0], accounts[1], amount, signature, {
    //   from: accounts[2]
    // });

    const bal = await proxy.balances(accounts[1])
    expect(web3.utils.fromWei(bal, 'ether')).to.equal("0.25");

  })

  //https://medium.com/cypher-core/replay-attack-vulnerability-in-ethereum-smart-contracts-introduced-by-transferproxy-124bf3694e25
  it("can reuse a signature on another instance", async () => {
    const proxy = await createProxy(accounts[0]);
    const anotherProxy = await createProxy(accounts[0]);

    const nonce = 0;
    const amount = web3.utils.toWei("0.25", "ether");

    const msg = web3.utils.soliditySha3(accounts[0], accounts[1], amount, nonce);
    const signature = await web3.eth.sign(msg, accounts[0]);

    await proxy.payWithSignature(accounts[0], accounts[1], amount, signature, {
      from: accounts[2]
    });

    await anotherProxy.payWithSignature(accounts[0], accounts[1], amount, signature, {
      from: accounts[2]
    });

    const bal = await anotherProxy.balances(accounts[1])
    expect(web3.utils.fromWei(bal, 'ether')).to.equal("0.25");

  })

  it("can create a valid signature for the same action", async () => {
    const proxy = await createProxy(accounts[0]);

    const nonce = 0;
    const amount = web3.utils.toWei("0.25", "ether");

    const msg = web3.utils.soliditySha3(accounts[0], accounts[1], amount, nonce);
    const signature = await web3.eth.sign(msg, accounts[0]);

    const recovered = await web3.eth.accounts.recover(msg, signature);
    expect(recovered).to.equal(accounts[0]);

    const mSig = createMalledSig(signature)

    const malledRecovered = await web3.eth.accounts.recover(msg, mSig);
    expect(malledRecovered).to.equal(recovered);

    // await proxy.payWithSignature(accounts[0], accounts[1], amount, signature, {
    //   from: accounts[2]
    // });

    await proxy.payWithSignature(accounts[0], accounts[1], amount, mSig, {
      from: accounts[2]
    });

    const bal = await proxy.balances(accounts[1])
    expect(web3.utils.fromWei(bal, 'ether')).to.equal("0.25");

  });

});
