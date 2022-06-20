const { expect } = require("chai");
const {
  expectRevert
} = require('@openzeppelin/test-helpers');

const NumberOverflows = artifacts.require("NumberOverflows.sol");

contract("NumberOverflows", accounts => {
  it("allows regular deposits and withdrawals", async () => {
    const instance = await NumberOverflows.deployed();

    await web3.eth.sendTransaction({
      from: accounts[0],
      to: instance.address,
      value: web3.utils.toWei("1", "ether")
    })

    const contractBalance = await web3.eth.getBalance(instance.address);
    expect(web3.utils.fromWei(contractBalance)).to.equal("1");

    await instance.withdraw(web3.utils.toWei("1", "ether"));
    const newContractBalance = await web3.eth.getBalance(instance.address);
    expect(newContractBalance).to.equal("0");
  });

  it("throws when overflown", async () => {
    const instance = await NumberOverflows.deployed();

    await web3.eth.sendTransaction({
      from: accounts[0],
      to: instance.address,
      value: web3.utils.toWei("2", "ether")
    });

    await expectRevert(
      instance.withdraw(web3.utils.toWei("1", "ether"), { from: accounts[1] }),
      "Panic: Arithmetic overflow" // Sol > 0.8
      //"SafeMath: subtraction overflow" // Sol < 0.8
    )

  })

  it("allows batch overflows", async () => {
    const instance = await NumberOverflows.deployed();

    const uint255 = (new web3.utils.BN(2)).pow(new web3.utils.BN(255));
    await instance.batchTransfer([accounts[2], accounts[3]], uint255, {
      from: accounts[1]
    });

    const attackerBalance = await instance.balances(accounts[2]);
    expect(attackerBalance.toString()).to.equal("57896044618658097711785492504343953926634992332820282019728792003956564819968");

    await instance.withdraw(web3.utils.toWei("2", "ether"), { from: accounts[2] });
  })
});
