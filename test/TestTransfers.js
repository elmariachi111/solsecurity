const { expect } = require("chai");
const {
  expectRevert
} = require('@openzeppelin/test-helpers');
const { web3 } = require("@openzeppelin/test-helpers/src/setup");

const MoneyDispatcher = artifacts.require("MoneyDispatcher.sol");
const IDontWantYourMoney = artifacts.require("IDontWantYourMoney.sol");
const IConsumeGas = artifacts.require("IConsumeGas.sol");

const ONE_ETH = web3.utils.toWei("1", "ether");
const TWO_ETH = web3.utils.toWei("2", "ether");

contract("MoneyDispatcher", accounts => {
  let moneyDispatcher;
  let iDontWantYourMoney;
  beforeEach(async () => {
    moneyDispatcher = await MoneyDispatcher.new();
    iDontWantYourMoney = await IDontWantYourMoney.new();
  })

  it("can regularly deposit funds", async () => {
    await moneyDispatcher.deposit({ from: accounts[0], value: ONE_ETH });
    const res = await moneyDispatcher.transferFundsWithTransfer(accounts[0], ONE_ETH);
    expect(res.receipt.gasUsed).to.be.lessThan(40_000);
  });

  it("reverts when using transfer", async () => {
    await moneyDispatcher.deposit({ from: accounts[0], value: ONE_ETH });
    await expectRevert.unspecified(moneyDispatcher.transferFundsWithTransfer(iDontWantYourMoney, ONE_ETH))
  });

  it("doesnt revert when using send", async () => {
    await moneyDispatcher.deposit({ from: accounts[0], value: ONE_ETH });
    await moneyDispatcher.transferFundsWithSend(iDontWantYourMoney.address, ONE_ETH);
    const deposit = await moneyDispatcher.deposits(accounts[0]);
    const balance = await web3.eth.getBalance(moneyDispatcher.address);
    expect(web3.utils.fromWei(deposit)).to.equal("0");
    expect(web3.utils.fromWei(balance)).to.equal("1");
  });

  it("doesnt revert when using call", async () => {
    await moneyDispatcher.deposit({ from: accounts[0], value: ONE_ETH });
    await moneyDispatcher.transferFundsWithCall(iDontWantYourMoney.address, ONE_ETH);
    const deposit = await moneyDispatcher.deposits(accounts[0]);
    const balance = await web3.eth.getBalance(moneyDispatcher.address);
    expect(web3.utils.fromWei(deposit)).to.equal("0");
    expect(web3.utils.fromWei(balance)).to.equal("1");
  });

  // it("calls forward all available gas", async () => {
  //   const iConsumeGas = await IConsumeGas.new();
  //   await moneyDispatcher.deposit({ from: accounts[0], value: ONE_ETH });
  //   const res = await moneyDispatcher.transferFundsWithCall(iConsumeGas.address, ONE_ETH);
  //   expect(res.receipt.gasUsed).to.be.greaterThan(100_000);
  // });

  // it("send forwards all available gas", async () => {
  //   const iConsumeGas = await IConsumeGas.new();
  //   await moneyDispatcher.deposit({ from: accounts[0], value: ONE_ETH });
  //   const res = await moneyDispatcher.transferFundsWithSend(iConsumeGas.address, ONE_ETH);
  //   expect(res.receipt.gasUsed).to.be.greaterThan(100_000);
  // });

});
