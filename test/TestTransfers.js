const { expect } = require("chai");
const {
  expectRevert, expectEvent
} = require('@openzeppelin/test-helpers');
const { web3 } = require("@openzeppelin/test-helpers/src/setup");

const MoneyDispatcher = artifacts.require("MoneyDispatcher.sol");
const IDontWantYourMoney = artifacts.require("IDontWantYourMoney.sol");
const Bequeather = artifacts.require("Bequeather.sol");
const SignedDepositor = artifacts.require("SignedDepositor.sol");

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

  it("can transfer funds using selfdestruct", async () => {
    const bequeather = await Bequeather.new(iDontWantYourMoney.address);

    let unwantedBalance = await web3.eth.getBalance(iDontWantYourMoney.address);
    expect(unwantedBalance).to.be.equal("0");

    await web3.eth.sendTransaction({ from: accounts[0], to: bequeather.address, value: ONE_ETH })
    const result = await bequeather.farewell();
    unwantedBalance = await web3.eth.getBalance(iDontWantYourMoney.address);

    expect(unwantedBalance).to.be.equal(ONE_ETH);
  });

  it("falls back on the default function when ABI is incorrect", async () => {
    const depositor = await SignedDepositor.new();
    const badABI = [{
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "depositor",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "amount",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "int96",
          "name": "purpose",
          "type": "int96"
        }
      ],
      "name": "Deposited",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "amount",
          "type": "uint256"
        }
      ],
      "name": "GrantReceived",
      "type": "event"
    }, {
      "inputs": [
        {
          //this is wrong!
          "internalType": "uint256",
          "type": "uint256",
          "name": "purpose"
        }
      ],
      "name": "deposit",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    }]

    const badDepositor = new web3.eth.Contract(badABI, depositor.address, { from: accounts[0] });
    const receipt = await badDepositor.methods.deposit(42).send({ value: ONE_ETH });

    console.log(JSON.stringify(receipt, null, 2))
    expectEvent(receipt, "GrantReceived", {
      amount: ONE_ETH
    })

  });

});
