const chai = require("chai")
const { solidity } = require("ethereum-waffle");
chai.use(solidity);

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
    chai.expect(web3.utils.fromWei(contractBalance)).to.equal("1");

    await instance.withdraw(web3.utils.toWei("1", "ether"));
    const newContractBalance = await web3.eth.getBalance(instance.address);
    chai.expect(newContractBalance).to.equal("0");
  });

  it("throws when overflown", async () => {
    const instance = await NumberOverflows.deployed();

    // await web3.eth.sendTransaction({
    //   from: accounts[0],
    //   to: instance.address,
    //   value: web3.utils.toWei("1", "ether")
    // });

    await web3.eth.sendTransaction({
      from: accounts[0],
      to: instance.address,
      value: web3.utils.toWei("2", "ether")
    });

    const withdrawal = instance.withdraw(web3.utils.toWei("1", "ether"), { from: accounts[1] });
    await chai.expect(withdrawal).to.be.revertedWith("SafeMath: subtraction overflow")

  })

});
