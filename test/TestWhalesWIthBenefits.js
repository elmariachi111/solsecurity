const {
  expectEvent, expectRevert
} = require('@openzeppelin/test-helpers');
const { web3 } = require('@openzeppelin/test-helpers/src/setup');
const { expect } = require('chai');

const WhalesWithBenefits = artifacts.require("WhalesWithBenefits.sol");

contract("Gas intensive Transactions", accounts => {
  it("can add some members without a problem", async () => {
    const wwb = await WhalesWithBenefits.new();
    const newMembers = [...Array(20).keys()].map(i => web3.eth.accounts.create("some entropy"));
    await wwb.signup(newMembers[0].address, web3.utils.toWei("0.5", "ether"))

    let whaleMembers = await wwb.allWhaleMembers();
    expect(whaleMembers.length).to.equal(0);

    await wwb.signup(newMembers[1].address, web3.utils.toWei("1.5", "ether"))
    whaleMembers = await wwb.allWhaleMembers();
    expect(whaleMembers.length).to.equal(1);
  });

  it("can add many members without a problem", async () => {

    const wwb = await WhalesWithBenefits.new();
    const newMembers = [...Array(20).keys()].map(i => web3.eth.accounts.create("some entropy"));
    const promises = newMembers.slice(0, 10).map(async (account) =>
      await wwb.signup(account.address, web3.utils.toWei("0.5", "ether"), {
        gas: 200_000
      })
    )
    let res = await Promise.all(promises);
    let gasUsed = res.map(r => r.receipt.gasUsed);

    let whaleMembers = await wwb.allWhaleMembers();
    expect(whaleMembers.length).to.equal(0);

    const promisesWhales = newMembers.slice(10, 15).map(account =>
      wwb.signup(account.address, web3.utils.toWei("1.5", "ether"), {
        gas: 200_000
      })
    )

    res = await Promise.all(promisesWhales);
    gasUsed = gasUsed.concat(res.map(r => r.receipt.gasUsed));

    const memLength = await (wwb.memberCount());
    expect(memLength.toNumber()).to.eq(15);

    whaleMembers = await wwb.allWhaleMembers();
    expect(whaleMembers.length).to.equal(5);

    await expectRevert(wwb.signup(newMembers[16].address, web3.utils.toWei("0.5", "ether"), {
      gas: 200_000
    }), "after consuming all gas");
  })

});
