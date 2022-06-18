const { expect } = require("chai");
const {
  expectRevert
} = require('@openzeppelin/test-helpers');

const HighNoon = artifacts.require("HighNoon.sol");


contract("Timestamps", accounts => {
  it("unlocks at a certain timestamp", async () => {

    await new Promise((resolve, reject) => {
      web3.currentProvider.send({
        method: 'evm_setTime',
        params: [(new Date()).getTime()],
      }, () => resolve())
    });

    const startsAt = (Math.floor((new Date()).getTime() / 1000) + 10);
    const highNoon = await HighNoon.new(startsAt);
    await expectRevert(highNoon.draw(), "not started");

    let winningTimestamp = startsAt;
    while (winningTimestamp % 43 !== 0) {
      winningTimestamp++;
    }

    await new Promise((resolve, reject) => {
      web3.currentProvider.send({
        method: 'evm_setTime',
        params: [winningTimestamp * 1000],
      }, () => {
        web3.currentProvider.send({
          method: 'evm_mine',
          params: [],
        }, () => resolve());
      });
    })

    await highNoon.draw();

    const hasWon = await highNoon.wins(accounts[0]);
    expect(hasWon.toNumber()).to.equal(1);
  });

});
