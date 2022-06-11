const KeepASecret = artifacts.require('KeepASecret');

module.exports = async (callback) => {
  try {
    const contract = await KeepASecret.deployed();
    const secret = await web3.eth.getStorageAt(contract.address, 0);
    await contract.guessSecret(secret);
  } catch(err) {
    console.log('Oops: ', err.message);
  }
  callback();
};
