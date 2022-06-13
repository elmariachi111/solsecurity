const KeepASecret = artifacts.require('KeepASecret');

module.exports = async (callback) => {
  try 
  {
    const contractAddress = "0x215371DD03B11dEfb94391078F8Ab03b3BD28816";
    const contract = await KeepASecret.at(contractAddress);
    const slot0 = await web3.eth.getStorageAt(contract.address, 0);
    console.log("storage slot 0 [%s]", slot0);
    
  } catch(err) {
    console.log('Oops: ', err.message);
  }
  callback();
};
