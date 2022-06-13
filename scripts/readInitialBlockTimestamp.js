const KeepASecret = artifacts.require('KeepASecret');

module.exports = async (callback) => {
  try 
  {
    const contractAddress = "0x215371DD03B11dEfb94391078F8Ab03b3BD28816";
    const transactionHash = "0x717c916ca99d3ea0f8110331b929cbffe7e50416d0ebe3476e1297458a6f71fc";
    const contract = await KeepASecret.at(contractAddress);

    const transaction = await web3.eth.getTransaction(transactionHash);
    const block = await web3.eth.getBlock(transaction.blockNumber);
    const guess = web3.utils.keccak256(web3.utils.encodePacked(block.timestamp));
  
    console.log("contract deployed at %d. Calculated guess [%s]", block.timestamp, guess);
    
  } catch(err) {
    console.log('Oops: ', err.message);
  }
  callback();
};
