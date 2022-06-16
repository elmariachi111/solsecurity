const KeepASecret = artifacts.require('KeepASecret');

module.exports = async (callback) => {
  try {
    const sender = "0xE231B4e55fE1D0Afb3e746e64E78eEffB5b599d1";
    //assuming no ABI is exposed
    const contractAddress = "0x215371DD03B11dEfb94391078F8Ab03b3BD28816";
    const guess = "f1b58c5371b59bb44e16451a7c6c201da0e987654a47f7f9635ee928266e38f7";
    const guessSignature = web3.utils.keccak256("guessSecret(bytes32)").substr(0, 10);

    const calldata = guessSignature + guess;
    const tx = {
      from: sender,
      to: contractAddress,
      data: calldata,
    }

    const result = await web3.eth.sendTransaction(tx);
    console.log(result);
  } catch (err) {
    console.log('Oops: ', err.message);
  }
  callback();
};
