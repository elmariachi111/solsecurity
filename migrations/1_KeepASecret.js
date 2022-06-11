const KeepASecret = artifacts.require("KeepASecret");

module.exports = function (deployer) {
  deployer.deploy(KeepASecret);
};