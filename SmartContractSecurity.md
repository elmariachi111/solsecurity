## Be paranoid about your keys’ safety

https://twitter.com/osf_nft/status/1469261873111609346

https://twitter.com/thisiswenzel/status/1470419227337056259

[The Complete Security Guide to keep you, your computer, and your crypto safe : CryptoCurrency](https://www.reddit.com/r/CryptoCurrency/comments/rbd7q2/the_complete_security_guide_to_keep_you_your/)

https://twitter.com/LittlelemonsNFT/status/1477923368053706755

### Hardware based ledgers

[The Safest Way to Use MetaMask With Ledger Hardware Wallet | Ledger](https://www.ledger.com/academy/security/the-safest-way-to-use-metamask)

### Split keys

[Recovery Methods in Wallets | Stories](https://www.dynamic.xyz/blog/recovery-methods-in-wallets-an-overview)

### Use Truffle Dashboard to hide your keys during development

### How to recognize scams

https://medium.com/nexus-mutual/responsible-vulnerability-disclosure-ece3fe3bcefa

https://twitter.com/dingalingts/status/1470095710888808449

https://medium.com/@hugh_karp/nxm-hack-update-72c5c017b48

https://twitter.com/HughKarp/status/1341063567408328705

https://twitter.com/thisiswenzel/status/1470419224078159877

https://twitter.com/LittlelemonsNFT/status/1477923368053706755

https://twitter.com/thisiswenzel/status/1483602921854062596

https://twitter.com/thisiswenzel/status/1487063477609017348

https://twitter.com/richerd/status/1488735217934225408

https://twitter.com/0xQuit/status/1506702991834824704

https://twitter.com/tayvano_/status/1516225457640787969

### Safe Entropy

[Introduction &#xB7; Pro Tips for Ethereum Wallet Management](https://silentcicero.gitbooks.io/pro-tips-for-ethereum-wallet-management/content/)

[Ian Coleman&apos;s Bip39 Tool &#xB7; Pro Tips for Ethereum Wallet Management](https://silentcicero.gitbooks.io/pro-tips-for-ethereum-wallet-management/content/ethereum-wallet-basics/ian-colemans-bip39-tool.html)

[Generating Safe Entropy (Randomness) &#xB7; Pro Tips for Ethereum Wallet Management](https://silentcicero.gitbooks.io/pro-tips-for-ethereum-wallet-management/content/password-management/generating_safe_entropy.html)

### Multisignature safety

[What is Gnosis Safe? | Gnosis Help Center](https://help.gnosis-safe.io/en/articles/3876456-what-is-gnosis-safe)

[Why use the Gnosis Multi-Signature Wallet &#xB7; Pro Tips for Ethereum Wallet Management](https://silentcicero.gitbooks.io/pro-tips-for-ethereum-wallet-management/content/gnosis-multi-signature-wallet/why-use-the-gnosis-multi-signature-wallet.html)

## Avoid Solidity related pitfalls

### Data visibility

Even though they're built on crypto primitives, you can't hide anything on a blockchain. A very tempting beginner's error is to assume that `private` members of Solidity contracts could effectively hide information for others but that's not true. The `private` modifier, as in any other programming language is merely a hint to implementers how variables or functions are supposed to be used. 

As an example, consider this contract that pays out all its funds to a caller who guessed its "secret" variable correctly:

```solidity
//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract KeepASecret {
  bytes32 private         _secret;
  address payable private _owner;

  constructor() {
    _secret = keccak256(abi.encodePacked(block.timestamp));
  }

  receive() external payable {}

  function guessSecret(bytes32 guess) payable external {
    require (_secret == guess, "guess again");
    _secret = keccak256(abi.encodePacked(block.timestamp));
    _owner = payable(msg.sender);
    _owner.transfer(address(this).balance);
  }
}
```

it contains two clear misunderstandings. First, the seemingly random `block.timestamp` can be easily retrieved by  looking at the block where the contract has been instantiated. You can use any block explorer to find the initial deployment transaction, get its block's timestamp and construct a correct guess for your `guessSecret` call. This is how its done:

```javascript
const deployTransaction = await web3.eth.getTransaction(deployTransactionHash);
const block = await web3.eth.getBlock(deployTransaction.blockNumber);
const guess = web3.utils.keccak256(web3.utils.encodePacked(block.timestamp));
```

For consecutive calls that rely on the secret created by the previous call you instead would look for a previous call to `guessSecret` , get their block meta data including the timestamp and are able to reconstruct a valid guess, again. 

Actually there's a much more trivial way to retrieve the currently stored "secret" value. As stated, the `private` modifier only means that there's no way of calling code that would yield the variable's value but you can simply peek into the contract state by using a `getStorageAt` RPC call. 

Assuming that you don't have the contract's ABI at hand, you only need to observe a previous call on the chain to learn about the guess method's call signature. By knowing (or constructing) the call signature, you can invoke the method with a valid guess like this:

```javascript
const contractAddress = "0x215371DD03B11dEfb94391078F8Ab03b3BD28816";
const contract = await KeepASecret.at(contractAddress);
const slot0 = await web3.eth.getStorageAt(contract.address, 0);
//-> yields value of storage slot 0 where the "secret" is stored

//the first 8 bytes of its interface hash are representing a method's binary call signature:
const guessSignature = web3.utils.keccak256("guessSecret(bytes32)").substr(0,10);
const tx = {
  from: sender,
  to: contractAddress,
  data: guessSignature + slot0,
}
await web3.eth.sendTransaction(tx);
```

### 

### Number Overflows

A wide range of vulnerabilities of smart contracts derive from arithmetic overflows, a problem that needed particular attention in the past. Overflows occur when operating on variables that are determined to predefined range, similar to a mileage meter that returns to "000000" when going past "999999" miles. Developers who are used to working in high level languages like Javascript might be so used to operating on signed arithmetic that they often miss this kind of logic errors:

```solidity
pragma solidity <0.8.0;

contract NumberOverflows {
  mapping(address => uint256) public balances;

  receive() external payable {
    balances[msg.sender] += msg.value;
  }

  function withdraw(uint256 _amount) public {
    assert(balances[msg.sender] - _amount >= 0);
    balances[msg.sender] -= _amount;
    payable(msg.sender).transfer(_amount);
  }
}
```

This contract's `withdraw` method allows any sender to withdraw as much funds as they like because the `balances` value type is an unsigned integer and wraps to `2^256-1` (an astronomically high value) when "dropping" below 0. 

The good news is that Solidity >0.8 added transparent support for this error class and would revert during the execution of the assertion. If you're writing code that requires using a Solidity version below 0.8, you're highly recommended to use one of the publicly available SafeMath implementations for any arithmetic operation, e.g. the one by OpenZeppelin:

```solidity
pragma solidity <0.8.0;

import "@openzeppelin/contracts/math/SafeMath.sol";

contract NumberOverflows {
  using SafeMath for uint256;
  //...
  function withdraw(uint256 _amount) public {
    assert(balances[msg.sender].sub(_amount) >= 0);
    balances[msg.sender] = balances[msg.sender].sub(_amount);
    payable(msg.sender).transfer(_amount);
  }
}
```

Arithmetic overflow conditions aren't always as obvious as in this example. Even though seems quite unlikely that multiplications on an `uint256` ever hit the roof, they can be tricked into that by users, like in this [classical]([NVD - CVE-2018-10299](https://nvd.nist.gov/vuln/detail/CVE-2018-10299#vulnCurrentDescriptionTitle)) "batchOverflow" example that could be found in several early ERC20 contracts:

```solidity
  function batchTransfer(address[] memory receivers, uint256 value) public {
    uint256 amount = receivers.length * value;
    //instead: uint256 amount = value.mul(receivers.length);

    require(balances[msg.sender] >= amount);

    balances[msg.sender] = balances[msg.sender].sub(amount);
    for (uint256 i = 0; i < receivers.length; i++) {
      balances[receivers[i]] = balances[receivers[i]].add(value);
    }
  }
```

Since an attacker is in full control over `batchTransfer`'s inputs, anyone can choose $2^{255}$ for `value` and provide 2 accounts. The multiplication overflow leads to `amount` being zero which passes the requirement (the attacker's `balance`  is 0). After the call `receivers` will end up with nearly unlimited balances and can withdraw as much funds from the contract as they like. Here's the attack's code:

```javascript
const instance = await NumberOverflows.deployed();
const uint255 = (new web3.utils.BN(2)).pow(new web3.utils.BN(255));

await instance.batchTransfer([accounts[2], accounts[3]], uint255, {
  from: accounts[8]
});

const attackerBalance = await instance.balances(accounts[2]);
expect(attackerBalance.toString()).to.equal("57896044618658097711785492504343953926634992332820282019728792003956564819968");
await instance.withdraw(web3.utils.toWei("2", "ether"), { from: accounts[2] });
```

A far more advanced example of a hard to detect underflow issue can be found in the [PoWHCoin attack from 2018](https://medium.com/@ebanisadr/how-800k-evaporated-from-the-powh-coin-ponzi-scheme-overnight-1b025c33b530).

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#precision)

TM integer division  [Solidity Best Practices for Smart Contract Security | ConsenSys](https://consensys.net/blog/developers/solidity-best-practices-for-smart-contract-security/)



### Constraining method visibility / variable shadowing

Even worse than making wrong assumptions about the effects of visibility modifiers is to simply forget using them.

```solidity
//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract MethodVisibility {
  address private owner;
  bool public paused = false;

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  modifier notPaused() {
    require(paused == false);
    _;
  }

  function initialize() public {
    owner = msg.sender;
  }

  function togglePause(bool _newVal) public onlyOwner {
    paused = _newVal;
  }

  function withdraw() public onlyOwner notPaused {
    payable(msg.sender).transfer(address(this).balance);
  }
}
```

Using initializers for contracts is pretty common, particularly when writing proxies, composeable or upgradeable contracts. The author of this example unfortunately forgot to constrain calls to the `initialize` method so that **anyone** could set themselves as the contract owner and withdraw funds. The Solidity compiler cannot warn about that issue because it is not aware about the method's intention and so this type of mistake is often overlooked. The default visibility of Solidity contract functions is *public* and since version 0.5 it's mandatory to add a visibility modifier to functions so developers at least are made aware of the issue.

A lesser notable issue is Solidity's feature to shadow contract members in derived contracts. It's even possible to shadow implementations of built in members like `revert` or `selfdestruct`. When deriving from contracts that shadowed those members, child contracts will behave differently as expected. Since 0.5 the Solidity Compiler and solhint is warning users when they write code that shadows builtin symbols.

```solidity
//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract VariableShadowing {
  bool public alive = true;
  uint256 public value = 0;

  function selfdestruct(address payable beneficiary) internal {
    alive = false;
  }

  function addValue(uint256 x) public {
    value += x;
  }
}

contract ContractDestroyer is VariableShadowing {
  function destroy() public {
    selfdestruct(payable(msg.sender));
  }
}
```

 TM find an OZ sample when shadowing makes sense

[not-so-smart-contracts/unprotected_function at master · crytic/not-so-smart-contracts · GitHub](https://github.com/crytic/not-so-smart-contracts/tree/master/unprotected_function)

[not-so-smart-contracts/variable shadowing at master · crytic/not-so-smart-contracts · GitHub](https://github.com/crytic/not-so-smart-contracts/tree/master/variable%20shadowing)

https://dasp.co/#item-2

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#visibility)

[Common Smart Contract Vulnerabilities and How To Mitigate Them | Yos Riady · Software Craftsman](https://yos.io/2018/10/20/smart-contract-vulnerabilities-and-how-to-mitigate-them/#vulnerability-implicit-visibility)

[Recommendations for Smart Contract Security in Solidity - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/recommendations/#explicitly-mark-visibility-in-functions-and-state-variables)

> execution order: ?
> 
> In Solidity, the order of evaluation of sub-expressions is *unspecified*. This
> means that in `f(g(), h())`, `g()` might get evaluated before `h()` or `h()` might get evaluated before `g()`. Practically, this order is predictable, but
> Solidity code shouldn’t depend on that behavior between compiler versions. In *most* circumstances `g()` is evaluated before `h()` (left-to-right order),
> which is also the behavior that most languages specify in their
> standards. However, in the case of emitting an event with indexed arguments, the
> arguments are evaluated right-to-left.

### Locking pragmas

### Error handling

Solidity comes with a choice of error handling paradigms that compare to concepts of other languages. Most contracts make use of `require` statements with string reasons like this one:

```solidity
require(n % 2 == 0, "must provide an even number or this fails")
```

Solidity 0.8.4 introduced support for custom error types that not only allows you to save on gas during deployment (the error strings have to be written on chain) but also become part of the contract ABI, they can carry parameters and can be documented using NatSpec. Also clients that support custom error types get a better idea on what went wrong and translate the error to something meaningful inside the current user context. 

```solidity
contract SomeContract {
  /**
   * @dev mainly used for illustration purposes
   * @param givenNumber the number that was supposed to be even but wasn't
   */
  error NotAnEvenNumber(uint256 givenNumber);

  function addEvenNumber(uint256 evenNumber) public returns (uint256) {
    if (evenNumber % 2 != 0) {
      revert NotAnEvenNumber(evenNumber);
    }
    //do anything
    return value;
  }
}
```

A pitfall that's highly recommended to be avoided arises from using low level `call`s to other contracts or using `address.send` instead of `address.transfer`.  Errors thrown during low level calls don't even bubble up to the calling context and must be checked by their boolean return value. Here's an example:

```solidity
//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract EvenAdder {
  error NotAnEvenNumber(uint256 givenNumber);

  uint256 public value;

  constructor(uint256 initialValue) {
    value = initialValue;
  }

  function addEvenNumber(uint256 evenNumber) public returns (uint256) {
    if (evenNumber % 2 != 0) {
      revert NotAnEvenNumber(evenNumber);
    }

    value += evenNumber;
    return value;
  }
}

contract AdderClient {
  function addWithContractInterface(EvenAdder adder, uint256 value) public {
    adder.addEvenNumber(value);
  }

  function addWithLowLevelCall(address adder, uint256 value) public {
    bytes memory payload = abi.encodeWithSignature(
      "addEvenNumber(uint256)",
      value
    );
    (bool success, bytes memory returnData) = adder.call(payload);
    require(sucess, "something went wrong"); // <-- this is mandatory!
  }
}
```

The `addWithContractInterface` function makes use of a concrete contract interface that's known at compile time. Errors caused by reversions of `addEvenNumber` propagate to the calling context and revert the transactions. In contrast, `addWithLowLevelCall` calls the contract by manually assembling a call payload manually using the method's interface signature at runtime. When`addEvenNumber(uint256)` fails, execution of the calling contract will continue unless it explicitly requires the low level call's return value to be `true`.

When delegating control to other contracts, e.g. to transfer funds between accounts, things get even more hairy. To transfer Ethers, developers have three options: `address.send`, `address.transfer`, `address.call` as illustrated in this example:

```solidity
//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract MoneyDispatcher {
  mapping(address => uint256) public deposits;

  function deposit() external payable {
    deposits[msg.sender] += msg.value;
  }

  //doesn't revert
  function transferFundsWithSend(address payable to, uint256 amount) public {
    bool success = to.send(amount);
    deposits[msg.sender] -= amount;
  }

  //doesn't revert
  function transferFundsWithCall(address payable to, uint256 amount) public {
    (bool success, bytes memory returnData) = to.call{ value: amount }("");
    deposits[msg.sender] -= amount;
  }

  //reverts
  function transferFundsWithTransfer(address payable to, uint256 amount)
    public
  {
    to.transfer(amount);
    deposits[msg.sender] -= amount;
  }
}

//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract IDontWantYourMoney {
  error NoMoneyAccepted();

  receive() external payable {
    revert NoMoneyAccepted();
  }
}
```

When a sender initiates a transfer towards an instance of `IDontWantYourMoney`, only `transferFundsWithTransfer` reverts the transaction. Since the `success` return values remain unchecked, all following statements are executed.

TM link to ERC20 vulnerabilities / check return values

[Recommendations for Smart Contract Security in Solidity - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/recommendations/#handle-errors-in-external-calls)

[External Calls - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/#handle-errors-in-external-calls)

[SWC-104 · Overview](https://swcregistry.io/docs/SWC-104)

https://medium.com/coinmonks/8-security-vulnerabilities-in-ethereum-smart-contracts-that-can-now-be-easily-avoided-dcb7de37a64

[Types &mdash; Solidity 0.8.16 documentation](https://docs.soliditylang.org/en/develop/types.html#members-of-addresses)

[not-so-smart-contracts/unchecked_external_call at master · crytic/not-so-smart-contracts · GitHub](https://github.com/crytic/not-so-smart-contracts/tree/master/unchecked_external_call)

[External Calls - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/#handle-errors-in-external-calls)

### Blockheight, time and randomness

Suprisingly, time is a rather blurry concept on blockchains. All transactions within one block use and carry that block's timestamp which is defined by its miner or validator. The Ethereum protocol restricts the upper bound of a block's timestamp to [15 seconds in the future]([go-ethereum/consensus.go at master · ethereum/go-ethereum · GitHub](https://github.com/ethereum/go-ethereum/blob/master/consensus/ethash/consensus.go#L275)) but practically miners and validators will only build upon blocks that have a reasonably correct time on them. Ethereum's peering protocol even requires miners to sync their machine's time with a correct time source.

Since the precise time at which transactions are executed is unpredictable and unreliable, smart contracts should take great care when relying on `block.timestamp`. Consider this raffle that starts at a given point in time and selects a winner when it's executed at a seemingly random timestamp that can be divided by 43:

```solidity
//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract HighNoon {
  uint256 private _gameStartsAt;
  bool public gameover = false;

  constructor(uint256 gameStartsAt) {
    _gameStartsAt = gameStartsAt;
  }

  function draw() public {
    require(block.timestamp > _gameStartsAt, "not started");
    require(!gameover, "someone else has won");
    if (block.timestamp % 43 == 0) {
      gameover = true;
      payable(msg.sender).transfer(1 ether);
    } else {
      revert("good luck next time");
    }
  }
}


```

While usual blockchain users have to trust to luck, block producers can create blocks by selecting a timestamp that's greater than `gameStartsAt` and divisible by 43 for a new block. In the same block they call `draw` themselves and finally publish it slightly ahead of time. The least trustful atom of granular time on an EVM blockchain therefore roughly translates to the blocktime the chain needs to proceed (~14 seconds on mainnet). 

Another approach to lock funds, actions or decisions for a certain minimal amount of time is using the current chain's block height. Since all blocks build on top of each other and the average block time usually doesn't change dramatically, it might be a better measure for passed time in comparison to the use of wall clocks. However, using block heights for time locks doesn't solve the "miner gets it first" issue either, since block producers still can condition their issuance of blocks on the block height they observe.  

In relation, creating forgery-proof randomness on blockchains is practically impossible without an external source of entropy because all effects of blockchains transactions  are deterministically predefined and any random condition can be constructed by parties that understand the requirements. 

There are various approaches that can crate reliable random values, the most battle tested ones being verifiable random functions (VRF) [as supplied by the Chainlink oracle network](https://blog.chain.link/vrf-v2-mainnet-launch/) (e.g. used by [PoolTogether](https://medium.com/pooltogether/using-chainlink-vrf-for-randomness-generation-in-pooltogether-619a4280a7ae)) and RanDAOs which require a timelocked commit reveal scheme powered by several parties (e.g. used in [Eth's consensus layer's beacon chain](https://eth2book.info/altair/part2/building_blocks/randomness)). 



https://blog.cotten.io/timing-future-events-in-ethereum-5fbbb91264e7

https://dasp.co/#item-8

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#entropy)

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#block-timestamp)

[Timestamp Dependence - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/)

[Common Smart Contract Vulnerabilities and How To Mitigate Them | Yos Riady · Software Craftsman](https://yos.io/2018/10/20/smart-contract-vulnerabilities-and-how-to-mitigate-them/#vulnerability-bad-randomness)

[security - How can I securely generate a random number in my smart contract? - Ethereum Stack Exchange](https://ethereum.stackexchange.com/questions/191/how-can-i-securely-generate-a-random-number-in-my-smart-contract)

[Randomness | solidity-patterns](https://fravoll.github.io/solidity-patterns/randomness.html)

https://medium.com/ginar-io/a-review-of-random-number-generator-rng-on-blockchain-fe342d76261b

[Introduction to Chainlink VRF | Chainlink Documentation](https://docs.chain.link/docs/chainlink-vrf/)

[Upgrading Ethereum](https://eth2book.info/altair/part2/building_blocks/randomness)

### Event emission & traceability

Logging events is far more than a plain debugging feature of contracts, in fact many services and applications heavily depend on events that are emitted by smart contracts to recover contract state, analyse the state history, trigger actions on user interfaces or monitor activity. It's adviseable to trigger events from functions that modify state so side effects can be read and reacted on by callers. This is particularly useful for transactions that call other contracts during their execution:

```solidity
//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract TokenIssuer {
  uint256 internal constant ISSUANCE = 1_000_000;
  mapping(address => uint256) internal balances;

  event TokensIssued(
    address indexed caller,
    address indexed to,
    uint256 amount,
    uint256 balance
  );

  function issueTokens(address to) public returns (uint256) {
    balances[to] += ISSUANCE;

    emit TokensIssued(msg.sender, to, ISSUANCE, balances[to]);
    return balances[to];
  }
}

contract TokenGranter {
  TokenIssuer private _issuer;

  constructor(TokenIssuer issuer) {
    _issuer = issuer;
  }

  function grantTokens() external returns (uint256) {
    return _issuer.issueTokens(msg.sender);
  }
}

```

`TokenGranter` grants users new tokens by delegating a call to a trusted `TokenIssuer`. Even though `grantTokens` is supposed to  return the current user's token balance, client code cannot access this return value since it will only be determined after block finality has been reached, hence state modifying contract interactions only yield a transaction receipt to their callers. Emitting `TokenIssued` events on the issuer's side lets clients quickly verify the effects of their transactions.

Events can be used to cheaply store state traces that would be highly expensive to store on chain instead (8 gas per byte vs 625 gas). Instead of keeping iterable inverse mappings, e.g. to find all NFTs owned by an user on a contract, indexers simply can replay all transactions and watch for `Transfer` events to build a mapping that can be queried independently from the blockchain. 

Lastly, using events allows monitoring tools to track what's happening on a contract, send alerts and even trigger maintenance events (e.g. pausing withdrawals) in case they find suspicious interactions.



[A Guide to Events and Logs in Ethereum Smart Contracts | ConsenSys](https://consensys.net/blog/developers/guide-to-events-and-logs-in-ethereum-smart-contracts/)

[Solidity Best Practices for Smart Contract Security | ConsenSys](https://consensys.net/blog/developers/solidity-best-practices-for-smart-contract-security/)

[Events and Logging in Solidity](https://blog.chain.link/events-and-logging-in-solidity/)

[How To Use Events In Solidity | HackerNoon](https://hackernoon.com/how-to-use-events-in-solidity-pe1735t5)



### Who is msg.sender & tx.origin

Considered an artefact of Ethereum's early days Solidity's `tx.origin` global variable seems to be a very convenient tool to find out about the transaction's original sender by traversing the call stack up to  its initial entrypoint. That's very helpful to find out whether the execution has been triggered by an external account (`require(tx.origin == msg.sender)`) but can become dangerous when being used for authenticating the caller.  `tx.origin` vulnerabilities rely on phishing attacks on priviledged users that are tricked into interacting with another contract that calls the attackable contract on their behalf:

```solidity
//SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract Wallet {
  address public _owner;

  constructor(address owner) {
    _owner = owner;
  }

  receive() external payable {}

  function withdrawAll(address payable recipient) public {
    //to stay safe: use msg.sender instead
    require(tx.origin == _owner);
    recipient.transfer(address(this).balance);
  }
}

contract Phisher {
  Wallet private _attackableWallet;
  address private _attacker;

  constructor(Wallet wallet, address attacker) {
    _attackableWallet = wallet;
    _attacker = attacker;
  }

  receive() external payable {
    _attackableWallet.withdrawAll(payable(_attacker));
  }
}
```

When the owner of the `Phisher` contract successfully tricks `Wallet`'s `owner` to interact with one of its methods, e.g. by simply sending some funds, it can call `withdrawAll` without a rejection since the transaction's origin resolves to the wallet's owner.

[Security Considerations &mdash; Solidity 0.8.13 documentation](https://docs.soliditylang.org/en/v0.8.13/security-considerations.html#tx-origin)

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#tx-origin)

[tx.origin - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/)

[SWC-115 · Overview](https://swcregistry.io/docs/SWC-115)

### Replay attacks

[Security Considerations &mdash; Solidity 0.8.13 documentation](https://docs.soliditylang.org/en/v0.8.13/security-considerations.html#minor-details)

[defcon26/Replay Attacks on Ethereum Smart Contracts.md at master · nkbai/defcon26 · GitHub](https://github.com/nkbai/defcon26/blob/master/docs/Replay%20Attacks%20on%20Ethereum%20Smart%20Contracts.md)

https://medium.com/cypher-core/replay-attack-vulnerability-in-ethereum-smart-contracts-introduced-by-transferproxy-124bf3694e25

[What is a Replay Attack?](https://academy.bit2me.com/en/que-es-un-ataque-replay/)

### Running out of gas

[Security Considerations &mdash; Solidity 0.8.13 documentation](https://docs.soliditylang.org/en/v0.8.13/security-considerations.html#gas-limit-and-loops)

https://medium.com/coinmonks/8-security-vulnerabilities-in-ethereum-smart-contracts-that-can-now-be-easily-avoided-dcb7de37a64

### Unwanted calls to self-destruct / the fallback function

[not-so-smart-contracts/incorrect_interface at master · crytic/not-so-smart-contracts · GitHub](https://github.com/crytic/not-so-smart-contracts/tree/master/incorrect_interface)

[How to Hack Smart Contracts: Self Destruct and Solidity | HackerNoon](https://hackernoon.com/how-to-hack-smart-contracts-self-destruct-and-solidity)

[How Ethereum lost $300 Million Dollars | HackerNoon](https://hackernoon.com/how-ethereum-lost-300-million-dollars-bfedf7ba0c19)

[Why are selfdestructs used in contract programming? - Ethereum Stack Exchange](https://ethereum.stackexchange.com/questions/315/why-are-selfdestructs-used-in-contract-programming)

[Recommendations for Smart Contract Security in Solidity - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/recommendations/#remember-that-ether-can-be-forcibly-sent-to-an-account)

[Known Attacks - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/known_attacks/#forcibly-sending-ether-to-a-contract)

### Publishing Contract Sourcecode (etherscan, ipfs, sourcify)

https://sourcify.dev/

## Follow best practices for contract interactions

### The Checks Effects Interactions pattern

[Common Smart Contract Vulnerabilities and How To Mitigate Them | Yos Riady · Software Craftsman](https://yos.io/2018/10/20/smart-contract-vulnerabilities-and-how-to-mitigate-them/#use-checks-effects-interactions)

[DeadfrenzAttack/REPORT.md at main · hjorthjort/DeadfrenzAttack · GitHub](https://github.com/hjorthjort/DeadfrenzAttack/blob/main/REPORT.md)

### Pull vs Push Payments, why plain transfers are evil

[Pull over Push | solidity-patterns](https://fravoll.github.io/solidity-patterns/pull_over_push.html)

[Secure Ether Transfer | solidity-patterns](https://fravoll.github.io/solidity-patterns/secure_ether_transfer.html)

[Security - OpenZeppelin Docs](https://docs.openzeppelin.com/contracts/4.x/api/security#PullPayment)

https://medium.com/noblocknoparty/a-smartcontract-best-practice-push-pull-or-give-b2e8428e032a

https://medium.com/northwest-nfts/how-to-safely-push-payments-in-smart-contracts-nouns-dao-and-ethernauts-king-challenge-584feca283d4

[Recommendations for Smart Contract Security in Solidity - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/recommendations/#be-aware-of-the-tradeoffs-between-send-transfer-and-callvalue)

### Disclosing signatures / secure commit schemes

[Recommendations for Smart Contract Security in Solidity - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/recommendations/#remember-that-on-chain-data-is-public)

[How Not to Use ECDSA &#8211; Learning Words](https://yondon.blog/2019/01/01/how-not-to-use-ecdsa/)

https://blog.positive.com/predicting-random-numbers-in-ethereum-smart-contracts-e5358c6b8620



### Reacting on unwanted asset deposits

[not-so-smart-contracts/forced_ether_reception at master · crytic/not-so-smart-contracts · GitHub](https://github.com/crytic/not-so-smart-contracts/tree/master/forced_ether_reception)

[Security Considerations &mdash; Solidity 0.8.13 documentation](https://docs.soliditylang.org/en/v0.8.13/security-considerations.html#sending-and-receiving-ether)

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#ether)

[Fallback Functions - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/fallback-functions/)

[Force Feeding - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/attacks/force-feeding/)

[Known Attacks - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/known_attacks/#forcibly-sending-ether-to-a-contract)

### Don’t hand over control to unknown contracts

[not-so-smart-contracts/unchecked_external_call at master · crytic/not-so-smart-contracts · GitHub](https://github.com/crytic/not-so-smart-contracts/tree/master/unchecked_external_call)

https://medium.com/coinmonks/8-security-vulnerabilities-in-ethereum-smart-contracts-that-can-now-be-easily-avoided-dcb7de37a64

[Security Considerations &mdash; Solidity 0.8.13 documentation](https://docs.soliditylang.org/en/v0.8.13/security-considerations.html#authorized-proxies)

https://dasp.co/#item-4

[not-so-smart-contracts/unchecked_external_call at master · crytic/not-so-smart-contracts · GitHub](https://github.com/crytic/not-so-smart-contracts/tree/master/unchecked_external_call)

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#delegatecall)

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#contract-reference)

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#unchecked-calls)

### Have a fallback withdrawal to avoid locking tokens

### Reentrancy attacks

[Security - OpenZeppelin Docs](https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard)

[not-so-smart-contracts/reentrancy at master · crytic/not-so-smart-contracts · GitHub](https://github.com/crytic/not-so-smart-contracts/tree/master/reentrancy)

https://medium.com/coinmonks/8-security-vulnerabilities-in-ethereum-smart-contracts-that-can-now-be-easily-avoided-dcb7de37a64

[Security Considerations &mdash; Solidity 0.8.13 documentation](https://docs.soliditylang.org/en/v0.8.13/security-considerations.html#re-entrancy)

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#reentrancy)

[Reentrancy - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/)

https://gus-tavo-guim.medium.com/reentrancy-attack-on-smart-contracts-how-to-identify-the-exploitable-and-an-example-of-an-attack-4470a2d8dfe4

[Common Smart Contract Vulnerabilities and How To Mitigate Them | Yos Riady · Software Craftsman](https://yos.io/2018/10/20/smart-contract-vulnerabilities-and-how-to-mitigate-them/#vulnerability-reentrancy)

[Common Smart Contract Vulnerabilities and How To Mitigate Them | Yos Riady · Software Craftsman](https://yos.io/2018/10/20/smart-contract-vulnerabilities-and-how-to-mitigate-them/#use-reentrancy-guard)

[Hack Solidity: Reentrancy Attack | HackerNoon](https://hackernoon.com/hack-solidity-reentrancy-attack)

https://betterprogramming.pub/solidity-smart-contract-security-preventing-reentrancy-attacks-fc729339a3ff

[Known Attacks - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/known_attacks/#reentrancy)

### Avoid unlimited approvals

[Explained: The BadgerDAO Hack (December 2021)](https://halborn.com/explained-the-badgerdao-hack-december-2021/)

https://twitter.com/Mudit__Gupta/status/1466856043082702851

https://twitter.com/thisiswenzel/status/1479454667801247744

https://wiki.rugdoc.io/docs/how-to-revoke-permissions/

### Division Errors and avoiding token dust

[Integer Division - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/integer-division/)

## Make contracts maintainable and robust

### Privileged admin control / ownership

### Pauseability

[Security - OpenZeppelin Docs](https://docs.openzeppelin.com/contracts/4.x/api/security#Pausable)

### Emergency Response plans / Dead Man’s switches / Circuit breakers

[Circuit Breakers - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/precautions/circuit-breakers/)

### Speed Bumps / Rate Limits

[Speed Bumps - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/precautions/speed-bumps/)

[Rate Limiting - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/precautions/rate-limiting/)

[Software Engineering Techniques - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/software_engineering/#speed-bumps-delay-contract-actions)

### Denial of Service

[not-so-smart-contracts/denial_of_service at master · crytic/not-so-smart-contracts · GitHub](https://github.com/crytic/not-so-smart-contracts/tree/master/denial_of_service)

[Security Considerations &mdash; Solidity 0.8.13 documentation](https://docs.soliditylang.org/en/v0.8.13/security-considerations.html#call-stack-depth)

https://dasp.co/#item-5

[Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#dos)

[Denial of Service - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/)

[Common Smart Contract Vulnerabilities and How To Mitigate Them | Yos Riady · Software Craftsman](https://yos.io/2018/10/20/smart-contract-vulnerabilities-and-how-to-mitigate-them/#vulnerability-denial-of-service)

[GovernMental&#x27;s 1100 ETH jackpot payout is stuck because it uses too much gas : ethereum](https://www.reddit.com/r/ethereum/comments/4ghzhv/governmentals_1100_eth_jackpot_payout_is_stuck/)

[Known Attacks - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/known_attacks/#dos-with-unexpected-revert)

### Upgradeable Proxy contracts vs. migrations

[building-secure-contracts/guidelines.md at master · crytic/building-secure-contracts · GitHub](https://github.com/crytic/building-secure-contracts/blob/master/development-guidelines/guidelines.md#upgradeability)

[How contract migration works | Trail of Bits Blog](https://blog.trailofbits.com/2018/10/29/how-contract-migration-works/)

[Contract upgrade anti-patterns | Trail of Bits Blog](https://blog.trailofbits.com/2018/09/05/contract-upgrade-anti-patterns/)

[Upgradeability - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/precautions/upgradeability/)

### Secure Composable contracts: The Diamond Standard vs inheritance and mixins

### Contract Transaction Monitoring and automated reactions

## Test Your Contracts

[Static and Dynamic Analysis - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/security-tools/static-and-dynamic-analysis/)

[Best Practices for Smart Contract Development | Yos Riady · Software Craftsman](https://yos.io/2019/11/10/smart-contract-development-best-practices/#set-up-continuous-integration)

### JS based tests

[simple-security-toolkit/development-process.md at main · nascentxyz/simple-security-toolkit · GitHub](https://github.com/nascentxyz/simple-security-toolkit/blob/main/development-process.md)

[GitHub - OpenZeppelin/openzeppelin-test-helpers: Assertion library for Ethereum smart contract testing](https://github.com/OpenZeppelin/openzeppelin-test-helpers)

### Solidity based tests

### Code Coverage

### Predicting the unpredicted

https://twitter.com/CertiKCommunity/status/1461500552467169284

### Formal Verification

[SMTChecker and Formal Verification &mdash; Solidity 0.8.14 documentation](https://docs.soliditylang.org/en/v0.8.14/smtchecker.html)

[Formal verification - Wikipedia](https://en.wikipedia.org/wiki/Formal_verification)

[Best Practices for Smart Contract Development | Yos Riady · Software Craftsman](https://yos.io/2019/11/10/smart-contract-development-best-practices/#consider-formal-verification)

### Using Slither and Mythril to verify code correctness

[building-secure-contracts/program-analysis/slither at master · crytic/building-secure-contracts · GitHub](https://github.com/crytic/building-secure-contracts/tree/master/program-analysis/slither)

[building-secure-contracts/program-analysis/manticore at master · crytic/building-secure-contracts · GitHub](https://github.com/crytic/building-secure-contracts/tree/master/program-analysis/manticore)

### Fuzz testing

[Fuzz Testing - Foundry Book](https://book.getfoundry.sh/forge/fuzz-testing.html)

[building-secure-contracts/program-analysis/echidna at master · crytic/building-secure-contracts · GitHub](https://github.com/crytic/building-secure-contracts/tree/master/program-analysis/echidna)

[Getting Started with Smart Contract Fuzzing - ImmuneBytes](https://immunebytes.com/getting-started-with-smart-contract-fuzzing)

[Announcing the Winners of the Underhanded Solidity Contest 2022 | Solidity Blog](https://blog.soliditylang.org/2022/04/09/announcing-the-underhanded-contest-winners-2022/) (-> winner)

### Mutation testing: test your tests

[GitHub - JoranHonig/vertigo: Mutation Testing for Ethereum Smart Contracts](https://github.com/JoranHonig/vertigo)

### Running tests on forked blockchains

## Monitor your contracts and automate tasks

[Best Practices for Smart Contract Development | Yos Riady · Software Craftsman](https://yos.io/2019/11/10/smart-contract-development-best-practices/#provide-contract-sdks)

https://tenderly.co/

### Using Defender & Sentinel to pause your contract on suspicious conditions

- Write scripts to monitor your logic
  
  [Best Practices for Smart Contract Development | Yos Riady · Software Craftsman](https://yos.io/2019/11/10/smart-contract-development-best-practices/#set-up-event-monitoring)

- [simple-security-toolkit/pre-launch-security-checklist.md at main · nascentxyz/simple-security-toolkit · GitHub

- You want to be on top of what's happening with your project so you can respond quickly to security incidents. For example, you can have a script to monitor for new governance proposals and be alerted when they occur. Or, if you're using a TWAP, have a script that checks the TWAP every block, compares it against the price feed from a CEX, and alerts you if it's every different by more than 10%.

- Create Dune reports to monitor transaction volumes

- Continuous integration and precommit hooks

- Looking for transaction spikes

- Have an incident response plan at hand
  
  - [simple-security-toolkit/incident-response-plan-template.md at main · nascentxyz/simple-security-toolkit · GitHub](https://github.com/nascentxyz/simple-security-toolkit/blob/main/incident-response-plan-template.md)

- [simple-security-toolkit/pre-launch-security-checklist.md at main · nascentxyz/simple-security-toolkit · GitHub](https://github.com/nascentxyz/simple-security-toolkit/blob/main/pre-launch-security-checklist.md)

- 

## Verify your contracts by other parties

### Preparing your code for [audits](https://pages.consensys.net/preparing-for-a-smart-contract-audit)

[simple-security-toolkit/audit-readiness-checklist.md at main · nascentxyz/simple-security-toolkit · GitHub](https://github.com/nascentxyz/simple-security-toolkit/blob/main/audit-readiness-checklist.md)

[GitHub - Rari-Capital/solcurity: Opinionated security and code quality standard for Solidity smart contracts.](https://github.com/Rari-Capital/solcurity)

[publications/reviews at master · trailofbits/publications · GitHub](https://github.com/trailofbits/publications/tree/master/reviews)

### Linting Code style Writing human readable code NatSpec / Comments Documentation

[building-secure-contracts/guidelines.md at master · crytic/building-secure-contracts · GitHub](https://github.com/crytic/building-secure-contracts/blob/master/development-guidelines/guidelines.md#documentation-and-specifications)

[NatSpec Format &mdash; Solidity 0.8.15 documentation](https://docs.soliditylang.org/en/develop/natspec-format.html#natspec-format)

[Linters and Formatters - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/security-tools/linters-and-formatters/)

https://medium.com/protofire-blog/solhint-an-advanced-linter-for-ethereums-solidity-c6b155aced7b

[General - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/documentation/general/)

[Best Practices for Smart Contract Development | Yos Riady · Software Craftsman](https://yos.io/2019/11/10/smart-contract-development-best-practices/#write-good-documentation)

https://twitter.com/PaulRBerg/status/1536002060818305024

Runbooks

[Runbook - AWS Well-Architected Framework](https://wa.aws.amazon.com/wat.concept.runbook.en.html)

Slither printer: 

[Printer documentation · crytic/slither Wiki · GitHub](https://github.com/crytic/slither/wiki/Printer-documentation)

### Smart Contract Security Verification Standard

[GitHub - securing/SCSVS: Smart Contract Security Verification Standard](https://github.com/securing/SCSVS)

- The SWC registry

- Request Peer Reviews
  
  ### Utilise bug bounty programs
  
  [Bug Bounty Programs - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/bug-bounty-programs/)
  
  [Safe Haven - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/development-recommendations/precautions/safe-haven/)

### ### Preparing for due diligence processes

  [Public Smart Contract Audits and Security Reviews | ConsenSys Diligence](https://consensys.net/diligence/audits/)

## Integrate with DeFI protocols safely

[13 Biggest DeFi Hacks and Heists - Decrypt](https://decrypt.co/93874/biggest-defi-hacks-heists)

### ERC777 related reentrancy issues

[GitHub - d-xo/weird-erc20: weird erc20 tokens](https://github.com/d-xo/weird-erc20)

[awesome-buggy-erc20-tokens/ERC20_token_issue_list.md at master · sec-bit/awesome-buggy-erc20-tokens · GitHub](https://github.com/sec-bit/awesome-buggy-erc20-tokens/blob/master/ERC20_token_issue_list.md)

[ERC20 API: An Attack Vector on Approve/TransferFrom Methods - Google Docs](https://docs.google.com/document/d/1YLPtQxZu1UAvO9cZ1O2RPXBbT0mooh4DYKjA_jp-RLM/edit)

### Price Manipulation and Flashloan attacks

https://github.com/Crypto-Virus/cream-finance-exploit-example

https://twitter.com/0x5749/status/1476813266462539779

### Avoid trusting onchain oracles

- [simple-security-toolkit/pre-launch-security-checklist.md at main · nascentxyz/simple-security-toolkit · GitHub](https://github.com/nascentxyz/simple-security-toolkit/blob/main/pre-launch-security-checklist.md)

- [Oracle Manipulation - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/attacks/oracle-manipulation/)

[Chapter 11: Oracles - Why Oracles Are Needed - 《Mastering Ethereum》 - 书栈网 · BookStack](https://www.bookstack.cn/read/ethereumbook-en/spilt.1.b0fc44d2ef51cf12.md)

### Integration samples for external protocols

- Aave

- Uniswap

- Bancor

[Best Practices for Smart Contract Development | Yos Riady · Software Craftsman](https://yos.io/2019/11/10/smart-contract-development-best-practices/#build-with-other-protocols-in-mind)

[building-secure-contracts/token_integration.md at master · crytic/building-secure-contracts · GitHub](https://github.com/crytic/building-secure-contracts/blob/master/development-guidelines/token_integration.md)

### Reorgs

## Avoid exposing attacks on L2 networks bridges

#### Advantages and drawbacks of L2 networks

[Cross Chain Awareness - OpenZeppelin Docs](https://docs.openzeppelin.com/contracts/4.x/api/crosschain)

### Attacks on cross chain message layers / bridges

https://www.cryptovantage.com/news/why-are-cross-chain-cryptocurrency-bridges-so-vulnerable-to-attack/

[Cydia Dev Discloses Ethereum L2 Bug — Optimism Attacker Could Have &#039;Printed an Arbitrary Quantity of Tokens&#039; &ndash; Bitcoin News](https://news.bitcoin.com/cydia-dev-discloses-ethereum-l2-bug-optimism-attacker-could-have-printed-an-arbitrary-quantity-of-tokens/)

[Optimistic Rollups and Ethereum&#x27;s Layer-2 Solutions: Examining Arbitrum&#x27;s Security Mechanism | HackerNoon](https://hackernoon.com/optimistic-rollups-and-ethereums-layer-2-solutions-examining-arbitrums-security-mechanism-to3v35hr)

https://ethereum.org/en/developers/docs/bridges/#risk-with-bridges

### Example hacks

#### Ronin

[Ronin Attack Shows Cross-Chain Crypto Is a ‘Bridge’ Too Far](https://finance.yahoo.com/news/ronin-attack-shows-cross-chain-194557393.html)

https://twitter.com/Psycheout86/status/1509134627319033863

#### Wormhole

[How $323M in crypto was stolen from a blockchain bridge called Wormhole | Ars Technica](https://arstechnica.com/information-technology/2022/02/how-323-million-in-crypto-was-stolen-from-a-blockchain-bridge-called-wormhole/)

https://extropy-io.medium.com/solanas-wormhole-hack-post-mortem-analysis-3b68b9e88e13

#### Poly Network

[Poly Network Hack Analysis - Largest Crypto Hack - Mudit Gupta&#039;s Blog](https://mudit.blog/poly-network-largest-crypto-hack/)

#### Wintermute

https://twitter.com/optimismPBC/status/1534631766576836608

https://www.fxstreet.com/cryptocurrencies/news/optimism-loses-20m-tokens-after-l1-and-l2-confusion-exploited-202206090217

[How Optimism Just Lost 20 Million Tokens - Failed Transaction](https://insidebitcoins.com/news/how-optimism-just-lost-20-million-tokens)

[Transaction Replay + Management Vulnerability - Analysis of 20 Million OP Stolen Incident : SharkTeamorg](https://www.reddit.com/r/SharkTeamorg/comments/vamm1w/transaction_replay_management_vulnerability/)

## Harden your contracts against MEV - or embrace it

### The dark forest and advantages of being a miner / validator

[Ethereum is a Dark Forest - Paradigm](https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest)

[Escaping the Dark Forest](https://samczsun.com/escaping-the-dark-forest/)

[MEV and Me | Paradigm Research](https://research.paradigm.xyz/MEV)

https://twitter.com/bertcmiller/status/1402665992422047747

https://medium.com/onomy-protocol/what-is-miner-extractable-value-mev-2ef695945afa

[A Guide to MEV Attacks on Ethereum, and How to Prevent Them | CoinCodex](https://coincodex.com/article/13860/a-guide-to-mev-attacks-on-ethereum-and-how-to-prevent-them/)

https://ethereum.org/en/developers/docs/mev/

[Committee-driven MEV smoothing - Economics - Ethereum Research](https://ethresear.ch/t/committee-driven-mev-smoothing/10408)

[Ethereum transaction reordering: Unfair and harmful? • The Register](https://www.theregister.com/2022/03/31/ethereum_mining_mev/)

[Transaction ordering - HackMD](https://notes.ethereum.org/@holiman/H17hFNWfd)



### Front running

- https://dasp.co/#item-7

- [Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html#race-conditions)

- [Frontrunning - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/attacks/frontrunning/)

- [Outrunning the Frontrunners](https://blog.assembly.sc/outrunning-the-frontrunners/)

https://blog.positive.com/predicting-random-numbers-in-ethereum-smart-contracts-e5358c6b8620

https://arxiv.org/pdf/1902.05164.pdf

[Known Attacks - Ethereum Smart Contract Best Practices](https://ethereum-contract-security-techniques-and-tips.readthedocs.io/en/latest/known_attacks/#transaction-ordering-dependence-tod-front-running)

https://medium.com/archer-dao/transaction-ordering-affad826e496



### Sandwich attacks

https://medium.com/coinmonks/demystify-the-dark-forest-on-ethereum-sandwich-attacks-5a3aec9fa33e

[What Are Sandwich Attacks in DeFi — and How Can You Avoid Them? | Alexandria](https://coinmarketcap.com/alexandria/article/what-are-sandwich-attacks-in-defi-and-how-can-you-avoid-them)

[Modern MEV sandwich attacks on Ethereum routers — totlsota](https://mirror.xyz/totlsota.eth/9JaNkZ1XQfQD6Y79aLYHC_kb_dSBoJ2JYiag5BuGGM8)

https://ethereum.org/en/developers/docs/mev/#mev-examples-sandwich-trading

#### Avoid MEV opportunities in contracts

#### Leverage MEV infrastructure for the good

https://docs.flashbots.net/

https://docs.edennetwork.io/



https://medium.com/flashbots/frontrunning-the-mev-crisis-40629a613752

- https://dezentralizedfinance.com/top-10-miner-extractable-value-mev-protection-projects-ecosystem/

- 

https://dasp.co/#item-7

https://medium.com/@VitalikButerin/i-feel-like-this-post-is-addressing-an-argument-that-isnt-the-actual-argument-that-mev-auction-b3c5e8fc1021

[MEV Auction: Auctioning transaction ordering rights as a solution to Miner Extractable Value - Economics - Ethereum Research](https://ethresear.ch/t/mev-auction-auctioning-transaction-ordering-rights-as-a-solution-to-miner-extractable-value/6788)
