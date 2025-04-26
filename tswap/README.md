# T-Swap Security Audit Report

Lead Security Researcher: maheshbsl

## Overview
This audit report covers security issues found in the T-Swap protocol's smart contracts. The audit focuses on identifying potential vulnerabilities, security issues, and best practices violations.

## Findings Summary

| ID | Title | Severity |
| --- | --- | --- |
| [H-01](#h-01-weth-weth-pool-creation-allowed) | WETH-WETH Pool Creation Allowed | HIGH |
| [H-02](#h-02-no-slippage-protection-in-swapexactoutput) | No Slippage Protection in swapExactOutput | HIGH |
| [H-03](#h-03-incorrect-fee-calculation) | Incorrect Fee Calculation | HIGH |
| [H-04](#h-04-swap-function-breaks-the-constant-product-invariant) | Swap Function Breaks the Constant Product Invariant | HIGH |
| [H-05](#h-05-protocol-incompatible-with-rebasing-and-fee-on-transfer-tokens) | Protocol Incompatible with Rebasing and Fee-on-Transfer Tokens | HIGH |
| [M-01](#m-01-missing-zero-address-validation) | Missing Zero Address Validation | MEDIUM |
| [M-02](#m-02-logic-error-in-sellpooltokens-function) | Logic Error in sellPoolTokens Function | MEDIUM |

## Detailed Findings

### [H-01] WETH-WETH Pool Creation Allowed

**Severity**: HIGH

**Description**:  
The `PoolFactory.createPool()` function does not prevent creating a pool with WETH as both tokens. This allows creating a WETH-WETH pool, which breaks the core assumption of the protocol that pools are always between a token and WETH.

**Code Location**:  
`src/PoolFactory.sol:67-79`

```solidity
function createPool(address tokenAddress) external returns (address) {
    // No validation for tokenAddress == i_wethToken
    if (s_pools[tokenAddress] != address(0)) {
        revert PoolFactory__PoolAlreadyExists(tokenAddress);
    }
    // ... remaining code
}
```

**Proof of Concept**:  
The following test demonstrates the vulnerability:
```solidity
function testCreatePoolWithWeth() public {
    address poolCreatedWithWeth = factory.createPool(address(mockWeth));
    console.log("poolCreatedWithWeth", poolCreatedWithWeth);
}
```

When executed, this test successfully creates a WETH-WETH pool at address `0xffD4505B3452Dc22f8473616d50503bA9E1710Ac`.

**Impact**:  
This critically impacts the protocol as it:
1. Breaks the fundamental economic model of the protocol
2. May cause incorrect price calculations and unexpected behavior in swapping mechanisms
3. Could potentially be exploited to drain funds or manipulate prices
4. Undermines the core assumption that all pools represent token-WETH pairs

**Recommendation**:  
Add validation in the `createPool` function to prevent creating a pool where the token is the same as WETH:

```solidity
function createPool(address tokenAddress) external returns (address) {
    if (tokenAddress == i_wethToken) {
        revert PoolFactory__IdenticalTokens();
    }
    // Remaining code
}
```

### [H-02] No Slippage Protection in swapExactOutput

**Severity**: HIGH

**Description**:  
The `swapExactOutput` function lacks a critical parameter for maximum input amount, leaving users vulnerable to sandwich attacks and front-running. Unlike `swapExactInput` which has a `minOutputAmount` parameter, there is no equivalent `maxInputAmount` parameter in `swapExactOutput`.

**Code Location**:  
`src/TSwapPool.sol:274-293`

```solidity
function swapExactOutput(
    IERC20 inputToken,
    IERC20 outputToken,
    uint256 outputAmount,
    uint64 deadline
)
    public
    revertIfZero(outputAmount)
    revertIfDeadlinePassed(deadline)
    returns (uint256 inputAmount)
{
    uint256 inputReserves = inputToken.balanceOf(address(this));
    uint256 outputReserves = outputToken.balanceOf(address(this));
    // @audit no slippage protection for input token, should include max input amount
    inputAmount = getInputAmountBasedOnOutput(outputAmount, inputReserves, outputReserves);

    _swap(inputToken, inputAmount, outputToken, outputAmount);
}
```

**Proof of Concept**:  
```solidity
function testSwapExactOutputNoSlippageProtection() public {
    // deposit liquidity to the pool
    vm.startPrank(liquidityProvider);
    weth.approve(address(pool), 100e18);
    poolToken.approve(address(pool), 100e18);
    pool.deposit(100e18, 100e18, 100e18, uint64(block.timestamp));
    // now the pool has liquidity

    //get the current reserves of poolToken and weth
    uint256 poolTokenReserves = poolToken.balanceOf(address(pool));
    uint256 wethReserves = weth.balanceOf(address(pool));

    // user wants to swap poolToken for weth, user want to get 10 weth (not 100, which was too much)
    vm.startPrank(user);
    uint256 expectedInputAmount = pool.getInputAmountBasedOnOutput(10e18, poolTokenReserves, wethReserves);

    // now attacker front run the user's transaction
    address attacker = makeAddr("attacker");
    vm.startPrank(attacker);
    poolToken.mint(attacker, 100e18);
    weth.mint(attacker, 100e18);
    // attacker will take out the weth from the pool to make the weth price higher
    poolToken.approve(address(pool), 30e18);
    pool.swapExactInput(poolToken, 30e18, weth, 1, uint64(block.timestamp));
    vm.stopPrank(); 
    // now the pool reserves are changed 

    poolTokenReserves = poolToken.balanceOf(address(pool));
    wethReserves = weth.balanceOf(address(pool));

    uint256 actualInputAmount = pool.getInputAmountBasedOnOutput(10e18, poolTokenReserves, wethReserves);
    console.log("actualInputAmount", actualInputAmount);
    console.log("expectedInputAmount", expectedInputAmount);
    assert(actualInputAmount > expectedInputAmount);
}
```

The test shows that after a front-running attack, the user would have to pay significantly more pool tokens than expected to receive their desired WETH output.

**Impact**:  
1. Users have no way to limit how much they'll pay in a `swapExactOutput` transaction
2. Makes the protocol highly vulnerable to sandwich attacks and front-running
3. Could lead to significant economic loss for users when market conditions change between their calculation and transaction execution

**Recommendation**:  
Add a `maxInputAmount` parameter to the `swapExactOutput` function to protect users:

```solidity
function swapExactOutput(
    IERC20 inputToken,
    IERC20 outputToken,
    uint256 outputAmount,
    uint256 maxInputAmount,
    uint64 deadline
)
    public
    revertIfZero(outputAmount)
    revertIfDeadlinePassed(deadline)
    returns (uint256 inputAmount)
{
    uint256 inputReserves = inputToken.balanceOf(address(this));
    uint256 outputReserves = outputToken.balanceOf(address(this));
    inputAmount = getInputAmountBasedOnOutput(outputAmount, inputReserves, outputReserves);
    
    if (inputAmount > maxInputAmount) {
        revert TSwapPool__InputTooHigh(inputAmount, maxInputAmount);
    }

    _swap(inputToken, inputAmount, outputToken, outputAmount);
}
```

### [H-03] Incorrect Fee Calculation

**Severity**: HIGH

**Description**:  
The `getInputAmountBasedOnOutput` function uses an incorrect multiplier in its fee calculation. The function multiplies by 10000 when it should multiply by 1000 to properly account for the 0.3% fee, resulting in users paying approximately 10x more than they should.

**Code Location**:  
`src/TSwapPool.sol:237-249`

```solidity
function getInputAmountBasedOnOutput(
    uint256 outputAmount,
    uint256 inputReserves,
    uint256 outputReserves
)
    public
    pure
    revertIfZero(outputAmount)
    revertIfZero(outputReserves)
    returns (uint256 inputAmount)
{    // @audit high  multiplying by 10000, should be 1000
    return ((inputReserves * outputAmount) * 10000) / ((outputReserves - outputAmount) * 997);
}
```

**Impact**:  
1. Users are massively overcharged (~10x) when using `swapExactOutput` or `sellPoolTokens`
2. Creates a significant economic imbalance in the protocol
3. Directly affects the core pricing mechanism, causing severe distortions in the AMM

**Recommendation**:  
Correct the calculation by changing 10000 to 1000:

```solidity
return ((inputReserves * outputAmount) * 1000) / ((outputReserves - outputAmount) * 997);
```

### [H-04] Swap Function Breaks the Constant Product Invariant

**Severity**: HIGH

**Description**:  
The `_swap` function in TSwapPool includes a "feature" that gives away free tokens every 10 swaps. This directly breaks the constant product formula (x * y = k) that AMMs rely on for pricing stability.

**Code Location**:  
`src/TSwapPool.sol:330-339`

```solidity
// @audit break protocol invariant
swap_count++;
if (swap_count >= SWAP_COUNT_MAX) {
    swap_count = 0;
    outputToken.safeTransfer(msg.sender, 1_000_000_000_000_000_000);
}
```

**Proof of Concept**:  
```solidity
function testSwapBreakInvariant() public {
    // deposit liquidity to the pool
    vm.startPrank(liquidityProvider);
    weth.approve(address(pool), 100e18);
    poolToken.approve(address(pool), 100e18);
    pool.deposit(100e18, 100e18, 100e18, uint64(block.timestamp));
    vm.stopPrank();

    // swap 9 times
    for (uint256 i = 0; i < 9; i++) {
        vm.startPrank(user);
        // Mint fresh tokens for each swap
        poolToken.mint(user, 10e18);
        poolToken.approve(address(pool), 10e18);
        pool.swapExactInput(poolToken, 10e18, weth, 0, uint64(block.timestamp));
        vm.stopPrank();
    }

    // 10th swap will break the invariant
    vm.startPrank(user);
    // Mint fresh tokens for the final swap
    poolToken.mint(user, 10e18);
    poolToken.approve(address(pool), 10e18);
    // The pool will give extra tokens on the 10th swap which breaks the invariant
    pool.swapExactInput(poolToken, 10e18, weth, 0, uint64(block.timestamp));
    vm.stopPrank();
    
    // After 10 swaps the pool has given away extra tokens
    // Let's verify the invariant is broken:
    uint256 xReserve = poolToken.balanceOf(address(pool));
    uint256 yReserve = weth.balanceOf(address(pool));
    
    // Output the values for debugging
    console.log("X Reserve:", xReserve);
    console.log("Y Reserve:", yReserve);
    console.log("Product:", xReserve * yReserve);
    
    // Compare with initial K (100e18 * 100e18)
    uint256 initialK = 100e18 * 100e18;
    console.log("Initial K:", initialK);
    
    // The invariant should be broken - product should be less than initial K
    console.log("Invariant broken:", xReserve * yReserve < initialK);
    assert(xReserve * yReserve < initialK);
}
```

The test confirms that after 10 swaps, the constant product value has decreased, breaking a foundational invariant of the protocol.

**Impact**:  
1. Directly violates the x * y = k formula that AMMs rely on
2. Creates an unfair advantage for users who can time their trades
3. Depletes reserves and damages the economic security of the protocol
4. Makes price manipulation attacks easier as pool reserves become unbalanced

**Recommendation**:  
Remove the "bonus token" mechanism entirely:

```solidity
function _swap(IERC20 inputToken, uint256 inputAmount, IERC20 outputToken, uint256 outputAmount) private {
    if (_isUnknown(inputToken) || _isUnknown(outputToken) || inputToken == outputToken) {
        revert TSwapPool__InvalidToken();
    }
    
    emit Swap(msg.sender, inputToken, inputAmount, outputToken, outputAmount);

    inputToken.safeTransferFrom(msg.sender, address(this), inputAmount);
    outputToken.safeTransfer(msg.sender, outputAmount);
}
```

### [H-05] Protocol Incompatible with Rebasing and Fee-on-Transfer Tokens

**Severity**: HIGH

**Description**:  
The T-Swap protocol does not properly handle rebasing tokens or fee-on-transfer tokens, which can break the constant product invariant and lead to significant economic vulnerabilities. Rebasing tokens dynamically adjust holder balances, while fee-on-transfer tokens take a fee during transfers, resulting in the recipient receiving less than the amount sent. The protocol currently assumes tokens behave like standard ERC20s where send amount = received amount and balances remain static between operations.

**Code Location**:  
The issue affects multiple functions including deposits, withdrawals, and swaps:

`src/TSwapPool.sol:140-157` (For deposit function):
```solidity
function _addLiquidityMintAndTransfer(
    uint256 wethToDeposit,
    uint256 poolTokensToDeposit,
    uint256 liquidityTokensToMint
)
    private
{
    _mint(msg.sender, liquidityTokensToMint);
    emit LiquidityAdded(msg.sender, poolTokensToDeposit, wethToDeposit);

    // Interactions
    i_wethToken.safeTransferFrom(msg.sender, address(this), wethToDeposit);
    i_poolToken.safeTransferFrom(msg.sender, address(this), poolTokensToDeposit);
}
```

`src/TSwapPool.sol:340-341` (For swap function): 
```solidity
inputToken.safeTransferFrom(msg.sender, address(this), inputAmount);
outputToken.safeTransfer(msg.sender, outputAmount);
```

**Impact**:  
1. **For Rebasing Tokens**:
   - Positive rebases would allow users to exploit the protocol by depositing before a rebase and withdrawing after
   - Negative rebases would lead to insufficient reserves, breaking the invariant and potentially causing liquidity providers to lose funds
   - Price calculations would be incorrect as they don't account for automatic balance changes

2. **For Fee-on-Transfer Tokens**:
   - The protocol would consistently have less reserves than expected
   - Swaps would be imbalanced as the contract would receive less than expected from transfers
   - The constant product formula would be broken, leading to incorrect pricing
   - Potential for sandwich attacks exploiting the fee mechanics

**Recommendation**:  
1. Either explicitly disallow rebasing and fee-on-transfer tokens, or
2. Implement proper handling for these token types:

```solidity
// For transfers in, check actual received amount:
uint256 balanceBefore = inputToken.balanceOf(address(this));
inputToken.safeTransferFrom(msg.sender, address(this), inputAmount);
uint256 balanceAfter = inputToken.balanceOf(address(this));
uint256 actualReceivedAmount = balanceAfter - balanceBefore;

// Use actualReceivedAmount in calculations instead of inputAmount

// For transfers out, similar pattern to ensure minimum received
uint256 balanceBefore = outputToken.balanceOf(address(this));
outputToken.safeTransfer(msg.sender, outputAmount);
uint256 balanceAfter = outputToken.balanceOf(address(this));
uint256 actualSentAmount = balanceBefore - balanceAfter;

// Verify actualSentAmount meets requirements
```

Additionally, for rebasing tokens, implement a check for unexpected balance changes between operations.

### [M-01] Missing Zero Address Validation

**Severity**: MEDIUM

**Description**:  
The contract lacks zero address validation in multiple critical areas:
1. Constructor doesn't validate the `wethToken` parameter
2. `createPool` function doesn't validate the `tokenAddress` parameter

**Code Location**:  
`src/PoolFactory.sol:47-49`
```solidity
constructor(address wethToken) {
    //q: there is no validation for the zero address 
    i_wethToken = wethToken;
}
```

`src/PoolFactory.sol:67-79`
```solidity
function createPool(address tokenAddress) external returns (address) {
    // @audit the is no validation for the zero address, what if the tokenAddress is the wethtoken?
    // ... remaining code
}
```

**Proof of Concept**:  
The following test demonstrates the vulnerability:
```solidity
function testCreatePoolWithInvalidToken() public {
    // poolFactory is already deployed in the setup
    // just call the create pool with zero address
    vm.expectRevert();
    factory.createPool(address(0));
}
```

The test passes without reversion, confirming the vulnerability.

**Impact**:  
This could lead to:
1. Deployment with an invalid WETH token address
2. Creation of invalid pools with the zero address
3. Possible failures in token interactions
4. Potential protocol malfunction

**Recommendation**:  
Add zero address validation in both the constructor and `createPool` function:

```solidity
constructor(address wethToken) {
    if (wethToken == address(0)) {
        revert PoolFactory__ZeroAddress();
    }
    i_wethToken = wethToken;
}

function createPool(address tokenAddress) external returns (address) {
    if (tokenAddress == address(0)) {
        revert PoolFactory__ZeroAddress();
    }
    // Remaining code
}
```

### [M-02] Logic Error in sellPoolTokens Function

**Severity**: MEDIUM

**Description**:  
The `sellPoolTokens` function has a logic error where it incorrectly uses `swapExactOutput` when it should use `swapExactInput`. The function is meant to sell a specific amount of pool tokens, but it actually requests a specific amount of WETH output.

**Code Location**:  
`src/TSwapPool.sol:305-314`

```solidity
/**
 * @notice wrapper function to facilitate users selling pool tokens in exchange of WETH
 * @param poolTokenAmount amount of pool tokens to sell
 * @return wethAmount amount of WETH received by caller
 */
// @audit logic is wrong, should be swapExactInput
function sellPoolTokens(uint256 poolTokenAmount) external returns (uint256 wethAmount) {
    return swapExactOutput(i_poolToken, i_wethToken, poolTokenAmount, uint64(block.timestamp));
}
```

**Impact**:  
1. Users calling `sellPoolTokens(x)` will inadvertently be specifying how much WETH they want out, not how many pool tokens they want to sell
2. Leads to unexpected reverts or wrong trade sizes
3. Creates confusing user experience and potential loss of funds if users assume wrong behavior

**Recommendation**:  
Change the wrapper to call `swapExactInput`, so the argument is correctly treated as an input-amount parameter:

```solidity
function sellPoolTokens(uint256 poolTokenAmount) external returns (uint256 wethAmount) {
    wethAmount = swapExactInput(
        i_poolToken,
        poolTokenAmount,
        i_wethToken,
        0,                      // no minimum output enforced here
        uint64(block.timestamp)
    );
}
``` 