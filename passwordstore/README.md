# PasswordStore Security Audit Report

**Lead Auditor:** maheshbsl

## Overview
This report presents the findings of a security audit conducted on the PasswordStore contract. The audit focused on identifying security vulnerabilities, code quality issues, and potential attack vectors in the smart contract.

## Audit Scope
- Contract: PasswordStore.sol
- Commit Hash: 2e8f81e263b3a9d18fab4fb5c46805ffc10a9990
- Solidity Version: 0.8.18

## Summary of Findings
The audit revealed two critical security vulnerabilities in the PasswordStore contract that compromise its security guarantees:

| ID | Title | Severity |
| --- | --- | --- |
| [H-01](#h-01-missing-access-control-in-setpassword-function) | Missing access control in setPassword function | HIGH |
| [H-02](#h-02-private-password-visibility-is-misleading) | Private password visibility is misleading | HIGH |

## Detailed Findings

### [H-01] Missing access control in setPassword function

#### Description
The `setPassword` function lacks proper access control, allowing any external address to modify the stored password.

```solidity
function setPassword(string memory newPassword) external {
    s_password = newPassword;
    emit SetNetPassword();
}
```

This function should only be accessible to the contract owner, but it does not implement the necessary check.

#### Impact
Any malicious user can overwrite the owner's password, causing a complete loss of confidentiality. The owner may unwittingly retrieve a password that has been changed by an attacker.

#### Proof of Concept
I have written a test that demonstrates how any non-owner address can modify the password:

```solidity
// Test demonstrating that non-owners can set the password
function testNonOwnersCanSetPassword() public {
    address nonOwner = makeAddr("nonOwner");
    string memory newPass = "newPass";
    vm.prank(nonOwner);
    passwordStore.setPassword(newPass);

    vm.prank(owner);
    string memory actualPass = passwordStore.getPassword();
    assertEq(actualPass, newPass);
}
```

This test creates a non-owner address, uses it to set a new password, and then verifies that the owner retrieves this new password rather than the original one. The test passes, confirming the vulnerability.

#### Recommended Mitigation
Add an owner check similar to the one present in the `getPassword` function:

```solidity
function setPassword(string memory newPassword) external {
    if (msg.sender != s_owner) {
        revert PasswordStore__NotOwner();
    }
    s_password = newPassword;
    emit SetNetPassword();
}
```

### [H-02] Private password visibility is misleading

#### Description
The contract suggests that the password is private and only accessible to the owner:

```solidity
string private s_password;
```

However, marking a variable as `private` in Solidity only restricts access from other contracts. The data is still publicly visible on the blockchain and can be read by anyone with access to the blockchain data.

#### Impact
Users may have a false sense of security, believing that their passwords are securely stored when in fact they are visible to anyone who examines the blockchain state.

#### Proof of Concept
The following steps demonstrate how to access the supposedly "private" password directly from the blockchain storage:

1. Start a local Anvil blockchain:
```bash
make anvil
```

2. Deploy the PasswordStore contract:
```bash
make deploy
```

3. Get the deployed contract address from the console output (in this example: `0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0`)

4. Read the password value from storage slot 1 using Cast:
```bash
cast storage 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 1 --rpc-url http://localhost:8545
```
Output: `0x6d7950617373776f726400000000000000000000000000000000000000000014`

5. Decode the hex value to reveal the plaintext password:
```bash
cast --to-ascii 0x6d7950617373776f726400000000000000000000000000000000000000000014
```
Output: `myPassword`

This demonstrates that despite being declared as `private`, anyone can easily read the password from the blockchain.

#### Recommended Mitigation
1. Clearly document in the contract that on-chain data is not truly private
2. Consider storing only a hash of the password on-chain instead of the plaintext password
3. For truly sensitive data, consider off-chain storage solutions with appropriate security measures

## Conclusions
The PasswordStore contract fails to provide the security guarantees implied by its design. The identified vulnerabilities allow unauthorized access to supposedly private data and enable malicious actors to tamper with stored passwords.

Users should not use this contract for storing sensitive information until the recommended mitigations have been implemented and a follow-up audit has been conducted. 