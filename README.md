# Security Researcher Portfolio

## Summary

* Security researcher specializing in smart contract audits and vulnerability detection
* Lead auditor on multiple blockchain security assessments
* Focus on access control, storage vulnerabilities, and protocol design flaws

For an audit, reach out via:

* Twitter: [Your Twitter Handle]
* Telegram: [Your Telegram Handle]

## Audit Reports

| Project | Category | Severity | Report |
| ------- | -------- | -------- | ------ |
| [PasswordStore](https://github.com/Cyfrin/3-passwordstore-audit) | Security Storage | 2 High | [Report](./passwordstore/README.md) |

## Key Findings

### PasswordStore Audit

#### H-01: Missing access control in setPassword function
The `setPassword` function lacks proper access control, allowing any external address to modify the stored password. This constitutes a complete breakdown of the contract's security model.

#### H-02: Private password visibility is misleading
The contract creates a false sense of security by labeling data as "private" when all blockchain data remains publicly accessible. Demonstrated how on-chain storage can be easily read despite privacy modifiers.

## Tools & Methodologies

* Manual code review
* Static analysis
* Test-driven auditing
* Blockchain storage analysis

## Certifications & Education

* [Your relevant certifications]
* [Your education background]
