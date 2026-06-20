---
name: blocksec-audit-signed-1
project: burrowland
repository: https://github.com/NearDeFi/burrowland.git
security researcher: BlockSec
date: 2022-02-14
file link: https://github.com/NearDeFi/burrowland/blob/main/blocksec-audit-signed-1.pdf
---
# Security Audit Report for Burrow

Date: Feb 14th, 2022
Version: 1.0
Contact: contact@blocksecteam.com

## Chapter 1 Introduction

### 1.1 About Target Contracts

| Information | Description                            |
| ----------- | -------------------------------------- |
| Type        | SmartContract                          |
| Language    | Rust                                   |
| Approach    | Semi-automatic and manual verification |

The audit scope includes the contract under the directory contract in the burrowland repository. The auditing process is iterative. Specifically, we will further audit the commits that fix the founding issues. If there are new issues, we will continue this process. Thus, there are multiple commit SHA values referred in this report. The commit SHA values before and after the audit are shown in the following. Note that commit `c2e1d85030c5599d9423c2ec01525c914fe24743` is in branch `audit-fixes-2022-02-12` and has not been merged into main branch at the release of this audit report.

**Before and during the audit**

| Contract Name | Stage   | Commit SHA                               |
| ------------- | ------- | ---------------------------------------- |
| Burrow        | Initial | 0de39e9876694b0926c557426e7608b96444ee8e |

**After**

| Project | Commit SHA                               |
| ------- | ---------------------------------------- |
| Burrow  | c2e1d85030c5599d9423c2ec01525c914fe24743 |
### 1.2 Disclaimer
(...)

### 1.3 Procedure of Auditing
(...)

(...) We show the main concrete checkpoints in the following:

#### 1.3.1 Software Security
- Reentrancy
- DoS
- Access control
- Data handling and data flow
- Exception handling
- Untrusted external call and control flow
- Initialization consistency
- Events operation
- Error-prone randomness
- Improper use of the proxy system

#### 1.3.2 DeFi Security
- Semantic consistency
- Functionality consistency
- Access control
- Business logic
- Token operation
- Emergency mechanism
- Oracle security
- Whitelist and blacklist
- Economic impact
- Batch transfer

#### 1.3.3 NFT Security
- Duplicated item
- Verification of the token receiver
- Off-chain metadata security

1.3.4 Additional Recommendation
- Gas optimization
- Code quality and style

*Note: The previous checkpoints are the main ones. We may use more checkpoints during the auditing process according to the functionality of the project.*

### 1.4 Security Model

To evaluate the risk, we follow the standards or suggestions that are widely adopted by both industry and academy, including OWASP Risk Rating Methodology 2 and Common Weakness Enumeration 3. Accordingly, the severity measured in this report are classified into four categories: High, Medium, Low and Undetermined.

Furthermore, the status of a discovered issue will fall into one of the following four categories:
**Undetermined** No response yet.
**Acknowledged** The issue has been received by the client, but not confirmed yet.
**Confirmed** The issue has been recognized by the client, but not fixed yet.
**Fixed** The issue has been confirmed and fixed by the client.

## Chapter 2 Findings

In total, we find 6 potential issues in the smart contract. We also have 7 recommendations, as follows:
High Risk: 0
Medium Risk: 5
Low Risk: 1
Recommendations: 7

The details are provided in the following sections.

| ID  | Severity | Description                                      | Category          | Status       |
| --- | -------- | ------------------------------------------------ | ----------------- | ------------ |
| 1   | Medium   | MAX_NUM_ASSETS is a constant                     | Software Security | Fixed        |
| 2   | Medium   | Missing check on the returned value              | Software Security | Fixed        |
| 3   | Medium   | Storage usage is wrong in liquidation action     | DeFi Security     | Fixed        |
| 4   | Medium   | Storage usage is wrong in setting users' storage | DeFi Security     | Fixed        |
| 5   | Low      | Incomplete asset configuration check             | DeFi Security     | Fixed        |
| 6   | Medium   | The freshness of PriceData should be checked     | DeFi Security     | Fixed        |
| 7   | -        | Dead code is found                               | Recommendation    | Fixed        |
| 8   | -        | Deflation Token is not supported                 | Recommendation    | Confirmed    |
| 9   | -        | Redundant invoked function                       | Recommendation    | Fixed        |
| 10  | -        | Reliability of Oracle                            | Recommendation    | Confirmed    |
| 11  | -        | Upgrade module of the contract                   | Recommendation    | Confirmed    |
| 12  | -        | The risk of centralized design                   | Recommendation    | Confirmed    |
| 13  | -        | Allowed actions                                  | Recommendation    | Acknowledged |
### Software Security
#### 2.1.1 MAX_NUM_ASSETS cannot be changed without upgrading the contract
**Status** Fixed.
**Description** This issue is introduced in or before the initial commit. The `MAX_NUM_ASSETS` in line 135 are used in assert statement. However, `MAX_NUM_ASSETS` is a constant (i.e., 10). In this case, the assert statement in line 135 may fail when new asset is added. Part of the functionality cannot be guaranteed if the assert fail.

```Rust title:action.rs ln:136
if need_number_check {
	assert!(account.collateral.len() + account.borrowed.len() <= MAX_NUM_ASSETS);
}
```

**Impact** Part of the functionality may not work after adding new assets.
**Suggestion I** Add an interface to set the `MAX_NUM_ASSETS`.

#### 2.1.2 Missing check on the returned value
**Status** Fixed
**Description** This issue is introduced in or before the initial commit. In function `shares_to_amount`, when the `shares.0 < self.balance` and `shares.0 > self.shares.0`, the calculated return value will be larger than the `self.balance`.

```Rust title:pool.rs ln:38
pub fn shares_to_amount(&self, shares: Shares, round_up: bool) -> Balance { 
	if shares.0 >= self.balance || shares.0 == self.shares.0 {
		self.balance
	} else {
	let extra = if round_up {
		U256::from(self.shares.0 - 1)
	} else {
		U256::zero()
	};
	((U256::from(self.balance) * U256::from(shares.0) + extra) / U256::from(self.shares.0))
.as_u128()
	}
}
```

**Impact** The return value of function `shares_to_amount` my be larger than the `self.balance`.
**Suggestion I** Check whether the return value is larger than the self.balance

### 2.2 DeFi Security
#### 2.2.1 Storage usage is wrong in liquidation action

**Status** Fixed
**Description** This issue is introduced in or before the initial commit. The `required_bytes` in line 401 includes all the other accounts' storage usages. In this case, comparing between `available_bytes` and `required_bytes` does not make any sense. The `available_bytes` are for liquidation account and should not be added into the account who execute the liquidation action. `Extra_bytes` should not be added into the `liquidation_account` in line 409, the logic here is wrong.

```Rust title:action.rs ln:394
// We have to adjust the initial_storage_usage for the acting account to not double count
// the bytes from the liquidation account. As well as potentially cover the extra bytes
// required by the liquidation account that might be added due to farms.
let current_storage_usage = env::storage_usage();
if current_storage_usage > liquidation_storage.initial_storage_usage { 
	let required_bytes = current_storage_usage - liquidation_storage.initial_storage_usage;
	let available_bytes = liquidation_storage.available_bytes();
	if available_bytes < required_bytes {
		let extra_bytes = required_bytes - available_bytes;
		log!(
		"Account {} has to cover extra storage of {} bytes for liquidation account {}",
		account_id,
		extra_bytes,
		liquidation_account_id,
		);
		liquidation_storage.initial_storage_usage += extra_bytes;
		storage.initial_storage_usage += available_bytes;
	} else {
		storage.initial_storage_usage += required_bytes;
	}
} else {
	let released_bytes = liquidation_storage.initial_storage_usage - current_storage_usage;
	storage.initial_storage_usage -= released_bytes;
}
```

**Impact** The total calculation of the storage usage during liquidation process is wrong, which can influence the storage usage of users.
**Suggestion I** Re-implement the whole logic.

#### 2.2.2 Storage usage is wrong in setting users' storage

**Status** Fixed
**Description** This issue is introduced in or before the initial commit. The `env::storage_usage()` returns the storage