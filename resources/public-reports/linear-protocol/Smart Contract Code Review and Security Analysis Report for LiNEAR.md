---
name: Smart Contract Code Review and Security Analysis Report for LiNEAR
project: LiNEAR Protocol
repository: https://github.com/linear-protocol/LiNEAR.git
security researcher: Hacken
date: 2024-04-30
file link: https://github.com/linear-protocol/audits/blob/main/Hacken%20-%20Smart%20Contract%20Code%20Review%20and%20Security%20Analysis%20Report%20for%20LiNEAR%20-%20202405.pdf
---
# Smart Contract Code Review and Security Analysis Report for LiNEAR


| Audited By            | Approved By     |
| --------------------- | --------------- |
| Przemyslaw Swiatowiec | Ataberk Yavuzer |
## Findings

### F-2024-1979 - Lack of user charges for new deposit account creation leading to potential griefing attacks - Medium

**Description**
It was observed that the contract does not charge users for the storage used when creating new deposit acounts (`deposit` function). In the NEAR Protocol, the contract's balance is utilized to pay for storage costs. This oversight allows users, including potential malicious actors, to create deposit accounts with zero token deposits, leading to the allocation of new storage slots at the contract's expense.

Our tests revealed that the cost for adding a new `Account` struct to storage is approximately **0.004 NEAR**, while the transaction cost paid by a user is only **0.0005 NEAR**. This discrepancy indicates that the attacker can lock contract funds by utilizing storage slots creation for new accounts with low cost.

This situation is exacerbated by two facts:
1. Currently, zero-amount deposits are permitted.
2. The contract lacks a mechanism to reclaim or free up storage space once allocated.

This can lead to a scenario where a malicious actor deliberately drains the contract's available balance by creating numerous empty deposit accounts. This way there would be no funds left in the contract to accept new deposits - the contract is going to miss Near to pay for new storage.

What is more, in the current implementation, users deposit tokens and do not stake them. Such deposited tokens are part of the contract balance. As a result, malicious actor can lock not only funds that were added by protocol owners but also can potentially lock legitimate user deposits within the contract without the possibility of withdrawal or utilization.

**Affected code:**
```Rust title:contracts/linear/src/stake.rs+internal.rs
#[payable]
pub fn deposit (&mut self) {
	let amount = env::attached_deposit();
	self.internal_deposit(amount);
}

pub(crate) fn internal_deposit(&mut self, amount: Balance) {
	self.assert_running();
	
	let account_id = env::predecessor_account_id();
	let mut account = self.internal_get_account(&account_id);
	account.unstaked += amount;
	self.internal_save_account(&account_id, &account);
	
	Event::Deposit {
		account_id: &account_id,
		amount: &U128(amount),
		new_unstaked_balance: &U128(account.unstaked),
	} 
	.emit();
}

#[payable]
fn storage_withdraw(&mut self, amount: Option<U128>) -> StorageBalance {
	assert_one_yocto();
	let predecessor_account_id = env::predecessor_account_id();
	if let Some(storage_balance) = self.internal_storage_balance_of(&precedessor_account_id);
		match amount {
			Some(amount) if amount.0 > 0 => {
				env::panic_str("The amount is greater than the available storage balance");
			}
			_ => storage_balance,
		}
	} else {
		env::panic_str(
			format!("The account {} is not registered", &predecessor_account_id).as_str(),
		);
	}
}

/// Storage unregister is disabled because staking users don't need
/// to deposit but they are allowed to withdraw storage fee with
/// the current implementation.

#[payable]
fn storage_unregister(&mut self, force: Option<bool>) -> bool {
	panic!("Storage unregister is not supported yet.");
}

```

**Status:** Mitigated

#### Classification

**Impact**
Likelihood 1-5: 3
Impact 1-5: 3
Exploitability 0-2: 0
Complexity 0-2: 2
Final Score: 2.6 (Medium)
Hacken Calculator Version: 0.6

**Severity** Medium

#### Recommendations

**Recommendation**
To mitigate the risks associated with free storage allocation for new deposit accounts and protect the contract's balance from potential griefing attacks, it is recommended that the contract implement a charging mechanism for storage slots used by users. Users should bear the cost of the storage required for their deposit accounts to prevent malicious exploitation and ensure the contract's sustainability.

**Remediation**
Commit: [aa045346b87feca978476121883ab1611b487600](https://github.com/linear-protocol/LiNEAR/commit/aa045346b87feca978476121883ab1611b487600)

the deposit and stake interfaces are designed to align with the staking pool core contract, thereby ensuring consistency across the platform. Given the infrequency of griefing attacks and the impact on user experience and cross-contract interactions, the decision to forego storage fees is deemed appropriate. The strategy to disallow zero-amount deposits has been adopted to mitigate potential risks while maintaining seamless integration and functionality.

#### Evidences
**PoC**

```
test(
	'Drain contract tokens',
	async (t) => {
		const { contract, alice, root, owner } = t.context;
		const whitelist = await root.createSubAccount("whitelist2");
		await whitelist.deploy("compiled-contracts/mock_whitelist.wasm");
		await root.call(whitelist, 'new', {});
		const validator1 = await root.createSubAccount('validator1', {
			initialBalance: NEAR.parse('1000000').toString(),
		});
		await root.call(whitelist, 'add_whitelist', {"account_id": validator1.accountId});
		
		await owner.call(contract, 'set_whitelist_contract_id', {
			account_id: whitelist.accountId,
		});
		
		let drained = false;
		let counter = 0;
		// legit user deposits
		const legitDeposit = NEAR.parse('1');
		await alice.call(contract, 'deposit', {}, { attachedDeposit: legitDeposit });
		while(!drained) {
			counter++;
			try {
				const user = await root.createSubAccount(counter.toString(), {
					initialBalance: NEAR.parse('1000000').toString(),
				});
				const deposit = NEAR.parse('0');
				await user.call(contract, 'deposit', {}, { attachedDeposit: deposit });
				const contractBalance = await contract.balance();
				console.log(contractBalance.total.toHuman());
				const userBalance = user.balance();
				console.log((await userBalance).total.toHuman());
				break;
			} catch(e) {
				console.log(e);
				drained = true;
			}
		}
		
		// observe that contract balance is 0 and user cannot create new deposits
		const contractBalance = await contract.balance();
		console.log(contractBalance.total.toHuman());
		await alice.call(contract, 'deposit', {}, { attachedDeposit: legitDeposit });
		}
```

---

### F-2024-1983 - Inability to free allocated storage for unused accounts - Low

**Description**
During the security and functionality review of the smart contract, it was observed that there is no mechanism in place to free up storage once it has been allocated. This limitation is particularly problematic for accounts that are no longer in use. In the context of the NEAR protocol, where contracts are charged for storage allocation, the inability to reclaim storage space for unused accounts can lead to inefficient use of resources and unnecessary financial costs for the users. The loss primarily impacts users who send LiNEAR tokens to recipients without previous deposits or stakes in the protocol, as they must cover a non-refundable storage fee, which neither the sender nor the recipient can retrieve.

**Affected code:**

```Rust
fn storage_withdraw(&mut self, amount: Option) -> StorageBalance {
	assert_one_yocto();
	let predecessor_account_id = env::predecessor_account_id();
	if let Some(storage_balance) = self.internal_storage_balance_of(&predecessor_account_id
		match amount {
			Some(amount) if amount.0 > 0 => {
				env::panic_str("The amount is greater than the available storage balance");
			}
			_ => storage_balance,
		}
	} else {
		env:panic_str(
			format!("The account {} is not registered", &predecessor_account_id).as_str(),
		);
	}
}

/// Storage unregister is disabled because staking users don't need
/// to deposit but they are allowed to withdraw storage fee with
/// the current implementation.
#[payable]
fn storage_unregister(&mut self, force: Option) -> bool {
	panic!("Storage unregister is not supported yet.");
}
```

**Status** Fixed

#### Classification

**Impact**
Likelihood 1-5: 3
Impact 1-5: 2
Exploitability 0-2: 0
Complexity 0-2: 2
Final Score: 2.1 (Low)
Hacken Calculator Version: 0.6

**Severity** Low

#### Recommendations

**Remediation**
To address the identified issue and improve the contract's efficiency and costeffectiveness, it is recommended to implement a mechanism that allows for the freeing of storage for accounts that are no longer in use. This would involve creating a method within the contract that can be invoked to delete unused accounts and reclaim the associated storage space.

Commit: [aa045346b87feca978476121883ab1611b487600](https://github.com/linear-protocol/LiNEAR/commit/aa045346b87feca978476121883ab1611b487600)

the proposal to introduce a mechanism for freeing storage of inactive accounts is reconsidered in light of F-2024-1979, which effectively addresses related concerns. Due to potential security risks highlighted by the client, such as attackers exploiting minimal deposits for disproportionate withdrawals, it is recommended to continue prohibiting storage withdrawals and account unregistering. This approach ensures the ongoing integrity and security of the contract as established by F-2024-1979.

## Observations

### F-2024-1975 - Lack of event emissions for critical state changes - Info

**Description**
The LiNear contract does not emit events for critical actions and state changes, particularly in functions such as set_owner, add_manager, remove_manager, set_beneficiary, remove_beneficiary, set_treasury, set_whitelist_contract_id, pause, resume. Events in Near contracts are crucial for tracking changes and actions off-chain, providing transparency and auditability for contract interactions. The absence of events for these critical operations means that external systems, interfaces, and users lack a reliable, onchain method to detect and respond to these significant changes. This oversight can impede monitoring, analytics, and integration with off-chain systems, ultimately affecting the contract's usability and governance.

**Status** Fixed

#### Recommendations
**Remediation**
Modify the contract to emit specific events for all critical state changes.

Remediation (commit id: [ee3088aa7abe62e571edabbab15c2774d1416b94](https://github.com/linear-protocol/LiNEAR/commit/ee3088aa7abe62e571edabbab15c2774d1416b94)):
events for the aforementioned changes are emitted.

### F-2024-1977 - Unnecessary double checks in add_manager and remove_manager functions - Info

**Description**
During the security audit of the LiNear contract, it was observed that the functions add_manager and remove_manager contain redundant state checks for the contract's pause status (assert_running function), The assert_running function which validates that the contract is not paused, is invoked twice within the same transactional context for each of the aforementioned functions. This redundancy results in unnecessary computation, thereby increasing the execution cost for users performing these operations. The assert_running is verified both in add_manager/remove_manager and internal_add_manager/internal_remove_manager:

What is more, the managers struct updates are also happening in contract initialization - the contract owner is automatically set as the manager. During initialization, there is no need to check for pause status as pause variable is set to false in the initialization function.

**Status** Fixed

#### Recommendations

**Remediation**
It is recommended to check for contract pause state only once - either in internal or external functions.

Remediation (commit id: [4e8a6d294aaaa9d5fee6fc154f2ba26fa8a2a50d](https://github.com/linear-protocol/LiNEAR/commit/4e8a6d294aaaa9d5fee6fc154f2ba26fa8a2a50d)): the double checks were removed.

### F-2024-1978 - Lack of two-step ownership transfer pattern - Info

**Description**
The current implementation of the LiNear smart contract allows for the immediate transfer of contract ownership through a single transaction, without an intermediate confirmation step. This one-step ownership transfer mechanism permits the current owner to set any address as the new owner directly, without a secondary verification or acceptance step from the new owner. This approach exposes the contract to risks associated with locking contract ownership if an incorrect new owner is set. Such a contract could be unlocked only by upgrading the contract to a new version (migration process).

```Rust
pub fn set_owner(&mut self, new_owner_id: AccountId) {
	self.assert_owner();
	self.owner_id = new_owner_id;
}
```

**Status** Mitigated

#### Recommendations

**Remediation**
Consider implementing a two-step ownership transfer pattern.

Remediation: the client states that since all management activities, including changes in ownership, are handled by the DAO, implementing a two-step ownership transition pattern is redundant.

### F-2024-2164 - Inconsistent account data retrieval in internal_get_account function - Info

**Description**
It was observed that the internal_get_account function within the smart contract inconsistently retrieves account data due to the use of unwrap_or_default. This method returns a default account structure when an account does not exist, instead of throwing an error.

As a result, this improper error handling causes downstream inaccuracies in related view functions such as get_account_details and get_account. These functions incorrectly report that non-existent accounts can withdraw funds (can_withdraw set to true) and display other account values as 0. This behavior can mislead users or external systems interacting with the contract by presenting inaccurate account status and data.

```Rust
pub fn get_account(&self, account_id: AccountId) -> HumanReadableAccount {
	let account = self.internal_get_account(&account_id);
	HumanReadableAccount {
		account_id,
		unstaked_balance: account.unstaked.into(),
		staked_balance: self
			.staked_amount_from_num_shares_rounded_down(account.stake_shares)
			.into(),
		can_withdraw: account.unstaked_available_epoch_height <= get_epoch_height(),
	}
}

pub fn get_account_details(&self, account_id: AccountId) -> AccountDetailsView {
	let account = self.internal_get_account(&account_id);
	AccountDetailsView {
		account_id,
		unstaked_balance: account.unstaked.into(),
		staked_balance: self
			.staked_amount_from_num_shares_rounded_down(account.stake_shares)
			.into(),
		unstaked_available_epoch_height: account.unstaked_available_epoch_height,
		can_withdraw: account.unstaked_available_epoch_height <= get_epoch_height(),
	}
}

pub(crate) fn internal_get_account(&self, account_id: &AccountId) -> Account {
	self.accounts.get(account_id).unwrap_or_default()
}
```

**Status** Accepted

#### Recommendations

**Remediation**
To correct data inconsistencies and improve the integrity of account information retrieved from the smart contract, it is recommended to modify the internal_get_account function to throw an appropriate error when an account does not exist, instead of returning a default account structure.

**Remediation:** to maintain compatibility with existing modules, the client has decided not to alter the get_account function. This decision ensures consistency with the implementation of the staking pool contract.