---
name: BlockSec - Security Audit Report for LiNEAR - 202204
project: LiNEAR Protocol
repository: https://github.com/linear-protocol/LiNEAR.git
security researcher: BlockSec
date: 2022-04-01
file link: https://github.com/linear-protocol/audits/blob/main/BlockSec%20-%20Security%20Audit%20Report%20for%20LiNEAR%20-%20202204.pdf
---
# Security Audit Report for LiNEAR

## 1. Introduction

| Project | Version   | Commit SHA                               |
| ------- | --------- | ---------------------------------------- |
| LiNEAR  | Version 1 | fdbacc68c98205cba9f42c130d464ab3114257b6 |
| LiNEAR  | Version 2 | 41bb61f72a7575861b39faa5e888a86148958c5f |

## 2. Findings

### 2.1 Software Security

#### 2.1.1 Precision loss

**Status** Fixed in `version 2`
**Introduced by** `version 1`
**Description** In line 125 of function `internal_calculate_distribution`, division is performed before multiplication when calculating variable `reward_per_session`

```Rust title:contracts/linear/src/farm.rs ln:110
	fn internal_calculate_distribution()
		&self,
		farm: &Farm,
		total_staked: Balance,
	) -> Option<RewardDistribution> {
		if farm.start_date > env::block_timestamp() {
			// Farm hasn't started.
			return None;
		}
		let mut distribution = farm.last_distribution.clone();
		if distribution.undistributed == 0 {
			// Farm has ended.
			return Some(distribution);
		}
		distribution.reward_round = (env::block_timestamp() - farm.start_date) / SESSSION_INTERVAL;
		let reward_per_session =
			farm.amount / (farm.end_date - farm.start_date) as u128 * SESSION_INTERVAL as u128;*
```

**Impact** Division truncates for integers in Rust language. In this case, division before multiplication for integers may result in precision loss
**Suggestion I** Modify this calculation to perform multiplication before division
**Suggestion II** Pre-calculate the value of `reward_per_session` when a farm is added. This is because `farm.amount`, `farm.end_date` and `farm.start_date` do not change during farming process unless the owner stops it

### 2.2 DeFi Security
#### 2.2.1 User's available balance may be locked temporarily

**Status** Confirmed
**Introduced by** `version 1`
**Description** User's deposited `NEAR` will be added into the user's unstaked balance directly. Therefore, if the user invoked the `unstake/unstake_all` functions, that amount of available `NEAR` will be locked in the next 0 to 8 epochs.

```Rust title:contracts/linear/src/internal.rs ln:13
	pub(crate) fn internal_deposit(&mut self, amount: Balance) {
		let account_id = env::predecessor_account_id();
		let mut account = self.internal_get_account(&account_id);
		account.unstaked += amount;
		self.internal_save_account(&account_id, &account);
		
		Event::Deposit {
			account_id: &account_id
			amount: &U128(amount),
			new_unstaked_balance: &U128(account.unstaked),
		}	
		.emit();
}
```

**Impact** If a user is unaware of this contract workflow and directly interacts with this contract, the user's available balance may be locked temporarily
**Suggestion I** Add another attribute (e.g., `available_amount`) to struct `Account` to maintain the available `NEAR`
**Feedback from the Project** This is by design, basically following the original interface and design of the staking pool. To resolve the potential issue, we can make enhancements to add another field `unstaking` to distinguish from `unstaked`, and move `unstaking` into `unstaked` before we kick off the next unstaking process for this account. But for now, we'd prefer to not make the change at the moment, to keep the workflow consistent with staking pool. As a workaround, when users are unstaking from frontend, the UI will remind users to withdraw first if they have `unstaked` amount in their account.

#### 2.2.2 Unlimited reward distribution to beneficiaries

**Status** Fixed in `version 2`
**Introduced by** `version 1`
**Description** This contract does not check the total weight of all beneficiaries in the function `assert_valid` when setting up a new beneficiary

```Rust title:contracts/linear/src/owner.rs ln:21
	pub fn set_beneficiary(&mut self, account_id: AccountId, fraction: Fraction) {
		self.assert_owner();
		fraction.assert_valid();
		self.beneficiaries.insert(&account_id, &fraction);
	}
```

```Rust title:contracts/linear/src/utils.rs ln:21
	pub fn assert_valid(&self) {
		require!(self.denominator != 0, ERR_FRACTION_BAD_DENOMINATOR);
		require!(
			self.numerator <= self.denominator,
			ERR_FRACTION_BAD_NUMERATOR
			);
	}
```

**Impact** Once the total weight of beneficiaries exceeds 100%, the `LiNEARs` minted for beneficiaries may decrease the price of `LiNEAR` after the execution of action `epoch_update_rewards`
**Suggestion I** Introduce a reasonable threshold to limit the total reward distributed to beneficiaries

#### 2.2.3 User's unstaking requests may not be satisfied in time

**Status** Fixed in `version 2`
**Introduced by** `version 1`

**Description** The number of epochs returned from function `get_num_epoch_to_unstake` should be doubled in some corner cases. For example, if the total `NEARs` staked in validator staking pools, which are not in pending status, is not enough, the users can not withdraw all the unstaked `NEARs` requests after 4 epochs.

```Rust title:contracts/linear/src/validator_pool.rs ln:199
pub fn get_num_epoch_to_unstake(&self, _amount: u128) -> EpochHeight {
	// the num of epoches can be doubled or tripped if not enough stake is available
	NUM_EPOCHS_TO_UNLOCK
}
```

**Impact** User's unstaking requests may not always be satisfied in time
**Suggestion I** Implement a strategy to predict the user's unstaking waiting time based on validator staking pool's status

### 2.3 Additional Recommendation

#### 2.3.1 Function `epoch_update_rewards` may not work due to unlimited beneficiaries

**Status** Fixed in `version 2`
**Introduced by** `version 1`
**Description** The number of beneficiaries is unlimited. In this case, function `epoch_update_rewards` that invokes function `internal_distribute_staking_rewards` may run out of gas.

```Rust title:contracts/linear/src/epoch_actions.rs ln:129
pub fn epoch_update_rewards(&mut self, validator_id: AccountId) {
	let min_gas = GAS_EPOCH_UPDATE_REWARDS + GAS_EXT_GET_BALANCE + GAS_CB_VALIDATOR_GET_BALANCE;
	require!(
		env::prepaid_gas() >= min_gas,
		format!("{}. require at least {:?}, ERR_NO_ENOUGH_GAS, min_gas)
	);
	
	let validator = self
		.validator_pool
		.get_validator(&validator_id)
		.expect(ERR_VALIDATOR_NOT_EXIST);
		
	if validator.staked_amount == 0 && validator.unstaked_amount == 0 {
		return;
	}

	validator
		.refresh_total_balance()
		.then(ext_self_action_cb::validator_get_balance_callback(
			validator.account_id,
			env::curent_account_id(),
			NO_DEPOSIT,
			GAS_CB_VALIDATOR_GET_BALANCE,
		));
}
```

```Rust title:contract/src/internal.rs ln:200
/// When there are rewards, a part of them will be
/// given to executor, manager or treasury by minting new LiNEAR tokens.

pub(crate) fn internal_distribute_staking_rewards(&mut self, rewards: Balance) {
	let hashmap: HashMap<AccountId, Fraction> = self.internal_get_beneficiaries();
	for (account_id, fraction) in hashmap.iter() {
		let reward_near_amount: Balance = fraction.multiply(rewards);
		// mint extra LiNEAR for him
		self.internal_mint_beneficiary_rewards(&account_id, reward_near_amount);
	}
}
```

**Impact** Function `epoch_update_rewards` may not work due to limited gas when there are too many beneficiaries
**Suggestion I** it is recommended to add a reasonable threshold to limit the number of beneficiaries

#### 2.3.2 Redundant Code

**Status** Confirmed
**Introduced by** `version 1`
**Description** Parameter `registration_only` is redundant as function `storage_deposit` do not implement any logic for this parameter

```Rust title:contracts/linear/src/fungible_token/storage.rs ln:79
fn storage_deposit(
	&mut self,
	account_id: Option<AccountId>,
	registration_only: Option<bool>,
) -> StorageBalance {
	let amount: Balance = env::attached_deposit();
	let account_id = account_id.unwrap_or_else(env::predecessor_account_id);
	if let Some(account) = self.accounts.get(&account_id) {
		log!("The account is already registered, refunding the deposit");
		if amount > 0 {
		Promise::new(env::predecessor_account_id()).transfer(amount);
		}
	} else {
		let min_balance = self.storage_balance_bounds().min.0;
		if amount < min_balance {
			env::panic_str("The attached deposit is less than the minimum storage balance");
		}
	
		self.internal_register_account(&account_id);
		let refund = amount - min_balance;
		if refund > 0 {
			Promise::new(env::predecessor_account_id()).transfer(refund);
		}
	}
	self.internal_storage_balance_of(&account_id).unwrap()
}
```

**Suggestion I** It is recommended to remove this unused parameter in function `storage_deposit`
**Feedback from the Project** That's true. The same happens to the standard FT implementation in near-contract-standards crate. We'll keep the unused `registration_only` parameter to keep consistent with the standard `storage_deposit(account_id, registration_only)` interface

#### 2.3.3 Missing check on the `prepaid_gas` in function `ft_transfer_call`

**Status** Fixed in `version 2`
**Introduced by `version 1`
**Description** The `prepaid_gas` should be checked to ensure it is enough for the target functions including `ft_on_transfer` and `ft_resolve_transfer`

```Rust title:contracts/linear/src/fungible_token/core.rs ln:25
#[payable]
fn ft_transfer_call(
	&mut self,
	receiver_id: AccountId,
	amount: U128,
	memo: Option<String>,
	msg: String,
) -> PromiseOrValue<U128> {
	assert_one_yocto();
	let sender_id = env::predecessor_account_id();
	let amount = amount.into();
	self.internal_ft_transfer(&sender_id, &receiver_id, amount, memo);
	// Initiating receiver's call and the callback
	ext_fungible_token_receiver::ft_on_transfer(
		sender_id.clone(),
		amount.into(),
		msg,
		receiver_id.clone(),
		NO_DEPOSIT,
		env::prepaid_gas() - GAS_FOT_FT_TRANSFER_CALL,
	)
	.then(ext_ft_self::ft_resolve_transfer(
		sender_id,
		receiver_id,
		amount.into(),
		env::current_account_id(),
		NO_DEPOSIT,
		GAS_FOR_RESOLVE_TRANSFER,
	))
	.into()
}
```

**Suggestion I** Check the `prepaid_gas`

#### 2.3.4 The risk of centralized design

**Status** Confirmed
**Introduced by** `version 1`
**Description** This project has potential centralization problems.
**Suggestion I** It is recommended to introduce a decentralization design in the contract, such as multi-signature or DAO
**Feedback from the Project I** Yes. This in plan as mentioned in github.com/linear-protocol/LiNEAR/issues/60
**Suggestion II** The project owner needs to ensure the security of the private key of the `OWNER_ROLE/MANAGERS_ROLE` and use a multi-signature scheme to reduce the risk of single-point failure
**Feedback from the Project II** Yes. We have been working on security policies to reduce the risks of single point of failure



