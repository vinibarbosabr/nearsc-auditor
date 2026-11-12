// The NEP-141 thin-wrapper shape: the transfer methods are the ABI and the
// 1-yocto check lives inside the delegated near-contract-standards
// `FungibleToken` implementation (`self.<field>.ft_transfer(...)`). The
// delegation itself is the check path.
#[near]
impl Fixture {
    #[payable]
    pub fn ft_transfer(
        &mut self,
        receiver_id: near_sdk::AccountId,
        amount: u128,
        memo: Option<String>,
    ) {
        self.token.ft_transfer(receiver_id, amount, memo);
    }

    #[payable]
    pub fn ft_transfer_call(
        &mut self,
        receiver_id: near_sdk::AccountId,
        amount: u128,
        memo: Option<String>,
        msg: String,
    ) -> near_sdk::PromiseOrValue<u128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }
}
