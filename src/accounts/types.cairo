use starknet::{EthAddress};

#[derive(Copy, Drop, Serde)]
pub struct RosettanetSignature {
    pub r: u256,
    pub s: u256,
    pub v: u32, // 27 or 28
}

#[derive(Copy, Drop, Clone, Serde)]
pub struct RosettanetCall {
    pub tx_type: u8, // 0: Legacy, 1: Eip2930, 2: Eip1559, only 0 and 2 supported atm
    pub to: EthAddress, // This has to be this account address for multicalls
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_price: u128, // On legacy transactions
    pub gas_limit: u64,
    pub value: u256, // To be used future
    pub calldata: Span<felt252>, // Calldata len must be +1 directive len
}

#[derive(Copy, Drop, Clone, Serde)]
pub struct RosettanetMulticall {
    pub to: felt252,
    pub entrypoint: felt252,
    pub calldata: Span<felt252>,
}