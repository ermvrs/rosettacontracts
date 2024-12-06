use starknet::{ContractAddress, EthAddress};
pub fn developer() -> ContractAddress {
    starknet::contract_address_const::<1>()
}

pub fn eth_account() -> EthAddress {
    0x12345678.try_into().unwrap()
}