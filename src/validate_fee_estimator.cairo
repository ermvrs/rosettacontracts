use rosettacontracts::accounts::types::{RosettanetCall};
use starknet::{ContractAddress, EthAddress};
#[starknet::interface]
pub trait IValidateFeeEstimator<TState> {
    fn __execute__(ref self: TState, target: ContractAddress, call: RosettanetCall) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, target: ContractAddress, call: RosettanetCall) -> felt252;
    fn is_valid_signature(self: @TState, hash: u256, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TState,
        class_hash: felt252,
        contract_address_salt: felt252,
        eth_address: EthAddress,
        registry: ContractAddress,
    ) -> felt252;
}

#[starknet::contract(account)]
pub mod ValidateFeeEstimator {
    use rosettacontracts::accounts::base::{IRosettaAccountDispatcher, IRosettaAccountDispatcherTrait};
    use rosettacontracts::accounts::types::{RosettanetCall};
    use starknet::{ContractAddress, EthAddress, ClassHash};
    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl ValidateFeeEstimatorImpl of super::IValidateFeeEstimator<ContractState> {
        fn __execute__(ref self: ContractState, target: ContractAddress, call: RosettanetCall) -> Array<Span<felt252>> {
            IRosettaAccountDispatcher { contract_address: target}.validate_rosettanet_call(call);
            array![array![].span()]
        }

        fn __validate__(self: @ContractState, target: ContractAddress, call: RosettanetCall) -> felt252 {
            assert(true == false, 'NOT ALLOWED');
            0
        }
        fn is_valid_signature(self: @ContractState, hash: u256, signature: Array<felt252>) -> felt252 {
            0
        }
        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            true
        }
        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            starknet::VALIDATED
        }
        fn __validate_deploy__(
            self: @ContractState,
            class_hash: felt252,
            contract_address_salt: felt252,
            eth_address: EthAddress,
            registry: ContractAddress,
        ) -> felt252 {
            starknet::VALIDATED
        }
    }
}