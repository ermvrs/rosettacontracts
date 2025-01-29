#[starknet::interface]
pub trait IMockUpgradedAccount<TState> {
    fn __execute__(self: @TState, call: Array<felt252>) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, call: Array<felt252>) -> felt252;
    fn is_valid_signature(self: @TState, hash: u256, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252
    ) -> felt252;
    fn upgraded(self: @TState,) -> felt252;
}

#[starknet::contract(account)]
pub mod MockUpgradedAccount {
    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState,) {}
    #[abi(embed_v0)]
    impl AccountImpl of super::IMockUpgradedAccount<ContractState> {
        // Instead of Array<Call> we use Array<felt252> since we pass different values to the
        // parameter
        // It is EOA execution so multiple calls are not possible right now. We will add Multicalls
        // in a different way in beta calls params can include raw signed tx or can include the abi
        // parsing bit locations for calldata
        fn __execute__(self: @ContractState, call: Array<felt252>) -> Array<Span<felt252>> {
            return array![array![].span()];
        }

        fn __validate__(self: @ContractState, call: Array<felt252>) -> felt252 {
            starknet::VALIDATED
        }

        fn is_valid_signature(
            self: @ContractState, hash: u256, signature: Array<felt252>
        ) -> felt252 {
            starknet::VALIDATED
        }

        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            true
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            0
        }

        fn __validate_deploy__(
            self: @ContractState, class_hash: felt252, contract_address_salt: felt252,
        ) -> felt252 {
            starknet::VALIDATED
        }

        fn upgraded(self: @ContractState) -> felt252 {
            1
        }
    }
}
