pub type EthPublicKey = starknet::secp256k1::Secp256k1Point;
#[starknet::interface]
pub trait IRosettaAccount<TState> {
    fn __execute__(self: @TState, calls: Array<felt252>) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, calls: Array<Call>) -> felt252;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252, public_key: EthPublicKey
    ) -> felt252;
    fn get_public_key(self: @TState) -> EthPublicKey;
    fn set_public_key(ref self: TState, new_public_key: EthPublicKey, signature: Span<felt252>);
    // Camel case
    fn isValidSignature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn getPublicKey(self: @TState) -> EthPublicKey;
    fn setPublicKey(ref self: TState, newPublicKey: EthPublicKey, signature: Span<felt252>);
}

#[starknet::contract(account)]
mod RosettaAccount {
    use super::EthPublicKey;
    use starknet::{EthAddress, get_execution_info, get_contract_address};


    #[storage]
    struct Storage {
        ethereum_address: EthAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl AccountImpl of super::IRosettaAccount<ContractState> {
        fn __execute__(self: @TState, calls: Array<felt252>) -> Array<Span<felt252>> {}

        fn __validate__(self: @TState, calls: Array<Call>) -> felt252 {}

        fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252 {}

        fn supports_interface(self: @TState, interface_id: felt252) -> bool {}

        fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252 {}

        fn __validate_deploy__(
            self: @TState,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: EthPublicKey
        ) -> felt252 {}

        fn get_public_key(self: @TState) -> EthPublicKey {}

        fn set_public_key(
            ref self: TState, new_public_key: EthPublicKey, signature: Span<felt252>
        ) {}

        fn isValidSignature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252 {
            self.is_valid_signature(hash, signature)
        }

        fn getPublicKey(self: @TState) -> EthPublicKey {
            self.get_public_key()
        }

        fn setPublicKey(ref self: TState, newPublicKey: EthPublicKey, signature: Span<felt252>) {
            self.set_public_key(newPublicKey, signature)
        }
    }
}
