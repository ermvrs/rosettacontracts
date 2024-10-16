pub type EthPublicKey = starknet::secp256k1::Secp256k1Point;
use starknet::EthAddress;
#[starknet::interface]
pub trait IRosettaAccount<TState> {
    fn __execute__(self: @TState, calls: Array<felt252>) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, calls: Array<felt252>) -> felt252;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252, public_key: EthPublicKey
    ) -> felt252;
    fn get_public_key(self: @TState) -> EthPublicKey;
    fn get_ethereum_address(self: @TState) -> EthAddress;
    fn set_public_key(ref self: TState, new_public_key: EthPublicKey, signature: Span<felt252>);
    // Camel case
    fn isValidSignature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn getPublicKey(self: @TState) -> EthPublicKey;
    fn getEthereumAddress(self: @TState) -> EthAddress;
    fn setPublicKey(ref self: TState, newPublicKey: EthPublicKey, signature: Span<felt252>);
}

#[starknet::contract(account)]
pub mod RosettaAccount {
    use super::EthPublicKey;
    use core::num::traits::Zero;
    use starknet::{
        EthAddress, get_contract_address, get_caller_address, get_tx_info
    };
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use rosettacontracts::accounts::utils::{is_valid_eth_signature, Secp256k1PointStorePacking};

    pub mod Errors {
        pub const INVALID_CALLER: felt252 = 'Rosetta: invalid caller';
        pub const INVALID_SIGNATURE: felt252 = 'Rosetta: invalid signature';
        pub const INVALID_TX_VERSION: felt252 = 'Rosetta: invalid tx version';
        pub const UNAUTHORIZED: felt252 = 'Rosetta: unauthorized';
    }


    #[storage]
    struct Storage {
        ethereum_address: EthAddress,
        ethereum_public_key: EthPublicKey
    }

    #[constructor]
    fn constructor(ref self: ContractState, eth_account: EthAddress) {
        self.ethereum_address.write(eth_account);
    }
    // TODO: Raw transaction tx.signature da, __execute__ parametresindede bit locationlar mı olacak??
    #[abi(embed_v0)]
    impl AccountImpl of super::IRosettaAccount<ContractState> {
        // Instead of Array<Call> we use Array<felt252> since we pass different values to the
        // parameter
        // It is EOA execution so multiple calls are not possible
        // calls params can include raw signed tx or can include the abi parsing bit locations for calldata
        fn __execute__(self: @ContractState, calls: Array<felt252>) -> Array<Span<felt252>> {
            let sender = get_caller_address();
            assert(sender.is_zero(), Errors::INVALID_CALLER);
            // TODO: Check tx version

            // TODO: Exec call

            // 1) Deserialize tx data from signature to get calldata and target contract.
            // 2) Match the entrypoint and call contract with calldata parsed according this function bit size param
            array![array!['todo'].span()]
        }

        fn __validate__(self: @ContractState, calls: Array<felt252>) -> felt252 {
            // TODO: check if validations enough
            self.validate_transaction()
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            if self._is_valid_signature(hash, signature.span()) {
                starknet::VALIDATED
            } else {
                0
            }
        }

        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            true
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            // TODO: check if validations enough
            self.validate_transaction()
        }

        fn __validate_deploy__(
            self: @ContractState,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: EthPublicKey
        ) -> felt252 {
            // TODO: check if validations enough
            self.validate_transaction()
        }

        fn get_public_key(self: @ContractState) -> EthPublicKey {
            self.ethereum_public_key.read()
        }

        fn get_ethereum_address(self: @ContractState) -> EthAddress {
            self.ethereum_address.read()
        }

        // We dont need that function
        fn set_public_key(
            ref self: ContractState, new_public_key: EthPublicKey, signature: Span<felt252>
        ) {}

        fn isValidSignature(
            self: @ContractState, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            self.is_valid_signature(hash, signature)
        }

        fn getPublicKey(self: @ContractState) -> EthPublicKey {
            self.get_public_key()
        }

        fn getEthereumAddress(self: @ContractState) -> EthAddress {
            self.get_ethereum_address()
        }

        // We dont need that function
        fn setPublicKey(
            ref self: ContractState, newPublicKey: EthPublicKey, signature: Span<felt252>
        ) {
            self.set_public_key(newPublicKey, signature)
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn initializer(ref self: ContractState, ethPubKey: EthPublicKey) {
            // Write pubkey to storage
            self._set_public_key(ethPubKey);
        }

        fn assert_only_self(self: @ContractState) {
            let caller = get_caller_address();
            let self = get_contract_address();
            assert(self == caller, Errors::UNAUTHORIZED);
        }

        // Overwrites ethereum public key. We may remove that function since we only need to
        // write during initialization.
        fn _set_public_key(ref self: ContractState, new_public_key: EthPublicKey) {
            self.ethereum_public_key.write(new_public_key);
        }

        /// Validates the signature for the current transaction.
        /// Returns the short string `VALID` if valid, otherwise it reverts.
        fn validate_transaction(self: @ContractState) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;
            assert(self._is_valid_signature(tx_hash, signature), Errors::INVALID_SIGNATURE);
            starknet::VALIDATED
        }

        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.
        fn _is_valid_signature(
            self: @ContractState, hash: felt252, signature: Span<felt252>
        ) -> bool {
            let public_key: EthPublicKey = self.ethereum_public_key.read();
            is_valid_eth_signature(hash, public_key, signature)
        }
    }
}
