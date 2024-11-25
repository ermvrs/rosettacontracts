pub type EthPublicKey = starknet::secp256k1::Secp256k1Point;
use starknet::{EthAddress};
#[starknet::interface]
pub trait IRosettaAccount<TState> {
    fn __execute__(self: @TState, calls: Array<felt252>) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, calls: Array<felt252>) -> felt252;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252, eth_public_key: EthPublicKey
    ) -> felt252;
    fn get_ethereum_address(self: @TState) -> EthAddress;
    // Camel case
    fn isValidSignature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn getEthereumAddress(self: @TState) -> EthAddress;
}

#[starknet::contract(account)]
pub mod RosettaAccount {
    use super::EthPublicKey;
    use core::num::traits::Zero;
    use starknet::{
        EthAddress, get_contract_address, get_caller_address, get_tx_info
    };
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use rosettacontracts::accounts::utils::{is_valid_eth_signature, Secp256k1PointStorePacking, pubkey_to_eth_address};
    use rosettacontracts::utils::serialization::{deserialize_bytes,compute_y_parity};
    use rosettacontracts::utils::rlp::{RLPType, RLPTrait, RLPItem, RLPHelpersTrait};
    use rosettacontracts::utils::transaction::eip1559::{Eip1559, Eip1559Trait};

    pub mod Errors {
        pub const INVALID_CALLER: felt252 = 'Rosetta: invalid caller';
        pub const INVALID_SIGNATURE: felt252 = 'Rosetta: invalid signature';
        pub const INVALID_TX_VERSION: felt252 = 'Rosetta: invalid tx version';
        pub const UNAUTHORIZED: felt252 = 'Rosetta: unauthorized';
    }

    pub struct RosettanetCall {
        calldata: Array<felt252>,
        directives: Array<bool>, // We use this directives to figure out u256 splitting happened in element in same index For ex if 3rd element of this array is true, it means 3rd elem is low, 4th elem is high of u256
        value: u256 // To be used future
    }


    #[storage]
    struct Storage {
        ethereum_address: EthAddress,
        ethereum_public_key: EthPublicKey
    }

    #[constructor]
    fn constructor(ref self: ContractState, eth_public_key: EthPublicKey) {
        self.ethereum_public_key.write(eth_public_key);
        self.ethereum_address.write(pubkey_to_eth_address(eth_public_key));
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

            // We don't use Call type
            // Instead we pass raw transaction properties in each different felt. And v,r,s on signature
            // So we verify that transaction is signed by correct address from generating
            // Transaction again.
            // There is no need to use Call struct here because all calldata will be passed as array of felts.

            // 1) Check if array length is higher than minimum
            // Order: ChainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data (Array)
            
            array![array!['todo'].span()]
        }

        fn __validate__(self: @ContractState, calls: Array<felt252>) -> felt252 {
            // TODO: check if validations enough
            // assert(calls.transaction.length > 9, 'Calldata wrong'); // TODO: First version only supports EIP1559
            // Check if to address registered on lens
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
            // TODO: Rosettanet accounts wont declare code
            self.validate_transaction()
        }

        fn __validate_deploy__(
            self: @ContractState,
            class_hash: felt252,
            contract_address_salt: felt252,
            eth_public_key: EthPublicKey
        ) -> felt252 {
            // TODO: check if validations enough
            self.validate_transaction()
        }

        fn get_ethereum_address(self: @ContractState) -> EthAddress {
            self.ethereum_address.read()
        }

        fn isValidSignature(
            self: @ContractState, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            self.is_valid_signature(hash, signature)
        }

        fn getEthereumAddress(self: @ContractState) -> EthAddress {
            self.get_ethereum_address()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn initializer(ref self: ContractState, ethPubKey: EthPublicKey) {
        }

        fn assert_only_self(self: @ContractState) {
            let caller = get_caller_address();
            let self = get_contract_address();
            assert(self == caller, Errors::UNAUTHORIZED);
        }

        /// Validates the signature for the current transaction.
        /// Returns the short string `VALID` if valid, otherwise it reverts.
        fn validate_transaction(self: @ContractState) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature; // Signature includes v,r,s
            assert(self._is_valid_signature(tx_hash, signature), Errors::INVALID_SIGNATURE);
            starknet::VALIDATED
        }

        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.
        fn _is_valid_signature(
            self: @ContractState, hash: felt252, signature: Span<felt252>
        ) -> bool {
            // TODO verify transaction with eth address not pub key
            // Kakarot calldata ile transactionu bir daha olusturup verify etmeye calismis
            assert(signature.len() == 5, 'Invalid Signature');
            let r: u256 = u256 {
                low: (*signature.at(0)).try_into().unwrap(),
                high: (*signature.at(1)).try_into().unwrap()
            };
            let s: u256 = u256 {
                low: (*signature.at(2)).try_into().unwrap(),
                high: (*signature.at(3)).try_into().unwrap()
            };
            let y_parity: u8 = (*signature.at(4)).try_into().unwrap();

            let public_key: EthPublicKey = self.ethereum_public_key.read();

            let chain_id: u64 = 1; // TODO: What will be the chainid?

            
            is_valid_eth_signature(hash, public_key, signature)
        }
    }
}
