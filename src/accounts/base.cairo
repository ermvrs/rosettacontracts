use starknet::{EthAddress, ContractAddress};
use rosettacontracts::accounts::utils::{RosettanetCall};


#[starknet::interface]
pub trait IRosettaAccount<TState> {
    fn __execute__(self: @TState, call: RosettanetCall) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, call: RosettanetCall) -> felt252;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252, eth_address: EthAddress,
        registry: ContractAddress
    ) -> felt252;
    fn get_ethereum_address(self: @TState) -> EthAddress;
    // Camel case
    fn isValidSignature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn getEthereumAddress(self: @TState) -> EthAddress;
}

#[starknet::contract(account)]
pub mod RosettaAccount {
    use core::num::traits::Zero;
    use starknet::{
        ContractAddress, EthAddress, get_contract_address, get_caller_address, get_tx_info
    };
    use starknet::syscalls::{call_contract_syscall};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use rosettacontracts::accounts::utils::{is_valid_eth_signature, RosettanetSignature, RosettanetCall, validate_target_function, generate_tx_hash};
    use crate::rosettanet::{IRosettanetDispatcher, IRosettanetDispatcherTrait};
    use openzeppelin::utils::deployments::{calculate_contract_address_from_deploy_syscall};

    pub mod Errors {
        pub const INVALID_CALLER: felt252 = 'Rosetta: invalid caller';
        pub const INVALID_SIGNATURE: felt252 = 'Rosetta: invalid signature';
        pub const INVALID_TX_VERSION: felt252 = 'Rosetta: invalid tx version';
        pub const UNAUTHORIZED: felt252 = 'Rosetta: unauthorized';
    }

    #[storage]
    struct Storage {
        ethereum_address: EthAddress,
        nonce: u64,
        registry: ContractAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState, eth_address: EthAddress, registry: ContractAddress) {
        self.ethereum_address.write(eth_address);
        self.registry.write(registry);
        // TODO: verify on deploy that address is correct
    }
    // TODO: Raw transaction tx.signature da, __execute__ parametresindede bit locationlar mı olacak??
    #[abi(embed_v0)]
    impl AccountImpl of super::IRosettaAccount<ContractState> {
        // Instead of Array<Call> we use Array<felt252> since we pass different values to the
        // parameter
        // It is EOA execution so multiple calls are not possible
        // calls params can include raw signed tx or can include the abi parsing bit locations for calldata
        fn __execute__(self: @ContractState, call: RosettanetCall) -> Array<Span<felt252>> {
            let sender = get_caller_address();
            assert(sender.is_zero(), Errors::INVALID_CALLER);

            let eth_target: EthAddress = call.to;
            let sn_target: ContractAddress = IRosettanetDispatcher { contract_address: self.registry.read() }.get_starknet_address(eth_target);
            assert(sn_target != starknet::contract_address_const::<0>(), 'target not registered');

            let entrypoint = validate_target_function(call.target_function, call.calldata);
            // If its native transfer do not handle calldata
            let mut calldata = call.calldata;
            calldata.pop_front(); // Remove first element, it is function selector

            let result: Span<felt252> = call_contract_syscall(sn_target, entrypoint, calldata).unwrap();
            // self.nonce.write(self.nonce.read() + 1); // Problem here ???
            array![result]
        }

        fn __validate__(self: @ContractState, call: RosettanetCall) -> felt252 {
            // TODO: check if validations enough
            // assert(calls.transaction.length > 9, 'Calldata wrong'); // TODO: First version only supports EIP1559
            // Check if to address registered on lens
            assert(call.nonce == self.nonce.read(), 'Nonce wrong');
            self.validate_transaction(call)
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            if self._is_valid_signature(hash.into(), signature.span()) {
                starknet::VALIDATED
            } else {
                0
            }
        }

        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            true
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            0
        }

        fn __validate_deploy__(
            self: @ContractState,
            class_hash: felt252,
            contract_address_salt: felt252,
            eth_address: EthAddress,
            registry: ContractAddress
        ) -> felt252 {
            assert(contract_address_salt == eth_address.into(), 'Salt and param mismatch');
            assert(registry != starknet::contract_address_const::<0>(), 'registry zero');
            let address = calculate_contract_address_from_deploy_syscall(
                eth_address.into(),
                class_hash.try_into().unwrap(),
                array![eth_address.into(), registry.into()].span(),
                0.try_into().unwrap()
            );

            assert(address == get_contract_address(), 'deployed address wrong');
            starknet::VALIDATED
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
        fn assert_only_self(self: @ContractState) {
            let caller = get_caller_address();
            let self = get_contract_address();
            assert(self == caller, Errors::UNAUTHORIZED);
        }

        /// Validates the signature for the current transaction.
        /// Returns the short string `VALID` if valid, otherwise it reverts.
        fn validate_transaction(self: @ContractState, call: RosettanetCall) -> felt252 {
            let tx_info = get_tx_info().unbox();

            // Validate target_function and calldata matches
            let _ = validate_target_function(call.target_function, call.calldata);

            // Validate transaction signature
            let expected_hash = generate_tx_hash(call);

            let signature = tx_info.signature; // Signature includes v,r,s
            assert(self._is_valid_signature(expected_hash, signature), Errors::INVALID_SIGNATURE);
            starknet::VALIDATED
        }

        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.
        fn _is_valid_signature(
            self: @ContractState, hash: u256, signature: Span<felt252>
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
            let v: u32 = (*signature.at(4)).try_into().unwrap();

            let rosettanet_signature = RosettanetSignature {
                v: v,
                r: r,
                s: s,
            };

            let eth_address: EthAddress = self.ethereum_address.read();

            is_valid_eth_signature(hash, eth_address, rosettanet_signature)
        }
    }
}
