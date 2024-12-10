use starknet::{EthAddress, ContractAddress};
use rosettacontracts::accounts::utils::{RosettanetCall};


#[starknet::interface]
pub trait IRosettaAccount<TState> {
    fn __execute__(self: @TState, call: RosettanetCall) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, call: RosettanetCall) -> felt252;
    fn is_valid_signature(self: @TState, hash: u256, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252, eth_address: EthAddress,
        registry: ContractAddress
    ) -> felt252;
    fn get_ethereum_address(self: @TState) -> EthAddress;
    fn rosettanet(self: @TState) -> ContractAddress;
    // Camel case
    fn isValidSignature(self: @TState, hash: u256, signature: Array<felt252>) -> felt252;
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

    const STRK_ADDRESS: felt252 = 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d;
    const TRANSFER_ENTRYPOINT: felt252 = 0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e;

    #[storage]
    struct Storage {
        ethereum_address: EthAddress,
        registry: ContractAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState, eth_address: EthAddress, registry: ContractAddress) {
        self.ethereum_address.write(eth_address);
        self.registry.write(registry);
    }
    #[abi(embed_v0)]
    impl AccountImpl of super::IRosettaAccount<ContractState> {
        // Instead of Array<Call> we use Array<felt252> since we pass different values to the
        // parameter
        // It is EOA execution so multiple calls are not possible right now. We will add Multicalls in a different way in beta
        // calls params can include raw signed tx or can include the abi parsing bit locations for calldata
        fn __execute__(self: @ContractState, call: RosettanetCall) -> Array<Span<felt252>> {
            let sender = get_caller_address();
            assert(sender.is_zero(), Errors::INVALID_CALLER);

            let eth_target: EthAddress = call.to;
            let sn_target: ContractAddress = IRosettanetDispatcher { contract_address: self.registry.read() }.get_starknet_address(eth_target);
            assert(sn_target != starknet::contract_address_const::<0>(), 'target not registered');

            // If value transfer, send STRK before calling contract
            if(call.value > 0) {
                // Re-check value
                let value_on_signature = self.get_transaction_value();
                assert(call.value == value_on_signature, ' value sig-tx mismatch');
                self.process_native_transfer(value_on_signature, call.to); // sends strk
            }

            if(call.calldata.len() == 0) {
                // do nothing
                return array![array![].span()];
            }

            let entrypoint = validate_target_function(call.target_function, call.calldata);
            let mut calldata = call.calldata;
            let _ = calldata.pop_front(); // Remove first element, it is function selector

            let address_updated_calldata = self.update_addresses(calldata, call.directives); // This function security concerns me
            let result: Span<felt252> = call_contract_syscall(sn_target, entrypoint, address_updated_calldata).unwrap();
            // self.nonce.write(self.nonce.read() + 1); // Problem here ???
            array![result]
        }

        fn __validate__(self: @ContractState, call: RosettanetCall) -> felt252 {
            // TODO: check if validations enough
            // assert(calls.transaction.length > 9, 'Calldata wrong'); // TODO: First version only supports EIP1559
            // Check if to address registered on lens
            self.validate_transaction(call)
        }

        fn is_valid_signature(
            self: @ContractState, hash: u256, signature: Array<felt252>
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

        fn rosettanet(self: @ContractState) -> ContractAddress {
            self.registry.read()
        }

        fn isValidSignature(
            self: @ContractState, hash: u256, signature: Array<felt252>
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
            if(call.calldata.len() > 0) {
                let _ = validate_target_function(call.target_function, call.calldata);
            }

            // Validate transaction signature
            let expected_hash = generate_tx_hash(call);

            let value_on_signature = self.get_transaction_value();
            assert(call.value == value_on_signature, 'value sig-tx mismatch');

            let signature = tx_info.signature; // Signature includes v,r,s
            assert(self._is_valid_signature(expected_hash, signature), Errors::INVALID_SIGNATURE);
            starknet::VALIDATED
        }

        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.
        fn _is_valid_signature(
            self: @ContractState, hash: u256, signature: Span<felt252>
        ) -> bool {
            // first 5 element signature, last 2 elements are value
            assert(signature.len() == 7, 'Invalid Signature length');
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

        // We also store transaction value inside signature, TX will be reverted if value mismatch
        // between signature and actual calldata
        fn get_transaction_value(self: @ContractState) -> u256 {
            let tx_info = get_tx_info().unbox();
            let signature = tx_info.signature;
            assert(signature.len() == 7, 'signature len wrong');
            u256 {
                low: (*signature.at(5)).try_into().unwrap(),
                high: (*signature.at(6)).try_into().unwrap()
            }
        }

        // TODO: write tests
        fn update_addresses(self: @ContractState, calldata: Span<felt252>, directives: Span<u8>) -> Span<felt252> {
            assert(calldata.len() == directives.len(), 'R-AB-1 sanity fails');
            let mut updated_array = ArrayTrait::<felt252>::new();
            let mut index = 0;

            while index < calldata.len() {
                let current_directive: u8 = *directives.at(index);
                if(current_directive == 2_u8) {
                    let eth_address: EthAddress = (*calldata.at(index)).try_into().unwrap();
                    let sn_address = IRosettanetDispatcher{contract_address: self.registry.read()}.get_starknet_address(eth_address);
                    updated_array.append(sn_address.into());
                } else {
                    updated_array.append(*calldata.at(index));
                }
                index +=1;
            };

            updated_array.span()
        }

        // Sends native currency to the receiver address
        fn process_native_transfer(self: @ContractState, value: u256, receiver: EthAddress) -> Span<felt252> {
            assert(value > 0, 'value zero');
            let sn_address = IRosettanetDispatcher{contract_address: self.registry.read()}.get_starknet_address(receiver);
            assert(sn_address != starknet::contract_address_const::<0>(), 'receiver not registered');

            let calldata: Span<felt252> = array![sn_address.into(), value.low.into(), value.high.into()].span();
            // tx has to be reverted if not enough balance
            call_contract_syscall(STRK_ADDRESS.try_into().unwrap(), TRANSFER_ENTRYPOINT, calldata).unwrap()
        }
    }
}
