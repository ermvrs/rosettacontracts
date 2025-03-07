use starknet::{EthAddress, ContractAddress};
use rosettacontracts::accounts::types::{RosettanetCall};


#[starknet::interface]
pub trait IRosettaAccount<TState> {
    fn __execute__(self: @TState, call: RosettanetCall) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, call: RosettanetCall) -> felt252;
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
    fn get_ethereum_address(self: @TState) -> EthAddress;
    fn rosettanet(self: @TState) -> ContractAddress;
    fn native_currency(self: @TState) -> ContractAddress;
    // Camel case
    fn isValidSignature(self: @TState, hash: u256, signature: Array<felt252>) -> felt252;
    fn getEthereumAddress(self: @TState) -> EthAddress;
    fn nativeCurrency(self: @TState) -> ContractAddress;
}

#[starknet::contract(account)]
pub mod RosettaAccount {
    use core::num::traits::Zero;
    use core::panic_with_felt252;
    use starknet::{
        ContractAddress, EthAddress, ClassHash, get_contract_address, get_caller_address,
        get_tx_info,
    };
    use starknet::syscalls::{
        call_contract_syscall, replace_class_syscall, get_class_hash_at_syscall,
    };
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use rosettacontracts::accounts::types::{
        RosettanetSignature, RosettanetCall, RosettanetMulticall,
    };
    use rosettacontracts::utils::decoder::{EVMCalldata, EVMTypesImpl};
    use crate::utils::bytes::{BytesTrait};
    use rosettacontracts::accounts::utils::{
        generate_tx_hash, is_valid_eth_signature, span_to_array,
    };
    use rosettacontracts::accounts::multicall::{prepare_multicall_context};
    use rosettacontracts::components::function_registry::{
        IFunctionRegistryDispatcherTrait, IFunctionRegistryDispatcher,
    };
    use crate::rosettanet::{IRosettanetDispatcher, IRosettanetDispatcherTrait};
    use openzeppelin_utils::deployments::{calculate_contract_address_from_deploy_syscall};

    pub mod Errors {
        pub const INVALID_CALLER: felt252 = 'Rosetta: invalid caller';
        pub const INVALID_SIGNATURE: felt252 = 'Rosetta: invalid signature';
        pub const INVALID_TX_VERSION: felt252 = 'Rosetta: invalid tx version';
        pub const UNAUTHORIZED: felt252 = 'Rosetta: unauthorized';
        pub const UNIMPLEMENTED_FEATURE: felt252 = 'Rosetta: unimplemented feature';
    }

    pub const TRANSFER_ENTRYPOINT: felt252 =
        0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e;
    pub const MULTICALL_SELECTOR: u32 =
        0x76971d7f; // function multicall((uint256,uint256,uint256[])[])
    pub const UPGRADE_SELECTOR: u32 = 0x74d0bb9d; // function upgradeRosettanetAccount(uint256)

    #[storage]
    struct Storage {
        ethereum_address: EthAddress,
        registry: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, eth_address: EthAddress, registry: ContractAddress) {
        self.ethereum_address.write(eth_address);
        self.registry.write(registry);
    }
    #[abi(embed_v0)]
    impl AccountImpl of super::IRosettaAccount<ContractState> {
        fn __execute__(self: @ContractState, call: RosettanetCall) -> Array<Span<felt252>> {
            let sender = get_caller_address();
            assert(sender.is_zero(), Errors::INVALID_CALLER);

            // Only try to register if its first tx
            if (call.nonce == 0 || call.nonce == 1) {
                self.register_account(); // Register this contract if not registered on registry
            }

            let eth_target: EthAddress = call.to;
            let sn_target: ContractAddress = IRosettanetDispatcher {
                contract_address: self.registry.read(),
            }
                .get_starknet_address_with_fallback(eth_target);

            // Multicall or upgrade call
            if (call.to == self.ethereum_address.read()) {
                // This is multicall
                let mut calldata = call.calldata;
                let selector: u32 = (*calldata.pop_front().unwrap()).try_into().unwrap();
                //let selector: u32 = (*call.calldata.at(0)).try_into().unwrap();
                if (selector == MULTICALL_SELECTOR) {
                    assert(call.value == 0, 'multicall value not zero');
                    let context = prepare_multicall_context(
                        self.registry.read(), calldata,
                    ); // First calldata element removed inside this function
                    return self.execute_multicall(context);
                } else if (selector == UPGRADE_SELECTOR) {
                    let latest_hash: ClassHash = IRosettanetDispatcher {
                        contract_address: self.registry.read(),
                    }
                        .latest_class();
                    let current_hash: ClassHash = get_class_hash_at_syscall(get_contract_address())
                        .unwrap();
                    assert(current_hash != latest_hash, 'no new upgrades');

                    replace_class_syscall(latest_hash).unwrap();
                    return array![array![latest_hash.into()].span()];
                } else {
                    panic_with_felt252(Errors::UNIMPLEMENTED_FEATURE);
                }
            }

            // If value transfer, send STRK before calling contract
            if (call.value > 0) {
                // Re-check value
                let value_on_signature = self.get_transaction_value();
                assert(call.value == value_on_signature, 'value sig-tx mismatch');
                self.process_native_transfer(value_on_signature, sn_target); // sends strk
            }

            if (call.calldata.len() == 0) {
                // do nothing
                return array![array![].span()];
            }

            let mut calldata = call.calldata;

            self.execute_call(sn_target, calldata)
            // self.nonce.write(self.nonce.read() + 1); // Problem here ???
        }

        fn __validate__(self: @ContractState, call: RosettanetCall) -> felt252 {
            self.validate_transaction(call)
        }

        fn is_valid_signature(
            self: @ContractState, hash: u256, signature: Array<felt252>,
        ) -> felt252 {
            let self_eth_address: EthAddress = self.ethereum_address.read();
            if self._is_valid_signature(hash, signature.span(), self_eth_address) {
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
            registry: ContractAddress,
        ) -> felt252 {
            assert(contract_address_salt == eth_address.into(), 'Salt and param mismatch');
            assert(registry != starknet::contract_address_const::<0>(), 'registry zero');
            let address = calculate_contract_address_from_deploy_syscall(
                eth_address.into(),
                class_hash.try_into().unwrap(),
                array![eth_address.into(), registry.into()].span(),
                0.try_into().unwrap(),
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

        fn native_currency(self: @ContractState) -> ContractAddress {
            IRosettanetDispatcher { contract_address: self.registry.read() }.native_currency()
        }

        fn isValidSignature(
            self: @ContractState, hash: u256, signature: Array<felt252>,
        ) -> felt252 {
            self.is_valid_signature(hash, signature)
        }

        fn getEthereumAddress(self: @ContractState) -> EthAddress {
            self.get_ethereum_address()
        }

        fn nativeCurrency(self: @ContractState) -> ContractAddress {
            self.native_currency()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        // Optimized validation
        fn validate_transaction(self: @ContractState, call: RosettanetCall) -> felt252 {
            let self_eth_address: EthAddress = self.ethereum_address.read();
            assert(call.tx_type == 0 || call.tx_type == 2, 'Tx type not supported');
            let tx_info = get_tx_info().unbox();
            // TODO: Tx version check

            if (call.to == self_eth_address) {
                let selector: u32 = (*call.calldata.at(0)).try_into().unwrap();

                assert(
                    ((selector == MULTICALL_SELECTOR) || (selector == UPGRADE_SELECTOR)),
                    'selector is not internal',
                );
            }

            // Validate transaction signature
            let expected_hash = generate_tx_hash(call);

            let value_on_signature = self.get_transaction_value();
            assert(call.value == value_on_signature, 'value sig-tx mismatch');

            let signature = tx_info.signature; // Signature includes v,r,s
            assert(
                self._is_valid_signature(expected_hash, signature, self_eth_address),
                Errors::INVALID_SIGNATURE,
            );
            starknet::VALIDATED
        }

        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.
        fn _is_valid_signature(
            self: @ContractState, hash: u256, signature: Span<felt252>, eth_address: EthAddress,
        ) -> bool {
            // first 5 element signature, last 2 elements are value
            assert(signature.len() == 7, 'Invalid Signature length');
            let r: u256 = u256 {
                low: (*signature.at(0)).try_into().unwrap(),
                high: (*signature.at(1)).try_into().unwrap(),
            };
            let s: u256 = u256 {
                low: (*signature.at(2)).try_into().unwrap(),
                high: (*signature.at(3)).try_into().unwrap(),
            };
            let v: u32 = (*signature.at(4)).try_into().unwrap();

            let rosettanet_signature = RosettanetSignature { v: v, r: r, s: s };

            is_valid_eth_signature(hash, eth_address, rosettanet_signature)
        }

        // We also store transaction value inside signature, TX will be reverted if value mismatch
        // between signature and actual calldata
        fn get_transaction_value(self: @ContractState) -> u256 {
            let tx_info = get_tx_info().unbox();
            let signature = tx_info.signature;
            assert(signature.len() == 7, 'signature len wrong');
            u256 {
                low: (*signature.at(5)).try_into().expect('sig val low fail'),
                high: (*signature.at(6)).try_into().expect('sig val high fail'),
            }
        }

        // Sends native currency to the receiver address
        fn process_native_transfer(
            self: @ContractState, value: u256, receiver: ContractAddress,
        ) -> Span<felt252> {
            assert(value > 0, 'value zero');
            assert(receiver != starknet::contract_address_const::<0>(), 'receiver zero');

            let calldata: Span<felt252> = array![
                receiver.into(), value.low.into(), value.high.into(),
            ]
                .span();
            // tx has to be reverted if not enough balance
            call_contract_syscall(self.native_currency(), TRANSFER_ENTRYPOINT, calldata)
                .expect('native transfer fails')
        }

        fn execute_call(
            self: @ContractState, target: ContractAddress, mut calldata: Span<u128>,
        ) -> Array<Span<felt252>> {
            let registry = self.registry.read();
            let selector: u32 = (*calldata.pop_front().unwrap()).try_into().unwrap();
            let (entrypoint, directives) = IFunctionRegistryDispatcher {
                contract_address: registry,
            }
                .get_function_decoding(selector);
            assert(entrypoint != 0x0, 'entrypoint not registered');
            let mut evm_calldata = EVMCalldata {
                registry: registry,
                offset: 0,
                relative_offset: 0,
                calldata: BytesTrait::new(
                    calldata.len() * 16, span_to_array(calldata),
                ) // DOES IT CONSUMES TOO MUCH GAS??
            };

            let decoded_calldata = evm_calldata.decode(directives);
            let result: Span<felt252> = call_contract_syscall(target, entrypoint, decoded_calldata)
                .unwrap();
            // self.nonce.write(self.nonce.read() + 1); // Problem here ???
            array![result]
        }

        fn execute_multicall(
            self: @ContractState, calls: Span<RosettanetMulticall>,
        ) -> Array<Span<felt252>> {
            let mut calls = calls;

            let mut results = ArrayTrait::<Span<felt252>>::new();
            loop {
                match calls.pop_front() {
                    Option::None => { break; },
                    Option::Some(call) => {
                        let result: Span<felt252> = call_contract_syscall(
                            (*call.to).try_into().expect('into target mc'),
                            *call.entrypoint,
                            *call.calldata,
                        )
                            .expect('multicall fails');
                        results.append(result);
                    },
                };
            };

            results
        }

        fn register_account(self: @ContractState) {
            let rosettanet = IRosettanetDispatcher { contract_address: self.registry.read() };
            let eth_address: EthAddress = self.ethereum_address.read();
            if (rosettanet
                .get_starknet_address(eth_address) == starknet::contract_address_const::<0>()) {
                rosettanet.register_deployed_account(eth_address);
            }
        }
    }
}
