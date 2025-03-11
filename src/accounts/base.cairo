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
        get_tx_info, ResourcesBounds,
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
    use crate::accounts::errors::AccountErrors::*;

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
            assert(sender.is_zero(), INVALID_CALLER);

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
                let mut calldata = call.calldata;
                let selector: u32 = (*calldata.pop_front().expect(CALLDATA_LEN_ZERO))
                    .try_into()
                    .expect(SELECTOR_HIGH);
                if (selector == MULTICALL_SELECTOR) {
                    assert(call.value == 0, MULTICALL_VALUE_NON_ZERO);
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
                    assert(current_hash != latest_hash, ALREADY_LATEST);

                    replace_class_syscall(latest_hash).expect(UPGRADE_FAILS);
                    return array![array![latest_hash.into()].span()];
                } else {
                    panic_with_felt252(UNIMPLEMENTED_FEATURE);
                }
            }

            // If value transfer, send STRK before calling contract
            if (call.value > 0) {
                // Re-check value
                let value_on_signature = self.get_transaction_value();
                assert(call.value == value_on_signature, VALUE_SIGNATURE_MISMATCH);
                self.process_native_transfer(value_on_signature, sn_target);
            }

            if (call.calldata.len() == 0) {
                return array![array![].span()];
            }

            let mut calldata = call.calldata;

            self.execute_call(sn_target, calldata)
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
        fn validate_transaction(self: @ContractState, call: RosettanetCall) -> felt252 {
            let self_eth_address: EthAddress = self.ethereum_address.read();
            assert(call.tx_type == 0 || call.tx_type == 2, NONSUPPORTED_TX_TYPE);
            let tx_info = get_tx_info().unbox();

            assert(tx_info.version == 3, INVALID_TX_VERSION); //@audit Verify is it correct?
            assert(
                tx_info.nonce == call.nonce.into(), INVALID_NONCE,
            ); // We cant handle nonce, so we can just check is it correct with signed data.

            if (call.tx_type == 0) {
                self.validate_resources(call.gas_limit, call.gas_price);
            } else {
                self.validate_resources(call.gas_limit, call.max_fee_per_gas);
            }

            if (call.to == self_eth_address) {
                let selector: u32 = (*call.calldata.at(0)).try_into().expect(SELECTOR_HIGH);

                assert(
                    ((selector == MULTICALL_SELECTOR) || (selector == UPGRADE_SELECTOR)),
                    WRONG_INTERNAL_SELECTOR,
                );
            }

            // Validate transaction signature
            let expected_hash = generate_tx_hash(call);

            let value_on_signature = self.get_transaction_value();
            assert(call.value == value_on_signature, VALUE_SIGNATURE_MISMATCH);

            let signature = tx_info.signature; // Signature includes v,r,s
            assert(
                self._is_valid_signature(expected_hash, signature, self_eth_address),
                INVALID_SIGNATURE,
            );
            starknet::VALIDATED
        }

        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.
        fn _is_valid_signature(
            self: @ContractState, hash: u256, signature: Span<felt252>, eth_address: EthAddress,
        ) -> bool {
            // first 5 element signature, last 2 elements are value
            assert(signature.len() == 7, INVALID_SIGNATURE_LENGTH);
            let r: u256 = u256 {
                low: (*signature.at(0)).try_into().expect(SIGNATURE_R_LOW_HIGH),
                high: (*signature.at(1)).try_into().expect(SIGNATURE_R_HIGH_HIGH),
            };
            let s: u256 = u256 {
                low: (*signature.at(2)).try_into().expect(SIGNATURE_S_LOW_HIGH),
                high: (*signature.at(3)).try_into().expect(SIGNATURE_S_HIGH_HIGH),
            };
            let v: u32 = (*signature.at(4)).try_into().expect(SIGNATURE_V_HIGH);

            let rosettanet_signature = RosettanetSignature { v: v, r: r, s: s };

            is_valid_eth_signature(hash, eth_address, rosettanet_signature)
        }

        // We also store transaction value inside signature, TX will be reverted if value mismatch
        // between signature and actual calldata
        fn get_transaction_value(self: @ContractState) -> u256 {
            let tx_info = get_tx_info().unbox();
            let signature = tx_info.signature;
            assert(signature.len() == 7, INVALID_SIGNATURE_LENGTH);
            u256 {
                low: (*signature.at(5)).try_into().expect(SIGNATURE_VALUE_HIGH),
                high: (*signature.at(6)).try_into().expect(SIGNATURE_VALUE_HIGH),
            }
        }

        // Sends native currency to the receiver address
        fn process_native_transfer(
            self: @ContractState, value: u256, receiver: ContractAddress,
        ) -> Span<felt252> {
            assert(value > 0, VALUE_TRANSFER_ZERO);
            assert(receiver != starknet::contract_address_const::<0>(), VALUE_RECEIVER_ZERO);

            let calldata: Span<felt252> = array![
                receiver.into(), value.low.into(), value.high.into(),
            ]
                .span();
            // tx has to be reverted if not enough balance
            call_contract_syscall(self.native_currency(), TRANSFER_ENTRYPOINT, calldata)
                .expect(VALUE_TRANSFER_FAILS)
        }

        fn execute_call(
            self: @ContractState, target: ContractAddress, mut calldata: Span<u128>,
        ) -> Array<Span<felt252>> {
            let registry = self.registry.read();
            let selector: u32 = (*calldata.pop_front().unwrap()).try_into().expect(SELECTOR_HIGH);
            let (entrypoint, directives) = IFunctionRegistryDispatcher {
                contract_address: registry,
            }
                .get_function_decoding(selector);
            assert(entrypoint != 0x0, TARGET_FUNCTION_NOT_REGISTERED);
            let mut evm_calldata = EVMCalldata {
                registry: registry,
                offset: 0,
                relative_offset: 0,
                calldata: BytesTrait::new(calldata.len() * 16, span_to_array(calldata)),
            };

            let decoded_calldata = evm_calldata.decode(directives);
            let result: Span<felt252> = call_contract_syscall(target, entrypoint, decoded_calldata)
                .unwrap();

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
                            (*call.to).try_into().expect(MULTICALL_TARGET_NO_CONTRACT_ADDRESS),
                            *call.entrypoint,
                            *call.calldata,
                        )
                            .expect(MULTICALL_CALL_FAILS);
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

        fn validate_resources(self: @ContractState, max_amount: u64, max_price_per_unit: u128) {
            let tx_info = get_tx_info().unbox();

            let resource_bounds: Span<ResourcesBounds> = tx_info.resource_bounds;
            for resource in resource_bounds {
                if (*resource.resource == 'L1_GAS') {
                    assert(*resource.max_amount == max_amount, MAX_AMOUNT_WRONG);
                    assert(
                        *resource.max_price_per_unit == max_price_per_unit, MAX_PRICE_UNIT_WRONG,
                    );
                }
            }
        }
    }
}
