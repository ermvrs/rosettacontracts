#[starknet::interface]
pub trait IRosettaAccount<TContractState> {
    fn __validate__(ref self: TContractState, calls: Array<Call>) -> felt252;
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
    fn is_valid_signature(self: @TContractState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn is_rosetta_account(self: @TContractState) -> bool;
    fn supports_interface(self: @TContractState, interface_id: felt252) -> bool;
}

#[starknet::contract(account)]
mod RosettaAccount {
    const TX_V1: felt252 = 1;
    const TX_V1_ESTIMATE: felt252 = consteval_int!(0x100000000000000000000000000000000 + 1);
    const TX_V3: felt252 = 3;
    const TX_V3_ESTIMATE: felt252 = consteval_int!(0x100000000000000000000000000000000 + 3);

    use starknet::{EthAddress, get_execution_info, get_contract_address};

    #[storage]
    struct Storage {
        ethereum_address: EthAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl AccountImpl of super::IRosettaAccount<ContractState> {
        // Verifies signature is the valid signature for this accounts ethereum address equivalent
        // And also can verify calldata length
        // Calldata will be array of u128s, ethereum calldata slots splitted into low and highs.
        fn __validate__(ref self: ContractState, calldata: Array<felt252>) -> felt252 {
            // TODO: verify that calldata parameter is the param that passed to the RPC addInvokeTransaction method
            // Validate ethereum signature
            let execution_info = get_execution_info().unbox();
            assert(execution_info.caller_address.is_zero(), 'rosetta-caller-zero');

            let tx_info = execution_info.tx_info.unbox();
            assert(tx_info.nonce == 0, 'rosetta-invalid-nonce');

            let execution_hash = tx_info.transaction_hash;

            let signature = tx_info.signature; // Must be ethereum signature somehow
            // assert(signature.len() == 2, 'invalid-signature-len'); // check signature length

            let tx_version = tx_info.version;
            assert(tx_version == TX_V3_ESTIMATE || tx_version == TX_V1_ESTIMATE,'escrow/invalid-signature'); // TODO: add signature verification
            // TODO
            starknet::VALIDATED
        }

        fn __execute__(ref self: ContractState, calldata: Array<felt252>) -> Array<Span<felt252>> { // TODO: can we pass any array of felts into calls param?

        }

        fn is_valid_signature(self: @ContractState, hash: felt252, signature: Array<felt252>) -> felt252 {
            0
        }

        fn is_rosetta_account(self: @ContractState) -> felt252 {
            1
        }

        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            true
        }
    }
}