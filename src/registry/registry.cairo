#[starknet::interface]
pub trait IRosettanetFunctionRegistry<TState> {

}

// Maybe it can be component instead of contract itself
#[starknet::contract]
pub mod RosettanetFunctionRegistry {
    #[storage]
    struct Storage {
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,

    ) {

    }

    #[abi(embed_v0)]
    impl RosettanetFunctionRegistry of super:: IRosettanetFunctionRegistry<ContractState> {

    }
}