#[starknet::component]
pub mod function_registry_component {
    use starknet::storage::{Map};
    use crate::components::types::{EthereumFunction, DecodingDirective};

    #[storage]
    pub struct Storage {
        entrypoints: Map<u32, felt252> // Ethereum function selector -> 
        // TODO: felt252 to Ethereum function mapping
    }
}
