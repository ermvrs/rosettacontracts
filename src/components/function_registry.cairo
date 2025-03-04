use crate::utils::decoder::{EVMTypes};
use starknet::ContractAddress;

#[starknet::interface]
pub trait IFunctionRegistry<TState> {
    fn register_function(ref self: TState, fn_name: Span<felt252>, inputs: Span<EVMTypes>);
    fn get_function_decoding(self: @TState, eth_selector: u32) -> (felt252, Span<EVMTypes>);
    fn is_dev(self: @TState, dev: ContractAddress) -> bool;
}

#[starknet::component]
pub mod FunctionRegistryComponent {
    use crate::utils::decoder::{EVMTypes};
    use starknet::ContractAddress;
    use starknet::storage::{Map};

    #[event]
    #[derive(Drop, Debug, PartialEq, starknet::Event)]
    pub enum Event {
        FunctionRegistered: FunctionRegistered
    }

    #[derive(Drop, Debug, PartialEq, starknet::Event)]
    pub struct FunctionRegistered {
        pub eth_selector: u32,
        pub entrypoint: felt252
    }

    #[storage]
    pub struct Storage {
        developers: Map<ContractAddress, bool>, // isDev?
        entrypoints: Map<u32, felt252>, // Ethereum function selector -> 
        //directives: Map<u32, Vec<EVMTypes>>
    }

    #[embeddable_as(FunctionRegistryImpl)]
    impl FunctionRegistry<TContractState, +HasComponent<TContractState>> of super::IFunctionRegistry<ComponentState<TContractState>> {
        fn register_function(ref self: ComponentState<TContractState>, fn_name: Span<felt252>, inputs: Span<EVMTypes>) {

            self.emit(FunctionRegistered { eth_selector: 0_u32, entrypoint: 0x0 });
        }
        // Returns function entrypoint and decoding directives
        fn get_function_decoding(self: @ComponentState<TContractState>, eth_selector: u32) -> (felt252, Span<EVMTypes>) {
            let entrypoint = self.entrypoints.read(eth_selector);
            //let mut serialized_directives: Span<felt252> = self.directives.read(eth_selector);
            //let directives: Span<EVMTypes> = Serde::deserialize(ref serialized_directives).unwrap();

            (entrypoint, array![].span())
        }

        fn is_dev(self: @ComponentState<TContractState>, dev: ContractAddress) -> bool {
            self.developers.read(dev)
        }

    }

    #[generate_trait]
    pub impl InternalImpl<TContractState, +HasComponent<TContractState>> of InternalTrait<TContractState> {
        fn initialize(ref self: ComponentState<TContractState>) {

        }
    }
}
