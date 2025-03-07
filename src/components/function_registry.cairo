use crate::utils::decoder::{EVMTypes};
use starknet::ContractAddress;

#[starknet::interface]
pub trait IFunctionRegistry<TState> {
    fn register_function(ref self: TState, fn_name: ByteArray, inputs: Span<EVMTypes>);
    fn get_function_decoding(self: @TState, eth_selector: u32) -> (felt252, Span<EVMTypes>);
    fn is_dev(self: @TState, dev: ContractAddress) -> bool;
}

#[starknet::component]
pub mod FunctionRegistryComponent {
    use starknet::{ContractAddress};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, Map, StoragePathEntry, Vec, VecTrait,
        MutableVecTrait
    };
    use crate::utils::decoder::{EVMTypes};
    use crate::components::utils::{calculate_function_selectors};


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
        directives: Map<u32, Vec<felt252>>
    }

    #[embeddable_as(FunctionRegistryImpl)]
    impl FunctionRegistry<
        TContractState, +HasComponent<TContractState>
    > of super::IFunctionRegistry<ComponentState<TContractState>> {
        fn register_function(
            ref self: ComponentState<TContractState>, fn_name: ByteArray, inputs: Span<EVMTypes>
        ) {
            // TODO: add access control
            let (sn_entrypoint, eth_selector) = calculate_function_selectors(@fn_name);
            self.entrypoints.write(eth_selector, sn_entrypoint);

            let mut inputs_serialized = array![];
            inputs.serialize(ref inputs_serialized);

            let vector_serialized_directives = self.directives.entry(eth_selector);
            for i in 0
                ..inputs_serialized
                    .len() {
                        vector_serialized_directives.append().write(*inputs_serialized.at(i));
                    };

            self.emit(FunctionRegistered { eth_selector, entrypoint: sn_entrypoint });
        }
        // Returns function entrypoint and decoding directives
        fn get_function_decoding(
            self: @ComponentState<TContractState>, eth_selector: u32
        ) -> (felt252, Span<EVMTypes>) {
            let entrypoint = self.entrypoints.read(eth_selector);

            let vector_serialized_directives = self.directives.entry(eth_selector);

            let mut serialized_directives = array![];

            for i in 0
                ..vector_serialized_directives
                    .len() {
                        serialized_directives.append(vector_serialized_directives.at(i).read());
                    };

            let mut serialized_directives = serialized_directives.span();

            let deserialized: Span<EVMTypes> = Serde::deserialize(ref serialized_directives)
                .unwrap();

            (entrypoint, deserialized)
        }

        fn is_dev(self: @ComponentState<TContractState>, dev: ContractAddress) -> bool {
            self.developers.read(dev)
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {
        fn initialize(ref self: ComponentState<TContractState>) {}
    }
}
