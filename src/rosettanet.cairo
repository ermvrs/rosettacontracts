use starknet::{ContractAddress, EthAddress, ClassHash};
#[starknet::interface]
pub trait IRosettanet<TState> {
    // Write methods
    fn register_contract(ref self: TState, address: ContractAddress); // Registers existing starknet contract to registry
    fn deploy_account(ref self: TState, eth_address: EthAddress) -> ContractAddress; // Deploys starknet account and returns address
    fn set_account_class(ref self: TState, class: ClassHash); // Sets account class, this function will be removed after stable account
    fn upgrade(ref self: TState, class: ClassHash); // Upgrades contract
    // Read methods
    fn get_starknet_address(self: @TState, eth_address: EthAddress) -> ContractAddress;
    fn get_ethereum_address(self: @TState, sn_address: ContractAddress) -> EthAddress;
    fn precalculate_starknet_account(self: @TState, eth_address: EthAddress) -> ContractAddress;
    fn account_class(self: @TState) -> ClassHash;
    fn developer(self: @TState) -> ContractAddress;
}
#[starknet::contract]
pub mod Rosettanet {
    use core::num::traits::Zero;
    use starknet::storage::{Map};
    use core::poseidon::{poseidon_hash_span};
    use starknet::syscalls::{deploy_syscall, replace_class_syscall};
    use starknet::{ContractAddress, EthAddress, ClassHash, get_contract_address, get_caller_address};
    use openzeppelin::utils::deployments::{calculate_contract_address_from_deploy_syscall};

    #[storage]
    struct Storage {
        sn_to_eth: Map<ContractAddress, EthAddress>,
        eth_to_sn: Map<EthAddress, ContractAddress>,
        account_class: ClassHash,
        dev: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, developer: ContractAddress) {
        self.dev.write(developer);
    }

    #[abi(embed_v0)]
    impl Rosettanet of super::IRosettanet<ContractState> {
        fn register_contract(ref self: ContractState, address: ContractAddress) {
            let eth_address = self.generate_eth_address(address);
            self.update_registry(address, eth_address);
        }

        fn deploy_account(ref self: ContractState, eth_address: EthAddress) -> ContractAddress {
            let eth_address_felt: felt252 = eth_address.into();

            let (account, _) = deploy_syscall(
                self.account_class.read(), eth_address_felt, array![eth_address_felt, get_contract_address().into()].span(), true
            )
                .unwrap();

            self.update_registry(account, eth_address);
            
            account
        }

        fn set_account_class(ref self: ContractState, class: ClassHash) {
            assert(get_caller_address() == self.dev.read(), 'only dev');

            self.account_class.write(class);
        }

        fn upgrade(ref self: ContractState, class: ClassHash) {
            assert(get_caller_address() == self.dev.read(), 'only dev');

            replace_class_syscall(class).unwrap();
        }

        // View methods
        fn get_starknet_address(self: @ContractState, eth_address: EthAddress) -> ContractAddress {
            self.eth_to_sn.read(eth_address)
        }

        fn get_ethereum_address(self: @ContractState, sn_address: ContractAddress) -> EthAddress {
            self.sn_to_eth.read(sn_address)
        }

        fn precalculate_starknet_account(self: @ContractState, eth_address: EthAddress) -> ContractAddress {
            let eth_address_felt: felt252 = eth_address.into();
            calculate_contract_address_from_deploy_syscall(
                eth_address_felt,
                self.account_class.read(),
                array![eth_address_felt, get_contract_address().into()].span(),
                0.try_into().unwrap()
            )
        }

        fn account_class(self: @ContractState) -> ClassHash {
            self.account_class.read()
        }

        fn developer(self: @ContractState) -> ContractAddress {
            self.dev.read()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn update_registry(ref self: ContractState, sn_address: ContractAddress, eth_address: EthAddress) {
            assert(self.sn_to_eth.read(sn_address).is_zero(), 'Contract already registered');
            assert(self.eth_to_sn.read(eth_address).is_zero(), 'EthAddress already registered');

            self.sn_to_eth.write(sn_address, eth_address);
            self.eth_to_sn.write(eth_address, sn_address);
        }

        // Default function for registering existing starknet contract
        fn generate_eth_address(self: @ContractState, sn_address: ContractAddress) -> EthAddress {
            let sn_hash = poseidon_hash_span(array![sn_address.into()].span());

            let (_, eth_address) = DivRem::div_rem(Into::<felt252, u256>::into(sn_hash), 0x10000000000000000000000000000000000000000_u256.try_into().unwrap());

            eth_address.try_into().unwrap()
        }
    }
}