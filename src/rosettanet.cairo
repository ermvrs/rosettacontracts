use starknet::{ContractAddress, EthAddress, ClassHash};
#[starknet::interface]
pub trait IRosettanet<TState> {
    // Write methods
    fn register_contract(ref self: TState, address: ContractAddress); // Registers existing starknet contract to registry
    fn deploy_account(ref self: TState, eth_address: EthAddress) -> ContractAddress; // Deploys starknet account and returns address
    fn register_deployed_account(ref self: TState, eth_address: EthAddress); // Registers account deployed not from this contract
    fn set_account_class(ref self: TState, class: ClassHash); // Sets account class, this function will be removed after stable account
    fn register_matched_addresses(ref self: TState, sn_address: ContractAddress, eth_address: EthAddress); // Will be used during alpha
    fn upgrade(ref self: TState, class: ClassHash); // Upgrades contract
    fn change_dev(ref self: TState, dev: ContractAddress); // Changes dev
    // Read methods
    fn get_starknet_address(self: @TState, eth_address: EthAddress) -> ContractAddress;
    fn get_ethereum_address(self: @TState, sn_address: ContractAddress) -> EthAddress;
    fn precalculate_starknet_account(self: @TState, eth_address: EthAddress) -> ContractAddress;
    fn latest_class(self: @TState) -> ClassHash;
    fn native_currency(self: @TState) -> ContractAddress;
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
    use rosettacontracts::accounts::base::{IRosettaAccountDispatcher, IRosettaAccountDispatcherTrait};

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        AddressRegistered: AddressRegistered,
        AccountDeployed: AccountDeployed,
        AccountClassChanged: AccountClassChanged,
        Upgraded: Upgraded,
        PredeployedAccountRegistered: PredeployedAccountRegistered,
        DevAddressUpdated: DevAddressUpdated
    }

    #[derive(Drop, starknet::Event)]
    pub struct AddressRegistered {
        #[key]
        pub sn_address: ContractAddress,
        pub eth_address: EthAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AccountDeployed {
        #[key]
        pub account: ContractAddress,
        pub eth_address: EthAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PredeployedAccountRegistered {
        #[key]
        pub account: ContractAddress,
        pub eth_address: EthAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AccountClassChanged {
        pub changer: ContractAddress,
        pub new_class: ClassHash,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Upgraded {
        pub upgrader: ContractAddress,
        pub new_class: ClassHash,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DevAddressUpdated {
        pub old: ContractAddress,
        pub new: ContractAddress,
    }

    #[storage]
    struct Storage {
        sn_to_eth: Map<ContractAddress, EthAddress>,
        eth_to_sn: Map<EthAddress, ContractAddress>,
        latest_class: ClassHash,
        // Accounts will always deployed with initial class, so we can always precalculate the addresses. 
        // They may need to upgrade to the latest hash after deployment.
        initial_class: ClassHash, 
        dev: ContractAddress,
        strk: ContractAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState, account_class: ClassHash, developer: ContractAddress, strk: ContractAddress) {
        self.initial_class.write(account_class);
        self.latest_class.write(account_class);
        self.dev.write(developer);
        self.strk.write(strk);

        let strk_eth_address = self.generate_eth_address(strk);
        self.update_registry(strk, strk_eth_address);
    }

    #[abi(embed_v0)]
    impl Rosettanet of super::IRosettanet<ContractState> {
        /// Registers starknet contract address to the registry with generating ethereum equivalent
        /// # Arguments
        /// * `address` - Starknet Contract Address that going to be registered
        fn register_contract(ref self: ContractState, address: ContractAddress) {
            let eth_address = self.generate_eth_address(address);
            self.update_registry(address, eth_address);
            
            self.emit(AddressRegistered {sn_address: address, eth_address: eth_address});
        }

        /// Deploys Rosettanet account for Ethereum Address
        /// # Arguments
        /// * `eth_address` - Ethereum Address for newly deployed account
        fn deploy_account(ref self: ContractState, eth_address: EthAddress) -> ContractAddress {
            let eth_address_felt: felt252 = eth_address.into();

            let (account, _) = deploy_syscall(
                self.initial_class.read(), eth_address_felt, array![eth_address_felt, get_contract_address().into()].span(), true
            )
                .unwrap();

            self.update_registry(account, eth_address);

            self.emit(AccountDeployed{ account: account, eth_address: eth_address });
            
            account
        }

        /// Registers pre deployed rosetta account to the registry
        /// # Arguments
        /// * `eth_address` - Ethereum Address for already deployed account
        fn register_deployed_account(ref self: ContractState, eth_address: EthAddress) {
            let precalculated_address: ContractAddress = self.precalculate_starknet_account(eth_address);
            assert(IRosettaAccountDispatcher { contract_address: precalculated_address }.rosettanet() == get_contract_address(), 'wrong deployment');
            // TODO: Add tests for this function
            self.update_registry(precalculated_address, eth_address);

            self.emit(PredeployedAccountRegistered {account: precalculated_address, eth_address });
        }

        /// Updates account class
        /// # Arguments
        /// * `class` - New Rosettanet account class hash
        fn set_account_class(ref self: ContractState, class: ClassHash) {
            assert(get_caller_address() == self.dev.read(), 'only dev');

            self.latest_class.write(class);

            self.emit(AccountClassChanged {changer: get_caller_address(), new_class: class});
        }

        /// Updates registry without generating eth address
        /// # Arguments
        /// * `sn_address` - Starknet address
        /// * `eth_address` - Ethereum address
        fn register_matched_addresses(ref self: ContractState, sn_address: ContractAddress, eth_address: EthAddress) {
            assert(get_caller_address() == self.dev.read(), 'only dev');

            self.update_registry(sn_address, eth_address);

            self.emit(AddressRegistered {sn_address: sn_address, eth_address: eth_address});
        }

        /// Updates this contracts class
        /// # Arguments
        /// * `class` - New class hash
        fn upgrade(ref self: ContractState, class: ClassHash) {
            assert(get_caller_address() == self.dev.read(), 'only dev');

            replace_class_syscall(class).unwrap();

            self.emit(Upgraded {upgrader: get_caller_address(), new_class: class});
        }

        /// Updates dev address
        /// # Arguments
        /// * `dev` - New dev address
        fn change_dev(ref self: ContractState, dev: ContractAddress) {
            assert(get_caller_address() == self.dev.read(), 'only dev');

            self.dev.write(dev);

            self.emit(DevAddressUpdated { old: get_caller_address(), new: dev });
        }

        /// Returns registered starknet contract address for specified ethereum address
        /// returns zero if not registered
        /// # Arguments
        /// * `eth_address` - Ethereum address
        fn get_starknet_address(self: @ContractState, eth_address: EthAddress) -> ContractAddress {
            self.eth_to_sn.read(eth_address)
        }

        /// Returns registered starknet contract address for specified ethereum address
        /// returns zero if not registered
        /// # Arguments
        /// * `sn_address` - Starknet contract address
        fn get_ethereum_address(self: @ContractState, sn_address: ContractAddress) -> EthAddress {
            self.sn_to_eth.read(sn_address)
        }

        /// Returns precalculated starknet address for accounts
        /// # Arguments
        /// * `eth_address` - Ethereum address that going to be used to precalculate starknet contract address
        fn precalculate_starknet_account(self: @ContractState, eth_address: EthAddress) -> ContractAddress {
            let eth_address_felt: felt252 = eth_address.into();
            calculate_contract_address_from_deploy_syscall(
                eth_address_felt,
                self.initial_class.read(),
                array![eth_address_felt, get_contract_address().into()].span(),
                0.try_into().unwrap()
            )
        }

        /// Returns latest account class hash
        fn latest_class(self: @ContractState) -> ClassHash {
            self.latest_class.read()
        }

        /// Returns native currency address on current network
        fn native_currency(self: @ContractState) -> ContractAddress {
            self.strk.read()
        }

        /// Returns developer address
        fn developer(self: @ContractState) -> ContractAddress {
            self.dev.read()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Registers sn_address and eth_address to the registry. Reverts if any of them already registered
        /// # Arguments
        /// * `sn_address` - Starknet contract address that going to be registered with eth_address
        /// * `eth_address` - Ethereum address that going to be registered with sn_address
        fn update_registry(ref self: ContractState, sn_address: ContractAddress, eth_address: EthAddress) {
            assert(self.sn_to_eth.read(sn_address).is_zero(), 'Contract already registered');
            assert(self.eth_to_sn.read(eth_address).is_zero(), 'EthAddress already registered');

            self.sn_to_eth.write(sn_address, eth_address);
            self.eth_to_sn.write(eth_address, sn_address);
        }

        /// Generates Ethereum address from starknet contract address
        /// # Arguments
        /// * `sn_address` - Starknet contract address that will be used to generate eth address
        fn generate_eth_address(self: @ContractState, sn_address: ContractAddress) -> EthAddress {
            let sn_hash = poseidon_hash_span(array![sn_address.into()].span());

            let (_, eth_address) = DivRem::div_rem(Into::<felt252, u256>::into(sn_hash), 0x10000000000000000000000000000000000000000_u256.try_into().unwrap());

            eth_address.try_into().unwrap()
        }
    }
}