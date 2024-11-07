use starknet::{ContractAddress, ClassHash, EthAddress};

#[starknet::interface]
pub trait IFactory<TContractState> {
    fn lens(self: @TContractState) -> ContractAddress;
    fn current_account_class(self: @TContractState) -> ClassHash;
    fn precalculate_starknet_address(self: @TContractState, address: EthAddress) -> ContractAddress;
    fn deploy_account(self: @TContractState, address: EthAddress) -> ContractAddress;
    fn upgrade_contract(self: @TContractState, new_class: ClassHash);
    fn change_account_class(ref self: TContractState, new_class: ClassHash);
}

#[starknet::contract]
pub mod Factory {
    use core::option::OptionTrait;
    use starknet::{ContractAddress, ClassHash, EthAddress, get_caller_address};
    use starknet::syscalls::{deploy_syscall, replace_class_syscall};
    use core::traits::{Into, TryInto};
    use openzeppelin::utils::deployments::{calculate_contract_address_from_deploy_syscall};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        account_class: ClassHash,
        lens: ContractAddress,
        dev: ContractAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState, dev: ContractAddress) {
        // todo write initial values to storage
        self.dev.write(dev);
    }

    #[abi(embed_v0)]
    impl Factory of super::IFactory<ContractState> {
        /// Returns lens contract address
        fn lens(self: @ContractState) -> ContractAddress {
            self.lens.read()
        }

        /// Returns latest account class hash
        fn current_account_class(self: @ContractState) -> ClassHash {
            self.account_class.read()
        }

        /// Precalculate starknet address derived from ethereum address. This will be users accounts
        /// starknet address if deployed.
        /// # Params
        /// `address` - Ethereum Address that will be used to precalculate starknet account address.
        /// # Returns
        /// `ContractAddress` - Precalculated starknet address
        fn precalculate_starknet_address(
            self: @ContractState, address: EthAddress
        ) -> ContractAddress {
            // TODO: Tests

            let eth_address_felt: felt252 = address.into();
            calculate_contract_address_from_deploy_syscall(
                eth_address_felt,
                self.account_class.read(),
                array![eth_address_felt].span(),
                0.try_into().unwrap()
            )
        }

            // TODO: this funcation can be removed
        /// Deploys new rosettanet account. Fails if account already deployed
        /// # Params
        /// `address` - Ethereum Address that will be used to deploy starknet account.
        /// # Returns
        /// `ContractAddress` - Newly deployed starknet account
        fn deploy_account(self: @ContractState, address: EthAddress) -> ContractAddress {
            // TODO: Tests
            let eth_address_felt: felt252 = address.into();

            let (account, _) = deploy_syscall(
                self.account_class.read(), eth_address_felt, array![eth_address_felt].span(), true
            )
                .unwrap();

            // Todo: register lens if needed ?? Or we can use precalculate
            account
        }

        // REMOVE THIS FUNCTION AFTER DEVELOPMENT
        fn upgrade_contract(self: @ContractState, new_class: ClassHash) {
            assert(get_caller_address() == self.dev.read(), 'only dev');

            replace_class_syscall(new_class).unwrap();
        }

        // REMOVE THIS FUNCTION AFTER DEVELOPMENT
        fn change_account_class(ref self: ContractState, new_class: ClassHash) {
            assert(get_caller_address() == self.dev.read(), 'only dev');

            self.account_class.write(new_class);
        }
    }
}
