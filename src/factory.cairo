use starknet::{ContractAddress, ClassHash, EthAddress};

#[starknet::interface]
trait IFactory<TContractState> {
    fn lens(self: @TContractState) -> ContractAddress;
    fn current_account_class(self: @TContractState) -> ClassHash;
    fn precalculate_starknet_address(self: @TContractState, address: EthAddress) -> ContractAddress;
}

#[starknet::contract]
mod Factory {
    use core::option::OptionTrait;
    use starknet::{ContractAddress, ClassHash, EthAddress};
    use core::traits::{Into, TryInto};

    #[storage]
    struct Storage {
        account_class: ClassHash,
        lens: ContractAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState, lens: ContractAddress, account_class: ClassHash) {
        self.account_class.write(account_class);
        self.lens.write(lens);
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
            // todo
            0.try_into().unwrap()
        }
    }
}
