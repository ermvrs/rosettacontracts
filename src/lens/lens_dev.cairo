use starknet::{ContractAddress, EthAddress};

#[starknet::interface]
trait ILensDev<TState> {
    fn register_address(ref self: TState, address: ContractAddress);
    fn register_address_dev(ref self: TState, address: ContractAddress, eth: EthAddress);
    fn get_eth_address_from_sn_address(self: @TState, sn_address: ContractAddress) -> EthAddress;
    fn get_sn_address_from_eth_address(self: @TState, eth_address: EthAddress) -> ContractAddress;
}


#[starknet::contract]
mod LensDev {
    use super::ILensDev;
    use starknet::{ContractAddress, EthAddress};
    use core::poseidon::PoseidonTrait;
    use core::hash::{HashStateTrait, HashStateExTrait};
    use core::traits::{Into, TryInto};
    use core::num::traits::{Zero};


    #[storage]
    struct Storage {
        eth_address_to_sn_address: LegacyMap::<EthAddress, ContractAddress>,
        sn_address_to_eth_address: LegacyMap::<ContractAddress, EthAddress>,
    }

    #[constructor]
    fn constructor(ref self: ContractState,) {}

    fn convert_to_eth_address(sn_address: ContractAddress) -> EthAddress {
        // Remove 252 bits to 160 bits

        // TODO: check is it higher than 160 bits.
        // TODO: then remove 160 bits.
        let sn_address_f252: felt252 = sn_address.into();

        let sn_address_u256: u256 = sn_address_f252.into();

        let (_, address) = DivRem::div_rem(
            sn_address_u256, 0x10000000000000000000000000000000000000000_u256.try_into().unwrap()
        );

        address.try_into().unwrap()
    }

    fn regenerate_address(eth_address: EthAddress) -> EthAddress {
        let hash = PoseidonTrait::new().update(eth_address.try_into().unwrap()).finalize();
        convert_to_eth_address(hash.try_into().unwrap())
    }

    #[abi(embed_v0)]
    impl Lens of ILensDev<ContractState> {
        fn register_address(ref self: ContractState, address: ContractAddress) {
            assert(self.sn_address_to_eth_address.read(address).is_zero(), 'already registered');

            let mut regenerated_address: EthAddress = convert_to_eth_address(address);

            let mut existance = self.eth_address_to_sn_address.read(regenerated_address).is_zero();
            if (existance) {
                // Register address and return
                self.eth_address_to_sn_address.write(regenerated_address, address);
                self.sn_address_to_eth_address.write(address, regenerated_address);
                return;
            }

            loop {
                regenerated_address = regenerate_address(regenerated_address);

                existance = self.eth_address_to_sn_address.read(regenerated_address).is_zero();

                if (existance) {
                    self.eth_address_to_sn_address.write(regenerated_address, address);
                    self.sn_address_to_eth_address.write(address, regenerated_address);
                    break;
                }
            }
        }

        // Function just for development tests. We can match any address with any eth address we
        // want.
        // Helps developing.
        fn register_address_dev(
            ref self: ContractState, address: ContractAddress, eth: EthAddress
        ) {
            assert(self.sn_address_to_eth_address.read(address).is_zero(), 'already registered');

            self.eth_address_to_sn_address.write(eth, address);
            self.sn_address_to_eth_address.write(address, eth);
        }

        fn get_eth_address_from_sn_address(
            self: @ContractState, sn_address: ContractAddress
        ) -> EthAddress {
            self.sn_address_to_eth_address.read(sn_address)
        }

        fn get_sn_address_from_eth_address(
            self: @ContractState, eth_address: EthAddress
        ) -> ContractAddress {
            self.eth_address_to_sn_address.read(eth_address)
        }
    }
}
