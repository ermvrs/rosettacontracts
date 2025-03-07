use starknet::ContractAddress;

#[starknet::interface]
pub trait IMockWETH<TState> {
    // IERC20
    fn total_supply(self: @TState) -> u256;
    fn balance_of(self: @TState, account: ContractAddress) -> u256;
    fn allowance(self: @TState, owner: ContractAddress, spender: ContractAddress) -> u256;
    fn transfer(self: @TState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        self: @TState, sender: ContractAddress, recipient: ContractAddress, amount: u256,
    ) -> bool;
    fn approve(self: @TState, spender: ContractAddress, amount: u256) -> bool;
    fn mint(ref self: TState, receiver: ContractAddress, amount: u256);

    // IERC20Metadata
    fn name(self: @TState) -> ByteArray;
    fn symbol(self: @TState) -> ByteArray;
    fn decimals(self: @TState) -> u8;

    // IERC20Camel
    fn totalSupply(self: @TState) -> u256;
    fn balanceOf(self: @TState, account: ContractAddress) -> u256;
    fn transferFrom(
        self: @TState, sender: ContractAddress, recipient: ContractAddress, amount: u256,
    ) -> bool;
    fn last_deposit(self: @TState) -> u256;
}

#[starknet::contract]
pub mod MockWETH {
    use openzeppelin_token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use starknet::{ContractAddress, get_tx_info};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    // ERC20 Mixin
    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        last_deposit: u256,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        let name = "Wrapped Ether";
        let symbol = "WETH";

        self.erc20.initializer(name, symbol);
    }

    #[external(v0)]
    fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) {
        self.erc20.mint(recipient, amount);
    }

    #[external(v0)]
    fn last_deposit(self: @ContractState) -> u256 {
        self.last_deposit.read()
    }

    #[external(v0)]
    fn deposit(ref self: ContractState) {
        let tx_info = get_tx_info().unbox();
        let signature = tx_info.signature;
        let deposit_amount = u256 {
            low: (*signature.at(5)).try_into().expect('sig val low fail'),
            high: (*signature.at(6)).try_into().expect('sig val high fail'),
        };

        self.last_deposit.write(deposit_amount);
    }
}
