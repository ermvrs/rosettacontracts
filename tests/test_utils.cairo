use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address,
    stop_cheat_caller_address
};
use starknet::{ClassHash, ContractAddress, EthAddress};
use core::pedersen::PedersenTrait;
use core::hash::{HashStateExTrait, HashStateTrait};
use rosettacontracts::rosettanet::{IRosettanetDispatcher, IRosettanetDispatcherTrait};
use rosettacontracts::accounts::base::{IRosettaAccountDispatcher};
use rosettacontracts::mocks::erc20::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};
use rosettacontracts::mocks::weth::{IMockWETHDispatcher, IMockWETHDispatcherTrait};

fn compute_hash_on_elements(data: Span<felt252>) -> felt252 {
    let mut state = PedersenTrait::new(0);
    for elem in data {
        state = state.update_with(*elem);
    };

    state.update_with(data.len()).finalize()
}

pub fn declare_erc20() -> ClassHash {
    let class = declare("MockERC20").unwrap().contract_class();
    *class.class_hash
}

pub fn declare_account() -> ClassHash {
    let class = declare("RosettaAccount").unwrap().contract_class();
    *class.class_hash
}

pub fn deploy_and_set_account() -> IRosettanetDispatcher {
    let contract = declare("Rosettanet").unwrap().contract_class();
    let native_currency = deploy_erc20();
    let account_class = declare_account();
    let (contract_address, _) = contract
        .deploy(
            @array![
                account_class.into(), developer().into(), native_currency.contract_address.into()
            ]
        )
        .unwrap();
    let dispatcher = IRosettanetDispatcher { contract_address };

    start_cheat_caller_address(dispatcher.contract_address, developer());
    dispatcher.set_account_class(account_class);
    stop_cheat_caller_address(dispatcher.contract_address);

    dispatcher
}

pub fn developer() -> ContractAddress {
    starknet::contract_address_const::<1>()
}

pub fn eth_account() -> EthAddress {
    0x12345678.try_into().unwrap()
}

pub fn deploy_erc20() -> IMockERC20Dispatcher {
    let class = declare("MockERC20").unwrap().contract_class();
    let (contract_address, _) = class.deploy(@array![]).unwrap();
    IMockERC20Dispatcher { contract_address }
}

pub fn deploy_weth() -> IMockWETHDispatcher {
    let class = declare("MockWETH").unwrap().contract_class();
    let (contract_address, _) = class.deploy(@array![]).unwrap();
    IMockWETHDispatcher { contract_address }
}

pub fn deploy_rosettanet() -> IRosettanetDispatcher {
    let contract = declare("Rosettanet").unwrap().contract_class();
    let account_class = declare_account();
    let native_currency = deploy_erc20();
    let (contract_address, _) = contract
        .deploy(
            @array![
                account_class.into(), developer().into(), native_currency.contract_address.into()
            ]
        )
        .unwrap();
    let rosettanet = IRosettanetDispatcher { contract_address };

    rosettanet.register_function(array![0x7472616E7366657228616464726573732C75696E7432353629].span()); // transfer(address,uint256)
    rosettanet.register_function(array![0x63616C6C43616C63756C61746F722829].span()); // callCalculator()
    rosettanet.register_function(array![0x6465706F7369742829].span()); // deposit()
    rosettanet.register_function(array![0x617070726F766528616464726573732C75696E7432353629].span()); // approve(address,uint256)

    rosettanet
}

pub fn deploy_account_from_rosettanet(
    eth_address: EthAddress
) -> (IRosettanetDispatcher, IRosettaAccountDispatcher) {
    let account_class = declare_account();

    let rosettanet = deploy_rosettanet();

    start_cheat_caller_address(rosettanet.contract_address, developer());
    rosettanet.set_account_class(account_class);
    stop_cheat_caller_address(rosettanet.contract_address);

    let account = rosettanet.deploy_account(eth_address);

    (rosettanet, IRosettaAccountDispatcher { contract_address: account })
}

pub fn deploy_account_from_existing_rosettanet(
    eth_address: EthAddress, rosettanet_contract: ContractAddress
) -> IRosettaAccountDispatcher {
    let rosettanet = IRosettanetDispatcher { contract_address: rosettanet_contract };

    let account = rosettanet.deploy_account(eth_address);
    IRosettaAccountDispatcher { contract_address: account }
}

pub fn deploy_funded_account_from_rosettanet(
    eth_address: EthAddress
) -> (IRosettanetDispatcher, IRosettaAccountDispatcher, IMockERC20Dispatcher) {
    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    let native_currency_address = rosettanet.native_currency();

    let strk = IMockERC20Dispatcher { contract_address: native_currency_address };

    strk.mint(account.contract_address, 1000000);

    assert_eq!(strk.balance_of(account.contract_address), 1000000);

    (rosettanet, account, strk)
}

pub fn deploy_specificly_funded_account_from_rosettanet(
    eth_address: EthAddress, amount: u256
) -> (IRosettanetDispatcher, IRosettaAccountDispatcher, IMockERC20Dispatcher) {
    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    let native_currency_address = rosettanet.native_currency();

    let strk = IMockERC20Dispatcher { contract_address: native_currency_address };

    strk.mint(account.contract_address, amount);

    assert_eq!(strk.balance_of(account.contract_address), amount);

    (rosettanet, account, strk)
}

pub fn change_current_account_class(rosettanet_contract: ContractAddress, new_hash: ClassHash) {
    let dispatcher = IRosettanetDispatcher { contract_address: rosettanet_contract };
    start_cheat_caller_address(dispatcher.contract_address, developer());
    dispatcher.set_account_class(new_hash);
    stop_cheat_caller_address(dispatcher.contract_address);
}

// Forcely matches these addresses
pub fn manipulate_rosettanet_registry(
    rosettanet_contract: ContractAddress, sn_address: ContractAddress, eth_address: EthAddress
) {
    // Currently we use function in registry
    // After alpha version, we have to remove that function. So this function also needs to be
    // rewritten with store function in foundry
    start_cheat_caller_address(rosettanet_contract, developer());
    IRosettanetDispatcher { contract_address: rosettanet_contract }
        .register_matched_addresses(sn_address, eth_address);
    stop_cheat_caller_address(rosettanet_contract);
}

#[test]
fn test_storage_manipulation() {
    let rosettanet = deploy_rosettanet();

    let eth_address: EthAddress = 0x123.try_into().unwrap();
    let sn_address: ContractAddress = 0xFFF.try_into().unwrap();

    manipulate_rosettanet_registry(rosettanet.contract_address, sn_address, eth_address);

    assert_eq!(rosettanet.get_starknet_address(eth_address), sn_address);
    assert_eq!(rosettanet.get_ethereum_address(sn_address), eth_address);
}

// This test is exist to calculate how many steps spent on rosettanet deployment
// Actual usage wont include this amount because deployment done only once.
// Each test deploys rosettanet again.
#[test]
fn test_deploy_rosettanet() {
    let rosettanet = deploy_rosettanet();

    let transfer_entrypoint = rosettanet.get_starknet_entrypoint(0xa9059cbb);
    assert_eq!(transfer_entrypoint, 0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e);
}