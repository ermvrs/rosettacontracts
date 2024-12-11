use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address, stop_cheat_caller_address};

use rosettacontracts::rosettanet::{
    IRosettanetDispatcher, IRosettanetDispatcherTrait
};
use starknet::{ClassHash};

use rosettacontracts_integrationtest::test_utils::{developer, eth_account};

fn declare_accounts() -> ClassHash {
    let class = declare("RosettaAccount").unwrap().contract_class();
    *class.class_hash
}

fn deploy_rosettanet() -> IRosettanetDispatcher {
    let contract = declare("Rosettanet").unwrap().contract_class();
    let (contract_address, _) = contract.deploy(@array![developer().into()]).unwrap();
    IRosettanetDispatcher { contract_address }
}

fn deploy_and_set_account() -> IRosettanetDispatcher {
    let contract = declare("Rosettanet").unwrap().contract_class();
    let (contract_address, _) = contract.deploy(@array![developer().into()]).unwrap();
    let dispatcher = IRosettanetDispatcher { contract_address };
    let account_class = declare_accounts();

    start_cheat_caller_address(dispatcher.contract_address, developer());
    dispatcher.set_account_class(account_class);
    stop_cheat_caller_address(dispatcher.contract_address);

    dispatcher
}

#[test]
fn rosettanet_deploy_initial_dev() {
    let rosettanet = deploy_rosettanet();

    assert_eq!(rosettanet.developer(), starknet::contract_address_const::<1>());
}

#[test]
#[should_panic(expected: 'only dev')]
fn rosettanet_non_dev_set_class() {
    let rosettanet = deploy_rosettanet();

    rosettanet.set_account_class(1.try_into().unwrap());
}

#[test]
fn rosettanet_set_class() {
    let rosettanet = deploy_rosettanet();

    start_cheat_caller_address(rosettanet.contract_address, developer());
    rosettanet.set_account_class(1.try_into().unwrap());
    stop_cheat_caller_address(rosettanet.contract_address);

    assert_eq!(rosettanet.account_class(), 1.try_into().unwrap());
}

#[test]
fn rosettanet_check_precalculated_address() {
    let rosettanet = deploy_and_set_account();

    let precalculated_address = rosettanet.precalculate_starknet_account(eth_account());

    let deployed_account = rosettanet.deploy_account(eth_account());

    assert_eq!(precalculated_address, deployed_account);
}

#[test]
#[should_panic]
#[ignore] // Fail cannot be handled??
fn rosettanet_redeploy_same_account() {
    let rosettanet = deploy_and_set_account();

    let precalculated_address = rosettanet.precalculate_starknet_account(eth_account());

    let deployed_account = rosettanet.deploy_account(eth_account());

    assert_eq!(precalculated_address, deployed_account);
    rosettanet.deploy_account(eth_account());
}

#[test]
fn rosettanet_register_contract() {
    let rosettanet = deploy_rosettanet();

    rosettanet.register_contract(1.try_into().unwrap());

    let eth_address = rosettanet.get_ethereum_address(1.try_into().unwrap());

    assert_ne!(rosettanet.get_starknet_address(eth_address), 0.try_into().unwrap());
}

#[test]
#[should_panic(expected: 'Contract already registered')]
fn rosettanet_register_existing_contract() {
    let rosettanet = deploy_rosettanet();

    rosettanet.register_contract(1.try_into().unwrap());
    rosettanet.register_contract(1.try_into().unwrap());
}