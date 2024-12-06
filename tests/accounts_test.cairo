use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address, stop_cheat_caller_address};

use rosettacontracts::rosettanet::{
    IRosettanetDispatcher, IRosettanetDispatcherTrait
};

use rosettacontracts::accounts::base::{IRosettaAccountDispatcher, IRosettaAccountDispatcherTrait};
use starknet::{ContractAddress, ClassHash, EthAddress};
use rosettacontracts::test_data::{developer, eth_account};

fn declare_account() -> ClassHash {
    let class = declare("RosettaAccount").unwrap().contract_class();
    *class.class_hash
}
// TODO: test deploying from its own

fn deploy_rosettanet() -> IRosettanetDispatcher {
    let contract = declare("Rosettanet").unwrap().contract_class();
    let (contract_address, _) = contract.deploy(@array![developer().into()]).unwrap();
    IRosettanetDispatcher { contract_address }
}

fn deploy_account_from_rosettanet(eth_address: EthAddress) -> (IRosettanetDispatcher, IRosettaAccountDispatcher) {
    let account_class = declare_account();

    let rosettanet = deploy_rosettanet();

    start_cheat_caller_address(rosettanet.contract_address, developer());
    rosettanet.set_account_class(account_class);
    stop_cheat_caller_address(rosettanet.contract_address);

    let account = rosettanet.deploy_account(eth_address);

    (rosettanet, IRosettaAccountDispatcher { contract_address: account })
}

#[test]
fn check_initial_variables() {
    let (rosettanet, account) = deploy_account_from_rosettanet(eth_account());

    assert_eq!(account.rosettanet(), rosettanet.contract_address);
    assert_eq!(account.get_ethereum_address(), eth_account());
}

#[test]
fn test_signature_validation() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx_hash: u256 = 0x2b02ce3f05e22e1045d2d6872e22487820c9b408dcfb9b4cf4c0b1fdf4effe60;
    let signature: Array<felt252> = array![0x64534a24ba972dec423b5562e5529844, 0x94a76749edb78eff04f44205e8268fc2 ,0x4a801ea1ad2eb9d7ba8210bbbd8dd196, 0x6241083946fd385474d1b48ea02e2144, 0x1b]; // r.low, r.high, s.low, s.high, v

    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(tx_hash, signature), 1);
}