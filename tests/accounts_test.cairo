use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address, stop_cheat_caller_address};

use rosettacontracts::rosettanet::{
    IRosettanetDispatcher, IRosettanetDispatcherTrait
};
use rosettacontracts::accounts::utils::{RosettanetCall};
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
    // EIP2930 tx hash
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x105d7b8d7c9fe830c123f2d99c01e09bfa7d902cb3b5afee409cf3dca533f52b;
    let signature: Array<felt252> = array![0x3188ef10bf8469101d372e6b0960ed1b, 0x02bb74ffa5465b3dda0e353bbc3b6be3, 0x436c4cd167829819ce46024300e24d6d , 0x0739cb3999ae6842528ce5d8ec01a7fc , 0x1b, 0x0,0x0]; // r.low, r.high, s.low, s.high, v

    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_wrong_signature() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x105d7b8d7c9fe830c123f2d99c01e09bfa7d902cb3b5afee409cf3dca533f52b;
    let signature: Array<felt252> = array![0x3188ef10bf8469101d372e6b0960ed2b, 0x02bb74ffa5465b3dda0e353bbc3b6be3, 0x436c4cd167829819ce46024300e24d6d , 0x0739cb3999ae6842528ce5d8ec01a7fc , 0x1b,0x0,0x0]; // r.low, r.high, s.low, s.high, v

    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_signature_wrong_address() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e2.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x105d7b8d7c9fe830c123f2d99c01e09bfa7d902cb3b5afee409cf3dca533f52b;
    let signature: Array<felt252> = array![0x3188ef10bf8469101d372e6b0960ed1b, 0x02bb74ffa5465b3dda0e353bbc3b6be3, 0x436c4cd167829819ce46024300e24d6d , 0x0739cb3999ae6842528ce5d8ec01a7fc , 0x1b, 0x0, 0x0]; // r.low, r.high, s.low, s.high, v

    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
fn test_transaction_validation() {
    // Testing with empty access list eip1559 transaction
    // Access list support will be added further
    let tx = RosettanetCall {
        to: .try_into().unwrap(),
        nonce: ,
        max_priority_fee_per_gas: ,
        max_fee_per_gas: ,
        gas_limit: 21000,
        value: 0,
        calldata: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };
}