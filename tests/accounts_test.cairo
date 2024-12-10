use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address, stop_cheat_caller_address, 
    start_cheat_signature_global, stop_cheat_signature_global, start_cheat_nonce_global, stop_cheat_nonce_global};

use rosettacontracts::rosettanet::{
    IRosettanetDispatcher, IRosettanetDispatcherTrait
};
use rosettacontracts::accounts::utils::{RosettanetCall, generate_tx_hash};
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
fn test_signature_validation_eip1559() {
    // EIP1559 tx hash
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0xfea45e666ba85f417463f9c7bd9c0ab532c3a9bf29bb09c73fed760364f6c405;
    let signature = array![0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,0x15bd08d62685c22d30a57d611a643c76, 0x290a42b030be68a236a837dff15a77c3, 0x57f669dd35be2b984cd4ab48c0a0c588,0x1c,0x1,0x0];

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
fn test_transaction_validation_value_transfer_only() {
    // Testing with empty access list eip1559 transaction
    // Access list support will be added further
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
        nonce: 59,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_limit: 21000,
        value: 1,
        calldata: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,0x15bd08d62685c22d30a57d611a643c76, 0x290a42b030be68a236a837dff15a77c3, 0x57f669dd35be2b984cd4ab48c0a0c588,0x1c,0x1,0x0];
    let unsigned_tx_hash: u256 = 0xfea45e666ba85f417463f9c7bd9c0ab532c3a9bf29bb09c73fed760364f6c405;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    let validation = account.__validate__(tx);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_transaction_validation_calldata() {
    // TODO: test with calldata, example transfer of usdc
}

#[test]
fn test_transaction_validation_calldata_and_value_transfer() {
    // TODO: call target after sending strk
    // No execution just validate
}