use starknet::{EthAddress};
use snforge_std::{
    start_cheat_signature_global, stop_cheat_signature_global, start_cheat_nonce_global,
    stop_cheat_nonce_global, start_cheat_caller_address, stop_cheat_caller_address
};

use rosettacontracts::accounts::base::{IRosettaAccountDispatcherTrait};
use rosettacontracts::accounts::utils::{generate_tx_hash};
//use rosettacontracts::rosettanet::{IRosettanetDispatcherTrait};
use rosettacontracts::accounts::types::{RosettanetCall};

use rosettacontracts_integrationtest::test_utils::{
    deploy_account_from_rosettanet
};

#[test]
fn test_signature_validation_eip1559() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0xfea45e666ba85f417463f9c7bd9c0ab532c3a9bf29bb09c73fed760364f6c405;
    let signature = array![
        0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,
        0x15bd08d62685c22d30a57d611a643c76,
        0x290a42b030be68a236a837dff15a77c3,
        0x57f669dd35be2b984cd4ab48c0a0c588,
        0x1c,
        0x1,
        0x0
    ];

    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
fn test_signature_validation_legacy() {
    // Legacy tx hash
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x04af5100efeb883338fbc81c2c167f0907889760af4002d45b378ee093a882ac;
    let signature = array![
        0x34e45bcf8ecf1ca3bd52ea7a93ef7d31,
        0x74d09bfb0301645262106184fee00493,
        0xd43382bdf45a8c272bcf101e9fcfa716,
        0x55296d9471410304362b0e4fd0ab7e06,
        0x1b,
        0x0,
        0x0
    ];
    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_signature_validation_legacy_invalid() {
    // Legacy tx hash
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x04af5100efeb883338fbc81c2c167f0907889760af4002d45b378ee093a882ac;
    let signature = array![
        0x34e44bcf8ecf1ca3bd52ea7a93ef7d31,
        0x74d09bfb0301645262106184fee00493,
        0xd43382bdf45a8c272bcf101e9fcfa716,
        0x55296d9471410304362b0e4fd0ab7e06,
        0x1b,
        0x0,
        0x0
    ];
    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_signature_validation_eip1559_invalid() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x105d7b8d7c9fe830c123f2d99c01e09bfa7d902cb3b5afee409cf3dca533f52b;
    let signature: Array<felt252> = array![
        0x3188ef10bf8469101d372e6b0960ed2b,
        0x02bb74ffa5465b3dda0e353bbc3b6be3,
        0x436c4cd167829819ce46024300e24d6d,
        0x0739cb3999ae6842528ce5d8ec01a7fc,
        0x1b,
        0x0,
        0x0
    ]; // r.low, r.high, s.low, s.high, v

    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: "Unsupported tx type")]
fn test_transaction_validation_unsupported_tx_type() {
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 1,
        to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
        nonce: 4,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1000000000000000000,
        calldata: array![].span(),
    };

    let signature = array![
        0x8bba859d5730ac5dc9363a3c4cb101dd,
        0xb688a37cc78e902c27509be951232f94,
        0xb0e9624f16c50a779023870d75cad640,
        0x5c7bf7e431e816e08e9329edcc014fe4,
        0x1c,
        0xde0b6b3a7640000,
        0x0
    ];
    let unsigned_tx_hash: u256 = 0xbf4c65f85c5317b99259cedee5a69aacae0551f5a265d4df53714c9deb5add55;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    account.__validate__(tx);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_eip1559_transaction_validation_value_transfer_only() {
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 2,
        to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
        nonce: 4,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1000000000000000000,
        calldata: array![].span(),
    };

    let signature = array![
        0x8bba859d5730ac5dc9363a3c4cb101dd,
        0xb688a37cc78e902c27509be951232f94,
        0xb0e9624f16c50a779023870d75cad640,
        0x5c7bf7e431e816e08e9329edcc014fe4,
        0x1c,
        0xde0b6b3a7640000,
        0x0
    ];
    let unsigned_tx_hash: u256 = 0xbf4c65f85c5317b99259cedee5a69aacae0551f5a265d4df53714c9deb5add55;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    let validation = account.__validate__(tx);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_legacy_transaction_validation_value_transfer_only() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 0,
        to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
        nonce: 4,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 152345,
        gas_limit: 21000,
        value: 1000000000000000000,
        calldata: array![].span(),
    };

    let signature = array![
        0x584ebdc080c24d8b3d84e5342c9078a6,
        0xcfb188b344b90a84ed7d38a6256b3427,
        0x4537a84e51ec5819ee07de443874c7ea,
        0x21913827f62c0b6bc9643dd9a8892e75,
        0x1b,
        0xde0b6b3a7640000,
        0x0
    ];

    let unsigned_tx_hash: u256 = 0x147b5df4a6e91fdbd967747f7b375f155e26225cec38d1e0310e925b2b7565e9;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    let validation = account.__validate__(tx);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_legacy_transaction_validation_calldata() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 0,
        to: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
            .try_into()
            .unwrap(), // we dont need to deploy account, we only check validation here
        nonce: 77,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 45235,
        gas_limit: 21000,
        value: 0,
        calldata: array![0xa9059cbb, 0x000000000000000000000000b756b1bc, 0x042fa70d85ee84eab646a3b438a285ee, 0x00000000000000000000000000000000, 0x000000000000000000000000000f4240]
            .span(),
    };

    let signature = array![
        0xa242563ffb0771ea806fc160e0665583,
        0x6279ab9f3ee976a5a0a47538ca5383be,
        0xc8cfbaab64f80111d375dce2c52e896c,
        0x419770f60d92f921b9d5434941b3891a,
        0x1c,
        0x0,
        0x0
    ];
    let unsigned_tx_hash: u256 =
    0xb2e837d9ee9c8d6e9bb40a9cf18eac862c6b4f9b0bbe5d2437abb9dcade6bab2;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    let validation = account.__validate__(tx);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_eip1559_transaction_validation_calldata() {
    // Example usdc transfer
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 2,
        to: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
            .try_into()
            .unwrap(), // we dont need to deploy account, we only check validation here
        nonce: 77,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 18610805637,
        gas_price: 0,
        gas_limit: 45439,
        value: 0,
        calldata: array![0xa9059cbb, 0x000000000000000000000000b756b1bc, 0x042fa70d85ee84eab646a3b438a285ee, 0x00000000000000000000000000000000, 0x000000000000000000000000000f4240]
            .span(),
    };

    let signature = array![
        0xde2c0c4c1d73a7231fad380bc6cd02c9,
        0xc06cac1e37757fba67d6507da161962a,
        0xf84189fa5966ffb604a19482893c0ce1,
        0x348ea9530fd75922908d72503b041e4d,
        0x1c,
        0x0,
        0x0
    ];
    //let unsigned_tx_hash: u256 =
    //0xdba8cc62e6edeee140d6b73ae141c687f9738e00ad6a954dfbfd509d89aa7428;

    //let generated_tx_hash: u256 = generate_tx_hash(tx);
    //assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    let validation = account.__validate__(tx);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_transaction_validation_calldata_and_value_transfer() {
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let target: EthAddress = 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 2,
        to: target, // we dont need to deploy account, we only check validation here
        nonce: 96,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10000000000000000,
        calldata: array![0xd0e30db0].span(),
    };

    let signature = array![
        0x8c316619b18a29fa6b36e2a8aa3e2a7a,
        0x96b21fa5400b0ddf828efdaefa05dc8b,
        0xd79f6b9c8bc8a8ed2fcc183fd1069f02,
        0x6542b3440f82443065a9dc1486deb5b7,
        0x1c,
        0x2386f26fc10000,
        0x0
    ];
    let unsigned_tx_hash: u256 = 0x4efffa2e75fab48e0a7b03c45c53f8fffb98a89d6f457c44b98fd401ba287e29;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    let validation = account.__validate__(tx);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

// Todo validation tests and multicall tests