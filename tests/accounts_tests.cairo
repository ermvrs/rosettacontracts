use snforge_std::{
    start_cheat_signature_global, stop_cheat_signature_global, start_cheat_nonce_global,
    stop_cheat_nonce_global, start_cheat_caller_address, stop_cheat_caller_address
};

use rosettacontracts::accounts::utils::{
    RosettanetCall 
};
use rosettacontracts::accounts::utils_new::{generate_tx_hash};
use rosettacontracts::utils::transaction::eip2930::{AccessListItem};
use rosettacontracts::accounts::base::{IRosettaAccountDispatcherTrait};
use rosettacontracts::rosettanet::{IRosettanetDispatcherTrait};
use rosettacontracts::mocks::erc20::{IMockERC20DispatcherTrait, IMockERC20Dispatcher};
use rosettacontracts::mocks::weth::{IMockWETHDispatcherTrait};
use starknet::{EthAddress};
use rosettacontracts_integrationtest::test_utils::{
    deploy_weth, eth_account, deploy_account_from_rosettanet, deploy_funded_account_from_rosettanet,
    deploy_specificly_funded_account_from_rosettanet, deploy_account_from_existing_rosettanet,
    manipulate_rosettanet_registry, deploy_erc20, declare_erc20, change_current_account_class, register_functions
};

// TODO: test deploying account from its own
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
    let signature: Array<felt252> = array![
        0x3188ef10bf8469101d372e6b0960ed1b,
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
fn test_signature_validation_eip1559() {
    // EIP1559 tx hash
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
    let signature = array![0x34e45bcf8ecf1ca3bd52ea7a93ef7d31,0x74d09bfb0301645262106184fee00493, 0xd43382bdf45a8c272bcf101e9fcfa716,0x55296d9471410304362b0e4fd0ab7e06, 0x1b, 0x0,0x0];
    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_signature_validation_legacy_invalid() {
    // Legacy tx hash
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x04af5100efeb883338fbc81c2c167f0907889760af4002d45b378ee093a882ac;
    let signature = array![0x34e44bcf8ecf1ca3bd52ea7a93ef7d31,0x74d09bfb0301645262106184fee00493, 0xd43382bdf45a8c272bcf101e9fcfa716,0x55296d9471410304362b0e4fd0ab7e06, 0x1b, 0x0,0x0];
    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_wrong_signature() {
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
#[should_panic(expected: 'Invalid signature')]
fn test_signature_wrong_address() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e2.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x105d7b8d7c9fe830c123f2d99c01e09bfa7d902cb3b5afee409cf3dca533f52b;
    let signature: Array<felt252> = array![
        0x3188ef10bf8469101d372e6b0960ed1b,
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
    // Testing with empty access list eip1559 transaction
    // Access list support will be added further
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
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
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
fn test_transaction_validation_value_transfer_only() {
    // Testing with empty access list eip1559 transaction
    // Access list support will be added further
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
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
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
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![0x584ebdc080c24d8b3d84e5342c9078a6,0xcfb188b344b90a84ed7d38a6256b3427, 0x4537a84e51ec5819ee07de443874c7ea,0x21913827f62c0b6bc9643dd9a8892e75, 0x1b, 0xde0b6b3a7640000,0x0];

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
        calldata: array![0xa9059cbb, 0xb756b1bc042fa70d85ee84eab646a3b438a285ee, 0xf4240, 0x0]
            .span(),
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![0x7472616E7366657228616464726573732C75696E7432353629]
            .span() // transfer(address,uint256)
    };

    let signature = array![
        0xa242563ffb0771ea806fc160e0665583,0x6279ab9f3ee976a5a0a47538ca5383be, 0xc8cfbaab64f80111d375dce2c52e896c,0x419770f60d92f921b9d5434941b3891a, 0x1c, 0x0,0x0
    ];
    let unsigned_tx_hash: u256 = 0xb2e837d9ee9c8d6e9bb40a9cf18eac862c6b4f9b0bbe5d2437abb9dcade6bab2;

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
#[should_panic(expected: 'Invalid signature')]
fn test_legacy_transaction_validation_calldata_invalid_signature() {
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
        calldata: array![0xa9059cbb, 0xb756b1bc042fa70d85ee84eab646a3b438a285ee, 0xf4240, 0x0]
            .span(),
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![0x7472616E7366657228616464726573732C75696E7432353629]
            .span() // transfer(address,uint256)
    };

    let signature = array![
        0xa242563ffb0771ea806fc160e0665584,0x6279ab9f3ee976a5a0a47538ca5383be, 0xc8cfbaab64f80111d375dce2c52e896c,0x419770f60d92f921b9d5434941b3891a, 0x1c, 0x0,0x0
    ];
    let unsigned_tx_hash: u256 = 0xb2e837d9ee9c8d6e9bb40a9cf18eac862c6b4f9b0bbe5d2437abb9dcade6bab2;

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
fn test_transaction_validation_calldata() {
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
        calldata: array![0xa9059cbb, 0xb756b1bc042fa70d85ee84eab646a3b438a285ee, 0xf4240, 0x0]
            .span(),
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![0x7472616E7366657228616464726573732C75696E7432353629]
            .span() // transfer(address,uint256)
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
    let unsigned_tx_hash: u256 = 0xdba8cc62e6edeee140d6b73ae141c687f9738e00ad6a954dfbfd509d89aa7428;

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
#[should_panic(expected: 'function not registered')]
#[ignore]
fn test_transaction_validation_calldata_wrong_target_function() {
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
        calldata: array![0xb9059cbc, 0xb756b1bc042fa70d85ee84eab646a3b438a285ee, 0xf4240, 0x0]
            .span(),
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![0x17228616464726573732C75696E7432353619].span() // random hex
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
    let unsigned_tx_hash: u256 = 0xdba8cc62e6edeee140d6b73ae141c687f9738e00ad6a954dfbfd509d89aa7428;

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
fn test_transaction_validation_calldata_and_value_transfer() {
    // TODO: call target after sending strk
    // No execution just validate
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
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![0x6465706F7369742829].span()
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

#[test]
#[ignore]
#[should_panic(expected: 'Access list not supported')]
fn test_validation_with_access_list() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let target: EthAddress = 0xC7f5D5D3725f36CF36477B84010EB8DdE42D3636.try_into().unwrap();
    let access_list_item = AccessListItem {
        ethereum_address: 0x5703ff58bB0CA34F870a8bC18dDd541f29375978.try_into().unwrap(),
        storage_keys: array![0_u256, 1_u256].span()
    };

    let tx = RosettanetCall {
        to: target, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 87,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 16357352599,
        gas_price: 0,
        gas_limit: 210000,
        value: 0,
        calldata: array![0xf4acc7b5].span(), // sends 1000000 tokens
        access_list: array![access_list_item].span(),
        directives: array![].span(),
        target_function: array![0x63616C6C43616C63756C61746F722829].span()
    };

    let signature = array![
        0xc7ac6350bd17348d16f37c3e16e32f38,
        0x4f3595825b9a4f9b3bc433a373aba603,
        0x309f20124684d93997be0ebaecec49c0,
        0x6a79d47f800e637b21026ba1591cee5b,
        0x1b,
        0x0,
        0x0
    ];
    let unsigned_tx_hash: u256 = 0xdd014b10515a451a59e9f92a9bbfa7ce01cc208856b5862d38f88d17ee4cf3d8;

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

// Execution tests

#[test]
#[ignore] // Ignored because we changed logic
#[should_panic(expected: 'target not registered')]
fn test_execute_value_transfer_to_non_registered() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
        tx_type: 2,
        nonce: 59,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1,
        calldata: array![].span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![
        0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,
        0x15bd08d62685c22d30a57d611a643c76,
        0x290a42b030be68a236a837dff15a77c3,
        0x57f669dd35be2b984cd4ab48c0a0c588,
        0x1c,
        0x1,
        0x0
    ];

    let (_, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(execution, array![array![].span()]);
}

#[test]
#[should_panic(expected: 'value sig-tx mismatch')]
fn test_execute_value_transfer_wrong_value_on_sig() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let receiver_address: EthAddress = 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee
        .try_into()
        .unwrap();
    let tx = RosettanetCall {
        to: receiver_address,
        tx_type: 2,
        nonce: 59,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1,
        calldata: array![].span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![
        0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,
        0x15bd08d62685c22d30a57d611a643c76,
        0x290a42b030be68a236a837dff15a77c3,
        0x57f669dd35be2b984cd4ab48c0a0c588,
        0x1c,
        0x1FFF,
        0x1FFF
    ];

    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    let _ = deploy_account_from_existing_rosettanet(receiver_address, rosettanet.contract_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(execution, array![array![].span()]);
}

#[test]
#[should_panic(expected: 'ERC20: insufficient balance')]
fn test_execute_value_transfer_not_enough_balance() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let receiver_address: EthAddress = 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee
        .try_into()
        .unwrap();
    let tx = RosettanetCall {
        to: receiver_address,
        tx_type: 2,
        nonce: 59,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1,
        calldata: array![].span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![
        0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,
        0x15bd08d62685c22d30a57d611a643c76,
        0x290a42b030be68a236a837dff15a77c3,
        0x57f669dd35be2b984cd4ab48c0a0c588,
        0x1c,
        0x1,
        0x0
    ];

    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    let _ = deploy_account_from_existing_rosettanet(receiver_address, rosettanet.contract_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(execution, array![array![].span()]);
}

#[test]
fn test_execute_value_transfer() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let receiver_address: EthAddress = 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee
        .try_into()
        .unwrap();
    let tx = RosettanetCall {
        to: receiver_address,
        tx_type: 2,
        nonce: 59,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1,
        calldata: array![].span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![
        0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,
        0x15bd08d62685c22d30a57d611a643c76,
        0x290a42b030be68a236a837dff15a77c3,
        0x57f669dd35be2b984cd4ab48c0a0c588,
        0x1c,
        0x1,
        0x0
    ];

    let (rosettanet, account, strk) = deploy_funded_account_from_rosettanet(eth_address);

    let receiver = deploy_account_from_existing_rosettanet(
        receiver_address, rosettanet.contract_address
    );
    assert_eq!(strk.balance_of(receiver.contract_address), 0);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(strk.balance_of(receiver.contract_address), 1);
    assert_eq!(execution, array![array![].span()]);
}

#[test]
#[ignore]
fn test_execute_erc20_transfer_receiver_not_registered() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let erc20_eth: EthAddress = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238.try_into().unwrap();
    let tx = RosettanetCall {
        to: erc20_eth, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 77,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 18610805637,
        gas_price: 0,
        gas_limit: 45439,
        value: 0,
        calldata: array![0xa9059cbb, 0xb756b1bc042fa70d85ee84eab646a3b438a285ee, 0xf4240, 0x0]
            .span(),
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![0x7472616E7366657228616464726573732C75696E7432353629]
            .span() // transfer(address,uint256)
    };

    let signature = array![
        0x6ddb2d56bf6b847af890501e1a44bf19,
        0xcc8d431460ddb8f3a228d1cdfe069be1,
        0xdbeff1d03deae8859e16491d3c7d4b89,
        0x62b4b646ff3c09068d04eb98eec04413,
        0x1b,
        0x0,
        0x0
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    register_functions(rosettanet);
    let erc20 = deploy_erc20();

    manipulate_rosettanet_registry(rosettanet.contract_address, erc20.contract_address, erc20_eth);

    let fallback_account_address = rosettanet
        .get_starknet_address_with_fallback(
            0xb756b1bc042fa70d85ee84eab646a3b438a285ee.try_into().unwrap()
        );

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(erc20.balance_of(fallback_account_address), 0xf4240);
}

#[test]
fn test_execute_erc20_transfer_legacy() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let erc20_eth: EthAddress = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238.try_into().unwrap();
    let tx = RosettanetCall {
        to: erc20_eth, // we dont need to deploy account, we only check validation here
        tx_type: 0,
        nonce: 23,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 39191,
        gas_limit: 21000,
        value: 0,
        calldata: array![0xa9059cbb, 0xb756b1bc042fa70d85ee84eab646a3b438a285ee, 0xf4240, 0x0]
            .span(), // sends 1000000 tokens
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![0x7472616E7366657228616464726573732C75696E7432353629]
            .span() // transfer(address,uint256)
    };

    let signature = array![
        0x8dbeaba3292e8da5751fe696af7248f3,0xad1e5653ac0873d540479f7a9619e94b, 0x5142bfaa68b44d063e3ca9a1e71dff21,0x6dcaafc193c6f1ad9eb684ab8d87c49b, 0x1c, 0x0,0x0
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    register_functions(rosettanet);

    let receiver = deploy_account_from_existing_rosettanet(
        0xb756b1bc042fa70d85ee84eab646a3b438a285ee.try_into().unwrap(), rosettanet.contract_address
    );

    let erc20 = deploy_erc20();

    erc20.mint(account.contract_address, 1500000); // Fund account

    manipulate_rosettanet_registry(rosettanet.contract_address, erc20.contract_address, erc20_eth);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(erc20.balance_of(receiver.contract_address), 1000000);
    assert_eq!(erc20.balance_of(account.contract_address), 500000);
    assert_eq!(execution, array![array![0x1].span()]); // erc20 transfer returns true
}

#[test]
fn test_execute_erc20_transfer() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let erc20_eth: EthAddress = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238.try_into().unwrap();
    let tx = RosettanetCall {
        to: erc20_eth, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 77,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 18610805637,
        gas_price: 0,
        gas_limit: 45439,
        value: 0,
        calldata: array![0xa9059cbb, 0xb756b1bc042fa70d85ee84eab646a3b438a285ee, 0xf4240, 0x0]
            .span(), // sends 1000000 tokens
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![0x7472616E7366657228616464726573732C75696E7432353629]
            .span() // transfer(address,uint256)
    };

    let signature = array![
        0x6ddb2d56bf6b847af890501e1a44bf19,
        0xcc8d431460ddb8f3a228d1cdfe069be1,
        0xdbeff1d03deae8859e16491d3c7d4b89,
        0x62b4b646ff3c09068d04eb98eec04413,
        0x1b,
        0x0,
        0x0
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    register_functions(rosettanet);
    let receiver = deploy_account_from_existing_rosettanet(
        0xb756b1bc042fa70d85ee84eab646a3b438a285ee.try_into().unwrap(), rosettanet.contract_address
    );

    let erc20 = deploy_erc20();

    erc20.mint(account.contract_address, 1500000); // Fund account

    manipulate_rosettanet_registry(rosettanet.contract_address, erc20.contract_address, erc20_eth);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(erc20.balance_of(receiver.contract_address), 1000000);
    assert_eq!(erc20.balance_of(account.contract_address), 500000);
    assert_eq!(execution, array![array![0x1].span()]); // erc20 transfer returns true
}

#[test]
#[should_panic(expected: 'ERC20: insufficient balance')]
fn test_execute_erc20_transfer_exceeds_balance() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let erc20_eth: EthAddress = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238.try_into().unwrap();
    let tx = RosettanetCall {
        to: erc20_eth, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 77,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 18610805637,
        gas_price: 0,
        gas_limit: 45439,
        value: 0,
        calldata: array![0xa9059cbb, 0xb756b1bc042fa70d85ee84eab646a3b438a285ee, 0xf4240, 0x0]
            .span(), // sends 1000000 tokens
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![0x7472616E7366657228616464726573732C75696E7432353629]
            .span() // transfer(address,uint256)
    };

    let signature = array![
        0x6ddb2d56bf6b847af890501e1a44bf19,
        0xcc8d431460ddb8f3a228d1cdfe069be1,
        0xdbeff1d03deae8859e16491d3c7d4b89,
        0x62b4b646ff3c09068d04eb98eec04413,
        0x1b,
        0x0,
        0x0
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    register_functions(rosettanet);

    deploy_account_from_existing_rosettanet(
        0xb756b1bc042fa70d85ee84eab646a3b438a285ee.try_into().unwrap(), rosettanet.contract_address
    );

    let erc20 = deploy_erc20();

    erc20.mint(account.contract_address, 500000); // Fund account but not enough

    manipulate_rosettanet_registry(rosettanet.contract_address, erc20.contract_address, erc20_eth);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_execute_erc20_transfer_with_value() {}

#[test]
#[should_panic(expected: 'Access list not supported')]
#[ignore] // Since validation done in __validate__ this is not failing. Execution doesnt care about access list context
fn test_execute_with_access_list() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let target: EthAddress = 0xC7f5D5D3725f36CF36477B84010EB8DdE42D3636.try_into().unwrap();
    let access_list_item = AccessListItem {
        ethereum_address: 0x5703ff58bB0CA34F870a8bC18dDd541f29375978.try_into().unwrap(),
        storage_keys: array![0_u256, 1_u256].span()
    };
    let tx = RosettanetCall {
        to: target, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 87,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 16357352599,
        gas_price: 0,
        gas_limit: 210000,
        value: 0,
        calldata: array![0xf4acc7b5].span(), // sends 1000000 tokens
        access_list: array![access_list_item].span(), // this must be always empty
        directives: array![].span(),
        target_function: array![0x63616C6C43616C63756C61746F722829].span() // callCalculator()
    };

    let signature = array![
        0xc7ac6350bd17348d16f37c3e16e32f38,
        0x4f3595825b9a4f9b3bc433a373aba603,
        0x309f20124684d93997be0ebaecec49c0,
        0x6a79d47f800e637b21026ba1591cee5b,
        0x1b,
        0x0,
        0x0
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    deploy_account_from_existing_rosettanet(target, rosettanet.contract_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_execute_value_transfer_and_call() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let target: EthAddress = 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9.try_into().unwrap();
    let tx = RosettanetCall {
        to: target, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 96,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10000000000000000,
        calldata: array![0xd0e30db0].span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![0x6465706F7369742829].span()
    };

    let signature = array![
        0x6032b3e971d4c254e37e5ee46891d63e,
        0xd09052bb95e3f38497e93e934b96860f,
        0x3ba19d6fd34eaf4ad1b155397ecd056a,
        0x2344e2307c2852957a9bf7d25d0d7dbf,
        0x1c,
        0x2386F26FC10000,
        0x0
    ];
    let (rosettanet, account, strk) = deploy_specificly_funded_account_from_rosettanet(
        eth_address, 20000000000000000_u256
    );

    register_functions(rosettanet);

    let weth = deploy_weth();
    manipulate_rosettanet_registry(rosettanet.contract_address, weth.contract_address, target);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(strk.balance_of(weth.contract_address), tx.value);
    assert_eq!(strk.balance_of(account.contract_address), 20000000000000000_u256 - tx.value);
    assert_eq!(weth.last_deposit(), tx.value);
}

#[test]
#[should_panic(expected: 'multicall value not zero')]
fn test_multicall_with_value() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address, // we dont need to deploy account, we only check validation here
        tx_type: 8,
        nonce: 96,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10,
        calldata: array![0x76971d7f].span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![0x6465706F7369742829].span()
    };

    let signature = array![
        0x6032b3e971d4c254e37e5ee46891d63e,
        0xd09052bb95e3f38497e93e934b96860f,
        0x3ba19d6fd34eaf4ad1b155397ecd056a,
        0x2344e2307c2852957a9bf7d25d0d7dbf,
        0x1c,
        0x2386F26FC10000,
        0x0
    ];
    let (rosettanet, account, strk) = deploy_specificly_funded_account_from_rosettanet(
        eth_address, 20000000000000000_u256
    );

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
#[should_panic(expected: 'Rosetta: unimplemented feature')]
fn test_multicall_wrong_selector() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address, // we dont need to deploy account, we only check validation here
        tx_type: 8,
        nonce: 96,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10,
        calldata: array![0xabcabcab].span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![0x6465706F7369742829].span()
    };

    let signature = array![
        0x6032b3e971d4c254e37e5ee46891d63e,
        0xd09052bb95e3f38497e93e934b96860f,
        0x3ba19d6fd34eaf4ad1b155397ecd056a,
        0x2344e2307c2852957a9bf7d25d0d7dbf,
        0x1c,
        0x2386F26FC10000,
        0x0
    ];
    let (rosettanet, account, strk) = deploy_specificly_funded_account_from_rosettanet(
        eth_address, 20000000000000000_u256
    );

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test] // Ignore this test after multicall is available
#[should_panic(expected: 'Rosetta: unimplemented feature')]
fn test_unimplemented_feature() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address, // we dont need to deploy account, we only check validation here
        tx_type: 8,
        nonce: 96,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 0,
        calldata: array![0xffffffff].span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![0x6465706F7369742829].span()
    };

    let signature = array![
        0x6032b3e971d4c254e37e5ee46891d63e,
        0xd09052bb95e3f38497e93e934b96860f,
        0x3ba19d6fd34eaf4ad1b155397ecd056a,
        0x2344e2307c2852957a9bf7d25d0d7dbf,
        0x1c,
        0x2386F26FC10000,
        0x0
    ];
    let (rosettanet, account, strk) = deploy_specificly_funded_account_from_rosettanet(
        eth_address, 20000000000000000_u256
    );

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_validation_real_data_failing() {
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let target: EthAddress = 0xbec5832bd3f642d090891b4991da42fa4d5d9e2d.try_into().unwrap();
    let tx = RosettanetCall {
        to: target,
        tx_type: 2,
        nonce: 1,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x095ea7b3, 0x1, 0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff
        ]
            .span(),
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![0x617070726F766528616464726573732C75696E7432353629].span()
    };
    let signature = array![
        0x71b346721683b41b0b508fb699019c0f,
        0x539d8bfcf7981d45eeab26c8582e0083,
        0xa44cbc3542440773e63fa205526972dc,
        0x3658ebdd892fc2bec784a083eebd055d,
        0x1c,
        0x0,
        0x0
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    deploy_account_from_existing_rosettanet(target, rosettanet.contract_address);

    let unsigned_tx_hash: u256 = 0xfd239b434a5033e678887a7d60fa5ace7f6cdbf110febe8d266bd947efb40c7b;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__validate__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_validate_multicall_transaction() {
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address, // Target is same bcs its feature call
        tx_type: 8,
        nonce: 59,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x2,
            0x123123,
            0x456456,
            0x2,
            0x111,
            0x222,
            0x888888,
            0x999999,
            0x2,
            0x654,
            0x321
        ]
            .span(),
        access_list: array![].span(),
        directives: array![0x2, 0x1, 0x0].span(),
        target_function: array![].span()
    };
    let signature = array![
        0x42507df1d32b89c5c789fa3d5d70f9c9,
        0xf30f73b6dfecb122e9c33e94d8d9c2ec,
        0x7ed1b0a8c87e84909580b659562d251f,
        0x711d7b42f0c91ee717f4770dff7c7f00,
        0x1b,
        0x0,
        0x0
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    let unsigned_tx_hash: u256 = 0x66c3880f27b684f53da1f020f6995153435154c89a11e6c641fa5d137c9edfe8;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let validation = account.__validate__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_validate_multicall_transaction_wrong_signature() {
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address, // Target is same bcs its feature call
        tx_type: 8,
        nonce: 59,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x2,
            0x123123,
            0x456456,
            0x2,
            0x111,
            0x222,
            0x888888,
            0x999999,
            0x2,
            0x654,
            0x321
        ]
            .span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };
    let signature = array![
        0x42607df1d32b89c5c789fa3d5d70f9c9,
        0xf30f73b6dfecb122e9c33e94d8d9c2ec,
        0x7ed1b0a8c87e84909580b659562d251f,
        0x711d7b42f0c91ee717f4770dff7c7f00,
        0x1b,
        0x0,
        0x0
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    let unsigned_tx_hash: u256 = 0x66c3880f27b684f53da1f020f6995153435154c89a11e6c641fa5d137c9edfe8;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let validation = account.__validate__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_execute_multicall_transaction() {
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let strk_address: felt252 = 0xA551825F2E7D5313EE03B1DFE40E2A7B78B27A7FED40FA17AEC27E010BFA96;
    let strk_receiver_1: felt252 = 0x555666;
    let strk_receiver_2: felt252 = 0x111222;

    let strk_1_amount: u256 = 1500;
    let strk_2_amount: u256 = 3000;

    let transfer_entrypoint: felt252 =
        0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e;
    // We dont use eth addresses on multicall
    let (rosettanet, account, strk) = deploy_funded_account_from_rosettanet(eth_address);
    assert_eq!(
        strk.contract_address.into(),
        0xA551825F2E7D5313EE03B1DFE40E2A7B78B27A7FED40FA17AEC27E010BFA96
    );

    let tx = RosettanetCall {
        to: eth_address,
        tx_type: 8,
        nonce: 59,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x2,
            strk_address,
            transfer_entrypoint,
            0x3,
            strk_receiver_1,
            strk_1_amount.low.into(),
            strk_1_amount.high.into(),
            strk_address,
            transfer_entrypoint,
            0x3,
            strk_receiver_2,
            strk_2_amount.low.into(),
            strk_2_amount.high.into()
        ]
            .span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![
        0x56df07af96d2ec1992ab5c5ba1577260,
        0xdf6e5f3347e5f26e03eecb3c6fa6569b,
        0x830eb63af9949d06ef4e6c096f5806,
        0x680c7672f0b3a18c902a68350cf19b60,
        0x1b,
        0x0,
        0x0
    ];

    let unsigned_tx_hash: u256 = 0x0f979b268363cd98b085532a6b1163d73bccb5b1acf58ad0a05d9537c81b297d;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(strk.balance_of(strk_receiver_1.try_into().unwrap()), 1500);
    assert_eq!(strk.balance_of(strk_receiver_2.try_into().unwrap()), 3000);
    assert_eq!(execution, array![array![0x1].span(), array![0x1].span()]);
}

#[test]
fn test_multicall_validate_actual_values() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address,
        tx_type: 8,
        nonce: 1,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x2,
            0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7,
            0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e,
            0x3,
            0x07D33254052409C04510C3652BC5BE5656F1EFF1B131C7C031592E3FA73F1F70,
            0x221B262DD8000,
            0x0,
            0x04c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f,
            0xe5b455a836c7a254df57ed39d023d46b641b331162c6c0b369647056655409,
            0x4,
            0x455448,
            0xE4306A06B19FDC04FDF98CF3C00472F29254C0E1,
            0x38D7EA4C68000,
            0x0
        ]
            .span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![
        0xf33158ce9a85ed8ba430d45faba907a6,
        0xd0a3476ce415af96c1e40ae3cc16fab9,
        0xfc09b9ed76e6f1abae8cf3b3732c92c2,
        0x74551833c56fee1df9cb2a2ac411c604,
        0x1b,
        0x0,
        0x0
    ];

    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    let unsigned_tx_hash: u256 = 0x1f766a70ecbf4270faeff147ff3df9fee659426af425bab130f449e47be438eb;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let validation = account.__validate__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_multicall_validate_actual_values_swap() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address,
        tx_type: 8,
        nonce: 6,
        max_priority_fee_per_gas: 155216104248442,
        max_fee_per_gas: 155216104248442,
        gas_price: 0,
        gas_limit: 50000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x2,
            0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7,
            0x219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c,
            0x3,
            0x02c56e8b00dbe2a71e57472685378fc8988bba947e9a99b26a00fade2b4fe7c2,
            0x38d7ea4c68000,
            0x0,
            0x02c56e8b00dbe2a71e57472685378fc8988bba947e9a99b26a00fade2b4fe7c2,
            0x01171593aa5bdadda4d6b0efde6cc94ee7649c3163d5efeb19da6c16d63a2a63,
            0x17,
            0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7,
            0x38d7ea4c68000,
            0x0,
            0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d,
            0x0000000000000000000000000000000000000000000000000005c8ac1d55b34e,
            0x0,
            0x00000000000000000000000000000000000000000000000000057ea382449d8a,
            0x0,
            0x052d8e9778d026588a51595e30b0f45609b4f771eecf0e335cdefed1d84a9d89,
            0x0,
            0x0,
            0x1,
            0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7,
            0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d,
            0x0444a09d96389aa7148f1aada508e30b71299ffe650d9c97fdaae38cb9a23384,
            0x000000000000000000000000000000000000000000000000000000e8d4a51000,
            0x6,
            0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d,
            0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7,
            0x000000000000000000000000000000000020c49ba5e353f80000000000000000,
            0x3e8,
            0x0,
            0x0000000000000000000000000000000000011ebd39f990000f1fc7d3532a0ba8
        ]
            .span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![
        0x451400a2f9bcef3ab5fe077740dd7340,
        0xbb7dfa5b5c282d46b46bfadde18c344b,
        0x9545626bb4e5348995064c9dd47b007,
        0x5c42fa0d43e2416471a498caa7b39583,
        0x1b,
        0x0,
        0x0
    ];

    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    let unsigned_tx_hash: u256 = 0x818bd006d9cc1dd0103fce48f6c554f2c23549799eacdced117d87ad54bd7f0d;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let validation = account.__validate__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_only_deploy_step_cost() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address,
        tx_type: 8,
        nonce: 6,
        max_priority_fee_per_gas: 155216104248442,
        max_fee_per_gas: 155216104248442,
        gas_price: 0,
        gas_limit: 50000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x2,
            0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7,
            0x219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c,
            0x3,
            0x02c56e8b00dbe2a71e57472685378fc8988bba947e9a99b26a00fade2b4fe7c2,
            0x38d7ea4c68000,
            0x0,
            0x02c56e8b00dbe2a71e57472685378fc8988bba947e9a99b26a00fade2b4fe7c2,
            0x01171593aa5bdadda4d6b0efde6cc94ee7649c3163d5efeb19da6c16d63a2a63,
            0x17,
            0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7,
            0x38d7ea4c68000,
            0x0,
            0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d,
            0x0000000000000000000000000000000000000000000000000005c8ac1d55b34e,
            0x0,
            0x00000000000000000000000000000000000000000000000000057ea382449d8a,
            0x0,
            0x052d8e9778d026588a51595e30b0f45609b4f771eecf0e335cdefed1d84a9d89,
            0x0,
            0x0,
            0x1,
            0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7,
            0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d,
            0x0444a09d96389aa7148f1aada508e30b71299ffe650d9c97fdaae38cb9a23384,
            0x000000000000000000000000000000000000000000000000000000e8d4a51000,
            0x6,
            0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d,
            0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7,
            0x000000000000000000000000000000000020c49ba5e353f80000000000000000,
            0x3e8,
            0x0,
            0x0000000000000000000000000000000000011ebd39f990000f1fc7d3532a0ba8
        ]
            .span(),
        access_list: array![].span(),
        directives: array![].span(),
        target_function: array![].span()
    };

    let signature = array![
        0x451400a2f9bcef3ab5fe077740dd7340,
        0xbb7dfa5b5c282d46b46bfadde18c344b,
        0x9545626bb4e5348995064c9dd47b007,
        0x5c42fa0d43e2416471a498caa7b39583,
        0x1b,
        0x0,
        0x0
    ];

    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    //let unsigned_tx_hash: u256 = 0x818bd006d9cc1dd0103fce48f6c554f2c23549799eacdced117d87ad54bd7f0d;
    //let generated_tx_hash: u256 = generate_tx_hash(tx);
    //assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    //let validation = account.__validate__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    //assert_eq!(validation, starknet::VALIDATED);
}
