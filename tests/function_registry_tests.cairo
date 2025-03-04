use rosettacontracts_integrationtest::test_utils::{
    deploy_rosettanet
};
//use rosettacontracts::rosettanet::{IRosettanetDispatcherTrait};
use rosettacontracts::components::function_registry::{IFunctionRegistryDispatcherTrait, IFunctionRegistryDispatcher};
use rosettacontracts::utils::decoder::{EVMTypes};

#[test]
fn test_register_function() {
    let rosettanet = deploy_rosettanet();

    IFunctionRegistryDispatcher{contract_address: rosettanet.contract_address}.register_function("transfer(address,uint256)", array![EVMTypes::Address, EVMTypes::Uint256].span());
}