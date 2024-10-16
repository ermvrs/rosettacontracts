use openzeppelin_utils::serde::SerializedAppend;
use rosettacontracts::accounts::base::{RosettaAccount, IRosettaAccountDispatcher, IRosettaAccountDispatcherTrait};
use rosettacontracts::factory::{Factory, IFactoryDispatcher, IFactoryDispatcherTrait};
use snforge_std::{declare, get_class_hash, ContractClassTrait, DeclareResultTrait};
use starknet::{EthAddress};

#[test]
fn deploy_check_initials() {
    let account_contract_class = declare("RosettaAccount").unwrap().contract_class();

    let factory_contract_class = declare("Factory").unwrap().contract_class();

    let mut factory_calldata = array![];

    factory_calldata.append_serde('123123');
    factory_calldata.append_serde('0');

    let (factory_contract_address, _) = factory_contract_class.deploy(@factory_calldata).unwrap();

    let factory_dispatcher = IFactoryDispatcher { contract_address: factory_contract_address };

    let ethereum_address: EthAddress = 0x11655f4Ee2A5B66F9DCbe758e9FcdCd3eBF95eE5.try_into().unwrap();

    let precalculated_address = factory_dispatcher.precalculate_starknet_address(ethereum_address);

    let (account_contract_address, _) = account_contract_class.deploy(@array![ethereum_address.into()]).unwrap();

    assert(precalculated_address == account_contract_address, 'precalculated address wrong');
    // TODO: burayı fixle neden hata dönüyor ve debug print ekle
}