use openzeppelin_utils::serde::SerializedAppend;
use rosettacontracts::accounts::base::{RosettaAccount, IRosettaAccountDispatcher, IRosettaAccountDispatcherTrait};
use rosettacontracts::factory::{Factory, IFactoryDispatcher, IFactoryDispatcherTrait};
use snforge_std::{declare, get_class_hash, ContractClassTrait, DeclareResultTrait};

#[test]
fn deploy_check_initials() {
    let account_contract_class = declare("RosettaAccount").unwrap().contract_class();

    let (account_contract_address, _) = account_contract_class.deploy(@array!['0']).unwrap();

    let account_class_hash = get_class_hash(account_contract_address);

    let factory_contract_class = declare("Factory").unwrap().contract_class();

    let mut factory_calldata = array![];

    factory_calldata.append_serde(account_class_hash);
    factory_calldata.append_serde('0');

    let (factory_contract_address, _) = factory_contract_class.deploy(@factory_calldata).unwrap();

    let factory_dispatcher = IFactoryDispatcher { contract_address: factory_contract_address };
    factory_dispatcher.current_account_class().print();
    account_class_hash.print();
    assert(factory_dispatcher.current_account_class() == account_class_hash, 'account class wrong');
    // TODO: burayı fixle neden hata dönüyor ve debug print ekle
}