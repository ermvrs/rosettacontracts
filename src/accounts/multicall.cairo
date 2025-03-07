use core::panic_with_felt252;

use crate::accounts::types::{RosettanetMulticall};
use crate::utils::decoder::{EVMCalldata, EVMTypes, EVMTypesImpl};
use crate::accounts::utils::{span_to_array};
use starknet::ContractAddress;
use crate::utils::bytes::{BytesTrait};

// Pass calldata without function selector
pub fn prepare_multicall_context(
    registry: ContractAddress, calldata: Span<u128>
) -> Span<RosettanetMulticall> {
    let mut evm_calldata = EVMCalldata {
        registry: registry,
        offset: 0,
        relative_offset: 0,
        calldata: BytesTrait::new(calldata.len() * 16, span_to_array(calldata))
    };

    let directives = array![
        EVMTypes::Array(
            array![
                EVMTypes::Tuple(
                    array![
                        EVMTypes::Felt252,
                        EVMTypes::Felt252,
                        EVMTypes::Array(array![EVMTypes::Felt252].span())
                    ]
                        .span()
                )
            ]
                .span()
        )
    ]
        .span();
    let decoded_calldata = evm_calldata.decode(directives);

    prepare_multicall_context_from_serialized_calldata(decoded_calldata)
}

fn prepare_multicall_context_from_serialized_calldata(
    calldata: Span<felt252>
) -> Span<RosettanetMulticall> {
    let mut calldata = calldata;

    let call_count: u64 = match calldata.pop_front() {
        Option::None => {
            0_u64
        }, // We may remove that panic or change the logic, since native eth transfer has empty calldata
        Option::Some(val) => { (*val).try_into().unwrap() }
    };

    let mut calls = ArrayTrait::<RosettanetMulticall>::new();

    let mut i = 0;
    loop {
        if (i == call_count) {
            break;
        }

        let to: felt252 = match calldata.pop_front() {
            Option::None => { 0x0 }, // TODO: panic
            Option::Some(val) => { (*val) }
        };
        if (to == 0x0) {
            panic_with_felt252('multicall to wrong');
        }
        let entrypoint: felt252 = match calldata.pop_front() {
            Option::None => { 0x0 }, // TODO: panic
            Option::Some(val) => { (*val) }
        };

        if (entrypoint == 0x0) {
            panic_with_felt252('multicall entry wrong');
        }

        let calldata_length: u64 = match calldata.pop_front() {
            Option::None => { 0 },
            Option::Some(val) => { (*val).try_into().unwrap() }
        };

        let mut inner_calldata: Array<felt252> = array![];
        let mut j = 0;
        loop {
            if (j == calldata_length) {
                break;
            }

            let value: felt252 = match calldata.pop_front() {
                Option::None => { break; }, // TODO: panic
                Option::Some(val) => { (*val) }
            };

            inner_calldata.append(value);

            j += 1;
        };

        calls.append(RosettanetMulticall { to, entrypoint, calldata: inner_calldata.span() });
        i += 1;
    };

    calls.span()
}


#[cfg(test)]
mod tests {
    use crate::accounts::multicall::{prepare_multicall_context};

    #[test]
    fn test_prepare_multicall_context() {
        let calldata: Span<u128> = array![
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000020,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000120,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000001c0,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000123123,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000456456,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000111,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000222,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000888888,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000999999,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000001,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000654,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000333333,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000232323,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000fff,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000bbb,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000ccc
        ]
            .span();

        let context = prepare_multicall_context(starknet::contract_address_const::<0>(), calldata);

        assert_eq!(context.len(), 3);
        assert_eq!((*context.at(0)).to, 0x123123);
        assert_eq!((*context.at(0)).entrypoint, 0x456456);
        assert_eq!((*context.at(0)).calldata.len(), 0x2);
        assert_eq!(*(*context.at(0)).calldata.at(0), 0x111);
        assert_eq!(*(*context.at(0)).calldata.at(1), 0x222);
        assert_eq!((*context.at(1)).to, 0x888888);
        assert_eq!((*context.at(1)).entrypoint, 0x999999);
        assert_eq!((*context.at(1)).calldata.len(), 0x1);
        assert_eq!(*(*context.at(1)).calldata.at(0), 0x654);
        assert_eq!((*context.at(2)).to, 0x333333);
        assert_eq!((*context.at(2)).entrypoint, 0x232323);
        assert_eq!((*context.at(2)).calldata.len(), 0x3);
        assert_eq!(*(*context.at(2)).calldata.at(0), 0xfff);
        assert_eq!(*(*context.at(2)).calldata.at(1), 0xbbb);
        assert_eq!(*(*context.at(2)).calldata.at(2), 0xccc);
    }
}
