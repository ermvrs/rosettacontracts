use core::panic_with_felt252;

use crate::accounts::types::{RosettanetMulticall};

pub fn prepare_multicall_context(calldata: Span<felt252>) -> Span<RosettanetMulticall> {
    let mut calldata = calldata;
    // Remove function selector.
    let _: felt252 = match calldata.pop_front() {
        Option::None => { 0 },
        Option::Some(val) => { *val }
    };

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
