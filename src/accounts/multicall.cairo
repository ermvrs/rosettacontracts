use core::panic_with_felt252;

use crate::accounts::types::{RosettanetMulticall};

pub fn prepare_multicall_context(calldata: Span<u128>) -> Span<RosettanetMulticall> {
    let mut calldata = calldata;
    // Remove function selector.
    let _: u128 = match calldata.pop_front() {
        Option::None => { 0 },
        Option::Some(val) => { *val }
    };

    let call_count: felt252 = u256 {
        high: *calldata.pop_front().unwrap(),
        low: *calldata.pop_front().unwrap()

    }.try_into().unwrap();

    let mut calls = ArrayTrait::<RosettanetMulticall>::new();

    let mut i = 0;
    loop {
        if (i == call_count) {
            break;
        }

        let to: felt252 = u256 {
                high: *calldata.pop_front().unwrap(),
                low: *calldata.pop_front().unwrap()

            }.try_into().unwrap();


        if (to == 0x0) {
            panic_with_felt252('multicall to wrong');
        }

        let entrypoint: felt252 = u256 {
                high: *calldata.pop_front().unwrap(),
                low: *calldata.pop_front().unwrap()
            }.try_into().unwrap();


        if (entrypoint == 0x0) {
            panic_with_felt252('multicall entry wrong');
        }

        let calldata_length: u64 = u256 {
            high: *calldata.pop_front().unwrap(),
            low: *calldata.pop_front().unwrap()
        }.try_into().unwrap();

        let mut inner_calldata: Array<felt252> = array![];
        let mut j = 0;
        loop {
            if (j == calldata_length) {
                break;
            }

            let value: felt252 = u256 {
                high: *calldata.pop_front().unwrap(),
                low: *calldata.pop_front().unwrap()
            }.try_into().unwrap();

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
            0x76971d7f,
            0x0,
            0x2,
            0x0,
            0x123123,
            0x0,
            0x456456,
            0x0,
            0x2,
            0x0,
            0x111,
            0x0,
            0x222,
            0x0,
            0x888888,
            0x0,
            0x999999,
            0x0,
            0x2,
            0x0,
            0x654,
            0x0,
            0x321
        ].span();

        let context = prepare_multicall_context(calldata);

        assert_eq!(context.len(), 2);
        assert_eq!((*context.at(0)).to, 0x123123);
        assert_eq!((*context.at(0)).entrypoint, 0x456456);
        assert_eq!((*context.at(0)).calldata.len(), 0x2);
        assert_eq!(*(*context.at(0)).calldata.at(0), 0x111);
        assert_eq!(*(*context.at(0)).calldata.at(1), 0x222);
        assert_eq!((*context.at(1)).to, 0x888888);
        assert_eq!((*context.at(1)).entrypoint, 0x999999);
        assert_eq!((*context.at(1)).calldata.len(), 0x2);
        assert_eq!(*(*context.at(1)).calldata.at(0), 0x654);
        assert_eq!(*(*context.at(1)).calldata.at(1), 0x321);
    }
}