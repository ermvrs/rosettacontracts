pub mod decoder;
pub mod bytes;

use core::integer::{u128_byte_reverse};

use crate::constants::{POW_2_250, POW_2_8, POW_2_16, POW_2_24};
use crate::optimized_rlp::{compute_keccak, get_byte_size_u128};

pub fn u128_split(input: u128) -> (u64, u64) {
    let (high, low) = core::integer::u128_safe_divmod(
        input, 0x10000000000000000_u128.try_into().unwrap()
    );

    (high.try_into().unwrap(), low.try_into().unwrap())
}

pub fn parse_function_name(full_signature: @ByteArray) -> @ByteArray {
    let mut name: ByteArray = Default::default();

    let mut i = 0;
    loop {
        let val = full_signature.at(i).unwrap();
        if (val == 0x28) {
            break;
        }
        name.append_word(val.into(), 1);
        i += 1;
    };

    @name
}

fn function_signature_from_felt_span(fn_name: Span<felt252>) -> @ByteArray {
    let mut fn_name = fn_name;
    let mut output: ByteArray = Default::default();
    loop {
        match fn_name.pop_front() {
            Option::None => { break; },
            Option::Some(val) => {
                let elem: u256 = (*val).into();
                if elem.high > 0 {
                    output.append_word(elem.high.into(), get_byte_size_u128(elem.high).into());
                    output.append_word(elem.low.into(), 16);
                } else {
                    output.append_word(elem.low.into(), get_byte_size_u128(elem.low).into());
                }
            }
        };
    };

    @output
}

pub fn calculate_sn_entrypoint(fn_name: Span<felt252>) -> felt252 {
    // let mut func_clone = func;
    let complete_fn_signature: @ByteArray = function_signature_from_felt_span(fn_name);

    let func_name: @ByteArray = parse_function_name(complete_fn_signature);

    let keccak_hash: u256 = compute_keccak(func_name); // full name

    let (_, sn_keccak) = DivRem::div_rem(keccak_hash, POW_2_250.try_into().unwrap());

    sn_keccak.try_into().unwrap()
}

pub fn eth_selector_from_span(selector: Span<u8>) -> felt252 {
    let value: u128 = (*selector.at(3)).into()
        + ((*selector.at(2)).into() * POW_2_8)
        + ((*selector.at(1)).into() * POW_2_16)
        + ((*selector.at(0)).into() * POW_2_24);

    value.into()
}

pub fn eth_function_signature_from_felts(func: Span<felt252>) -> felt252 {
    let function_signature: @ByteArray = function_signature_from_felt_span(func);
    let keccak_hash: u256 = compute_keccak(function_signature);
    let mut ba = Default::default();
    ba.append_word(keccak_hash.high.into(), 16);

    eth_selector_from_span(
        array![ba.at(0).unwrap(), ba.at(1).unwrap(), ba.at(2).unwrap(), ba.at(3).unwrap()].span()
    )
}


#[generate_trait]
pub impl U256Impl of U256Trait {
    /// Splits an u256 into 4 little endian u64.
    /// Returns ((high_high, high_low),(low_high, low_low))
    fn split_into_u64_le(self: u256) -> ((u64, u64), (u64, u64)) {
        let low_le = u128_byte_reverse(self.low);
        let high_le = u128_byte_reverse(self.high);
        (u128_split(high_le), u128_split(low_le))
    }

    /// Reverse the endianness of an u256
    fn reverse_endianness(self: u256) -> u256 {
        let new_low = u128_byte_reverse(self.high);
        let new_high = u128_byte_reverse(self.low);
        u256 { low: new_low, high: new_high }
    }
}
