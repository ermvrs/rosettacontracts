use crate::optimized_rlp::{compute_keccak};
use crate::constants::{POW_2_250};
use crate::utils::bits::{U256BitShift};

pub fn calculate_function_selectors(func: @ByteArray) -> (felt252, u32) {
    (calculate_sn_entrypoint(func), calculate_eth_function_selector(func))
}

fn calculate_sn_entrypoint(func: @ByteArray) -> felt252 {
    let name: @ByteArray = parse_function_name(func);

    let keccak_hash: u256 = compute_keccak(name);

    let (_, sn_keccak) =  DivRem::div_rem(keccak_hash, POW_2_250.try_into().unwrap());

    sn_keccak.try_into().unwrap()
}

fn parse_function_name(func: @ByteArray) -> @ByteArray {
    let mut name: ByteArray = Default::default();

    for i in 0..func.len() {
        match func.at(i) {
            Option::None => { break; },
            Option::Some(val) => {
                if(val == 0x28) {
                    name.append_byte(val);
                }
            }
        };
    };

    @name
}

fn calculate_eth_function_selector(func: @ByteArray) -> u32 {
    let keccak_hash: u256 = compute_keccak(func);

    let selector: u32 = U256BitShift::shr(keccak_hash, 224).try_into().unwrap();

    selector
}