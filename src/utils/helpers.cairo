use core::array::ArrayTrait;
use core::array::SpanTrait;
use core::cmp::min;
use core::hash::{HashStateExTrait, HashStateTrait};
use core::num::traits::SaturatingAdd;

use core::panic_with_felt252;
use core::pedersen::PedersenTrait;
use core::starknet::{EthAddress, ContractAddress, ClassHash};
use core::traits::TryInto;
use crate::utils::constants::{CONTRACT_ADDRESS_PREFIX, MAX_ADDRESS};
use crate::utils::constants::{POW_2, POW_256_1, POW_256_REV};
use crate::utils::array::{ArrayExtTrait};
use crate::utils::{U256TryIntoContractAddress, EthAddressIntoU256, BoolIntoNumeric};

/// Splits a u128 into two u64 parts, representing the high and low parts of the input.
///
/// # Arguments
/// * `input` - The u128 value to be split.
///
/// # Returns
/// A tuple containing two u64 values, where the first element is the high part of the input
/// and the second element is the low part of the input.
pub fn u128_split(input: u128) -> (u64, u64) {
    let (high, low) = core::integer::u128_safe_divmod(
        input, 0x10000000000000000_u128.try_into().unwrap()
    );

    (high.try_into().unwrap(), low.try_into().unwrap())
}

/// Computes the number of 32-byte words required to represent `size` bytes
///
/// # Arguments
/// * `size` - The size in bytes
///
/// # Returns
/// The number of 32-byte words required to represent `size` bytes
///
/// # Examples
/// bytes_32_words_size(2) = 1
/// bytes_32_words_size(34) = 2
#[inline(always)]
pub fn bytes_32_words_size(size: usize) -> usize {
    size.saturating_add(31) / 32
}

/// Computes 256 ** (16 - i) for 0 <= i <= 16.
pub fn pow256_rev(i: usize) -> u256 {
    if (i > 16) {
        panic_with_felt252('pow256_rev: i > 16');
    }
    let v = POW_256_REV.span().at(i);
    *v
}

/// Computes 2**pow for 0 <= pow < 128.
pub fn pow2(pow: usize) -> u128 {
    if (pow > 127) {
        return panic_with_felt252('pow2: pow >= 128');
    }
    let v = POW_2.span().at(pow);
    *v
}

/// Splits a u256 into `len` bytes, big-endian, and appends the result to `dst`.
pub fn split_word(mut value: u256, mut len: usize, ref dst: Array<u8>) {
    let word_le = split_word_le(value, len);
    let word_be = ArrayExtTrait::reverse(word_le.span());
    ArrayExtTrait::concat(ref dst, word_be.span());
}

/// Splits a u128 into `len` bytes in little-endian order and appends them to the destination array.
///
/// # Arguments
/// * `dest` - The destination array to append the bytes to
/// * `value` - The u128 value to split into bytes
/// * `len` - The number of bytes to split the value into
pub fn split_u128_le(ref dest: Array<u8>, mut value: u128, mut len: usize) {
    for _ in 0..len {
        dest.append((value % 256).try_into().unwrap());
        value /= 256;
    };
}

/// Splits a u256 into `len` bytes, little-endian, and returns the bytes array.
///
/// # Arguments
/// * `value` - The u256 value to be split.
/// * `len` - The number of bytes to split the value into.
///
/// # Returns
/// An `Array<u8>` containing the little-endian byte representation of the input value.
pub fn split_word_le(mut value: u256, mut len: usize) -> Array<u8> {
    let mut dst: Array<u8> = ArrayTrait::new();
    let low_len = min(len, 16);
    split_u128_le(ref dst, value.low, low_len);
    let high_len = min(len - low_len, 16);
    split_u128_le(ref dst, value.high, high_len);
    dst
}

/// Splits a u256 into 16 bytes, big-endian, and appends the result to `dst`.
///
/// # Arguments
/// * `value` - The u256 value to be split.
/// * `dst` - The destination array to append the bytes to.
pub fn split_word_128(value: u256, ref dst: Array<u8>) {
    split_word(value, 16, ref dst)
}

/// Converts a u256 to a bytes array represented by an array of u8 values in big-endian order.
///
/// # Arguments
/// * `value` - The u256 value to convert.
///
/// # Returns
/// An `Array<u8>` representing the big-endian byte representation of the input value.
pub fn u256_to_bytes_array(mut value: u256) -> Array<u8> {
    let mut bytes_arr: Array<u8> = ArrayTrait::new();
    // low part
    for _ in 0
        ..16_u8 {
            bytes_arr.append((value.low & 0xFF).try_into().unwrap());
            value.low /= 256;
        };

    // high part
    for _ in 0
        ..16_u8 {
            bytes_arr.append((value.high & 0xFF).try_into().unwrap());
            value.high /= 256;
        };

    // Reverse the array as memory is arranged in big endian order.
    let mut counter = bytes_arr.len();
    let mut bytes_arr_reversed: Array<u8> = ArrayTrait::new();
    while counter != 0 {
        bytes_arr_reversed.append(*bytes_arr[counter - 1]);
        counter -= 1;
    };
    bytes_arr_reversed
}


/// Computes the Starknet address for a given Kakarot address, EVM address, and class hash.
///
/// # Arguments
/// * `kakarot_address` - The Kakarot contract address.
/// * `evm_address` - The Ethereum address.
/// * `class_hash` - The class hash.
///
/// # Returns
/// A `ContractAddress` representing the computed Starknet address.
pub fn compute_starknet_address(
    kakarot_address: ContractAddress, evm_address: EthAddress, class_hash: ClassHash
) -> ContractAddress {
    // Deployer is always Kakarot (current contract)
    // pedersen(a1, a2, a3) is defined as:
    // pedersen(pedersen(pedersen(a1, a2), a3), len([a1, a2, a3]))
    // https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/hash_state.py#L6
    // https://github.com/xJonathanLEI/starknet-rs/blob/master/starknet-core/src/crypto.rs#L49
    // Constructor Calldata For an Account, the constructor calldata is:
    // [1, evm_address]
    let constructor_calldata_hash = PedersenTrait::new(0)
        .update_with(1)
        .update_with(evm_address)
        .update(2)
        .finalize();

    let hash = PedersenTrait::new(0)
        .update_with(CONTRACT_ADDRESS_PREFIX)
        .update_with(kakarot_address)
        .update_with(evm_address)
        .update_with(class_hash)
        .update_with(constructor_calldata_hash)
        .update(5)
        .finalize();

    let normalized_address: ContractAddress = (hash.into() & MAX_ADDRESS).try_into().unwrap();
    // We know this unwrap is safe, because of the above bitwise AND on 2 ** 251
    normalized_address
}
