use crate::utils::bytes::{Bytes, BytesTrait};
use crate::utils::bits::{get_bit_at, U256BitShift};
use crate::constants::{FELT252_MAX};
use core::num::traits::Bounded;
use core::traits::{DivRem};

#[derive(Serde, Copy, Drop)]
pub struct i257 {
    abs: u256,
    is_negative: bool,
}

#[derive(Drop, Serde)]
pub struct EVMCalldata {
    calldata: Bytes,
    offset: usize
}

pub trait AbiDecodeTrait {
    fn decode(
        ref self: EVMCalldata, types: Span<EVMTypes>
    ) -> Span<felt252>; // Returns span of felt252 which directly will be passed to call_syscall
}

// Tuples can be decoded like basic types in order
#[derive(Drop, Serde)]
pub enum EVMTypes {
    //Tuple: Span<EVMTypes>,
    //Array: Span<EVMTypes>,
    FunctionSignature,
    Address,
    Bool,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
    Int8,
    Int16,
    Int32,
    Int64,
    Int128,
    Int256, // Decoded as i257 Because there is no i256 type in cairo. Closest is i257
    Bytes1,
    Bytes2,
    Bytes3,
    Bytes4,
    Bytes5,
    Bytes6,
    Bytes7,
    Bytes8,
    Bytes9,
    Bytes10,
    Bytes11,
    Bytes12,
    Bytes13,
    Bytes14,
    Bytes15,
    Bytes16,
    Bytes17,
    Bytes18,
    Bytes19,
    Bytes20,
    Bytes21,
    Bytes22,
    Bytes23,
    Bytes24,
    Bytes25,
    Bytes26,
    Bytes27,
    Bytes28,
    Bytes29,
    Bytes30,
    Bytes31,
    Bytes32, // Decoded as serialized ByteArray
    Bytes,
    //String, // Same as bytes
// Also fixed bytes too

}


impl EVMTypesImpl of AbiDecodeTrait {
    fn decode(ref self: EVMCalldata, types: Span<EVMTypes>) -> Span<felt252> {
        let mut decoded = array![];

        for evm_type in types {
            let decoded_type = match evm_type {
                //EVMTypes::Tuple(tuple_types) => { self.decode(*tuple_types) },
                //EVMTypes::Array(array_types) => {decode_address(ref self)},
                EVMTypes::FunctionSignature => { decode_function_signature(ref self) },
                EVMTypes::Address => { decode_address(ref self) },
                EVMTypes::Bool => { decode_bool(ref self) },
                EVMTypes::Uint8 => { decode_uint8(ref self) },
                EVMTypes::Uint16 => { decode_uint16(ref self) },
                EVMTypes::Uint32 => { decode_uint32(ref self) },
                EVMTypes::Uint64 => { decode_uint64(ref self) },
                EVMTypes::Uint128 => { decode_uint128(ref self) },
                EVMTypes::Uint256 => { decode_uint256(ref self) },
                EVMTypes::Int8 => { decode_int8(ref self) },
                EVMTypes::Int16 => { decode_int16(ref self) },
                EVMTypes::Int32 => { decode_int32(ref self) },
                EVMTypes::Int64 => { decode_int64(ref self) },
                EVMTypes::Int128 => { decode_int128(ref self) },
                EVMTypes::Int256 => { decode_int256(ref self) },
                EVMTypes::Bytes1 => { decode_fixed_bytes(ref self, 1_usize) },
                EVMTypes::Bytes2 => { decode_fixed_bytes(ref self, 2_usize) },
                EVMTypes::Bytes3 => { decode_fixed_bytes(ref self, 3_usize) },
                EVMTypes::Bytes4 => { decode_fixed_bytes(ref self, 4_usize) },
                EVMTypes::Bytes5 => { decode_fixed_bytes(ref self, 5_usize) },
                EVMTypes::Bytes6 => { decode_fixed_bytes(ref self, 6_usize) },
                EVMTypes::Bytes7 => { decode_fixed_bytes(ref self, 7_usize) },
                EVMTypes::Bytes8 => { decode_fixed_bytes(ref self, 8_usize) },
                EVMTypes::Bytes9 => { decode_fixed_bytes(ref self, 9_usize) },
                EVMTypes::Bytes10 => { decode_fixed_bytes(ref self, 10_usize) },
                EVMTypes::Bytes11 => { decode_fixed_bytes(ref self, 11_usize) },
                EVMTypes::Bytes12 => { decode_fixed_bytes(ref self, 12_usize) },
                EVMTypes::Bytes13 => { decode_fixed_bytes(ref self, 13_usize) },
                EVMTypes::Bytes14 => { decode_fixed_bytes(ref self, 14_usize) },
                EVMTypes::Bytes15 => { decode_fixed_bytes(ref self, 15_usize) },
                EVMTypes::Bytes16 => { decode_fixed_bytes(ref self, 16_usize) },
                EVMTypes::Bytes17 => { decode_fixed_bytes(ref self, 17_usize) },
                EVMTypes::Bytes18 => { decode_fixed_bytes(ref self, 18_usize) },
                EVMTypes::Bytes19 => { decode_fixed_bytes(ref self, 19_usize) },
                EVMTypes::Bytes20 => { decode_fixed_bytes(ref self, 20_usize) },
                EVMTypes::Bytes21 => { decode_fixed_bytes(ref self, 21_usize) },
                EVMTypes::Bytes22 => { decode_fixed_bytes(ref self, 22_usize) },
                EVMTypes::Bytes23 => { decode_fixed_bytes(ref self, 23_usize) },
                EVMTypes::Bytes24 => { decode_fixed_bytes(ref self, 24_usize) },
                EVMTypes::Bytes25 => { decode_fixed_bytes(ref self, 25_usize) },
                EVMTypes::Bytes26 => { decode_fixed_bytes(ref self, 26_usize) },
                EVMTypes::Bytes27 => { decode_fixed_bytes(ref self, 27_usize) },
                EVMTypes::Bytes28 => { decode_fixed_bytes(ref self, 28_usize) },
                EVMTypes::Bytes29 => { decode_fixed_bytes(ref self, 29_usize) },
                EVMTypes::Bytes30 => { decode_fixed_bytes(ref self, 30_usize) },
                EVMTypes::Bytes31 => { decode_fixed_bytes(ref self, 31_usize) },
                EVMTypes::Bytes32 => { decode_bytes_32(ref self) },
                EVMTypes::Bytes => { decode_bytes(ref self) },
            };
            decoded.append_span(decoded_type);
        };

        decoded.span()
    }
}

// Usage will be
// let x = EVMCalldata { calldata: ByteArray of evm calldata, offset: 0};
// let params_list = array xxx
// each param element calls x.decode(param) and result appended to sn_calldata

fn decode_bytes(ref ctx: EVMCalldata) -> Span<felt252> {
    let (defer_offset, data_start_offset) = ctx.calldata.read_u256(ctx.offset); // We will move back to defer_offset after complete reading this dynamic type
    ctx.offset = data_start_offset.try_into().unwrap(); // Data start offset has to be lower than u32 range. TODO: Add check?
    let (new_offset, items_length) = ctx.calldata.read_u256(ctx.offset); // length of bytes
    ctx.offset = new_offset;

    let mut ba: ByteArray = Default::default();

    let (slot_count, last_slot_bytes) = DivRem::<u256>::div_rem(items_length, 32);

    let mut curr_slot_idx = 0;
    while curr_slot_idx < slot_count {
        let (new_offset, current_slot) = ctx.calldata.read_u256(ctx.offset);
        ctx.offset = new_offset;

        ba.append_word(current_slot.high.into(), 16);
        ba.append_word(current_slot.low.into(), 16);

        curr_slot_idx += 1;
    };

    // Append last bytes
    if(last_slot_bytes > 0) {
        let (new_offset, last_slot) = ctx.calldata.read_u256(ctx.offset);
        ctx.offset = new_offset;
    
        let last_word = U256BitShift::shr(last_slot, 256 - (last_slot_bytes * 8));
        ba.append_word(last_word.try_into().unwrap(), last_slot_bytes.try_into().unwrap()); // We can assume try_into is safe because we shifted bits line above.
    }
    ctx.offset = defer_offset;

    let mut serialized = array![];
    ba.serialize(ref serialized);
    serialized.span()
}

#[inline(always)]
fn decode_bytes_32(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let complete_word = U256BitShift::shr(value, 8); // This is 31 byte
    let pending_byte = U256BitShift::shr(value, 248); // This is first byte
    array![0x1, complete_word.try_into().unwrap(), pending_byte.try_into().unwrap(), 0x1].span()
}

// TODO: ensure bytes order? Maybe its better to shl for bytes32 ???

#[inline(always)]
fn decode_fixed_bytes(ref ctx: EVMCalldata, size: usize) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let value = U256BitShift::shr(value, ((32_usize - size) * 8).into());

    array![value.try_into().unwrap()].span()
}

fn decode_tuple(ref ctx: EVMCalldata, types: Span<EVMTypes>) -> Span<felt252> {
    ctx.decode(types)
}

#[inline(always)]
fn decode_function_signature(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u32(ctx.offset);
    ctx.offset = new_offset;
    array![value.into()].span()
}

#[inline(always)]
fn decode_address(ref ctx: EVMCalldata) -> Span<felt252> {
    // TODO
    array![].span()
}

#[inline(always)]
fn decode_bool(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint8(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint16(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint32(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint64(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint128(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint256(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.low.into(), value.high.into()].span()
}

//TODO: int8 to int 128 functions have same functionility. But they are seperated
// Because we may add range checks later
#[inline(always)]
fn decode_int8(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let msb: bool = get_bit_at(value, 255);
    if (msb) {
        let u256_max: u256 = Bounded::MAX;
        let value = (u256_max - value) + 1; // Absolute value

        let sn_value = FELT252_MAX.into() - value + 1;

        array![sn_value.try_into().unwrap()].span()
    } else {
        array![value.try_into().unwrap()].span()
    }
}

#[inline(always)]
fn decode_int16(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let msb: bool = get_bit_at(value, 255);
    if (msb) {
        let u256_max: u256 = Bounded::MAX;
        let value = (u256_max - value) + 1; // Absolute value

        let sn_value = FELT252_MAX.into() - value + 1;

        array![sn_value.try_into().unwrap()].span()
    } else {
        array![value.try_into().unwrap()].span()
    }
}

#[inline(always)]
fn decode_int32(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let msb: bool = get_bit_at(value, 255);
    if (msb) {
        let u256_max: u256 = Bounded::MAX;
        let value = (u256_max - value) + 1; // Absolute value

        let sn_value = FELT252_MAX.into() - value + 1;

        array![sn_value.try_into().unwrap()].span()
    } else {
        array![value.try_into().unwrap()].span()
    }
}

#[inline(always)]
fn decode_int64(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let msb: bool = get_bit_at(value, 255);
    if (msb) {
        let u256_max: u256 = Bounded::MAX;
        let value = (u256_max - value) + 1; // Absolute value

        let sn_value = FELT252_MAX.into() - value + 1;

        array![sn_value.try_into().unwrap()].span()
    } else {
        array![value.try_into().unwrap()].span()
    }
}

#[inline(always)]
fn decode_int128(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let msb: bool = get_bit_at(value, 255);
    if (msb) {
        let u256_max: u256 = Bounded::MAX;
        let value = (u256_max - value) + 1; // Absolute value

        let sn_value = FELT252_MAX.into() - value + 1;

        array![sn_value.try_into().unwrap()].span()
    } else {
        array![value.try_into().unwrap()].span()
    }
}

#[inline(always)]
fn decode_int256(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    if (value == 0) {
        return array![0x0, 0x0, 0x0].span();
    }
    let msb: bool = get_bit_at(value, 255); // TBD

    if (msb) {
        let u256_max: u256 = Bounded::MAX;
        let value = (u256_max - value) + 1; // Because zero is msb == false
        return array![value.low.into(), value.high.into(), msb.into()].span();
    } else {
        return array![value.low.into(), value.high.into(), msb.into()].span();
    }
}


#[cfg(test)]
mod tests {
    use crate::utils::decoder::{EVMCalldata, EVMTypesImpl, EVMTypes};
    use crate::utils::bytes::{Bytes, BytesTrait};

    fn cd(mut data: Bytes) -> EVMCalldata {
        EVMCalldata { offset: 0_usize, calldata: data }
    }

    #[test]
    fn test_decode_bytes_one_full_slot() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0xffffffffffffffffffaaaaaaaaaaaaaaaaaaafffffffffffffffffafafafaffa);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes].span());
        assert_eq!(*decoded.at(0), 0x1);
        assert_eq!(*decoded.at(1), 0xffffffffffffffffffaaaaaaaaaaaaaaaaaaafffffffffffffffffafafafaf);
        assert_eq!(*decoded.at(2), 0xfa);
        assert_eq!(*decoded.at(3), 0x1);
    }

    #[test]
    fn test_decode_bytes_one_slot() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000003);
        data.append_u256(0xffaabb0000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes].span());
        assert_eq!(*decoded.at(0), 0x0);
        assert_eq!(*decoded.at(1), 0xffaabb);
        assert_eq!(*decoded.at(2), 0x3);
    }

    #[test]
    fn test_decode_bytes() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000039);
        data.append_u256(0xffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaa);
        data.append_u256(0xbbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabb00000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes].span());
        assert_eq!(*decoded.at(0), 0x1);
        assert_eq!(*decoded.at(1), 0xffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbff);
        assert_eq!(*decoded.at(2), 0xaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabb);
        assert_eq!(*decoded.at(3), 0x1a);
    }

    #[test]
    fn test_decode_bytes32_zeroes() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes32].span());
        assert_eq!(*decoded.at(0), 0x1);
        assert_eq!(*decoded.at(1), 0x000fffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        assert_eq!(*decoded.at(2), 0x00);
        assert_eq!(*decoded.at(3), 0x1);
    }

    #[test]
    fn test_decode_bytes32() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes32].span());
        assert_eq!(*decoded.at(0), 0x1);
        assert_eq!(
            *decoded.at(1), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        );
        assert_eq!(*decoded.at(2), 0xff);
        assert_eq!(*decoded.at(3), 0x1);
    }

    #[test]
    fn test_decode_bytes2() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xff22000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes2].span());
        assert_eq!(*decoded.at(0), 0xff22);
    }

    #[test]
    fn test_decode_bytes31() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xff22000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes31].span());
        assert_eq!(
            *decoded.at(0), 0xff220000000000000000000000000000000000000000000000000000000000
        );
    }

    #[test]
    fn test_decode_bytes2_zero() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0022000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes2].span());
        assert_eq!(*decoded.at(0), 0x0022);
    }

    #[test]
    fn test_decode_int256_neg() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffce);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int256].span());
        assert_eq!(*decoded.at(0), 50);
        assert_eq!(*decoded.at(1), 0);
        assert_eq!(*decoded.at(2), 0x1);
    }

    #[test]
    fn test_decode_int256_pos() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000003c);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int256].span());
        assert_eq!(*decoded.at(0), 60);
        assert_eq!(*decoded.at(1), 0);
        assert_eq!(*decoded.at(2), 0x0);
    }

    #[test]
    fn test_decode_int256_zero() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int256].span());
        assert_eq!(*decoded.at(0), 0);
        assert_eq!(*decoded.at(1), 0);
        assert_eq!(*decoded.at(2), 0x0);
    }

    #[test]
    fn test_decode_int8_neg() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int8].span());
        assert_eq!(*decoded.at(0), -5);
    }

    #[test]
    fn test_decode_int8_pos() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000005);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int8].span());
        assert_eq!(*decoded.at(0), 5);
    }

    #[test]
    fn test_decode_int8_zero() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int8].span());
        assert_eq!(*decoded.at(0), 0);
    }
}
