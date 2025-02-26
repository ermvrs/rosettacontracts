use crate::utils::bytes::{Bytes, BytesTrait};
use crate::utils::bits::{most_significant_bit, get_bit_at};
use crate::constants::{FELT252_MAX};
use core::integer::BoundedInt;

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
    fn decode(ref self: EVMCalldata, types: Span<EVMTypes>) -> Span<felt252>; // Returns span of felt252 which directly will be passed to call_syscall
}

pub enum DecodingMethod {
    Basic,
    Dynamic
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
    //Int16,
    //Int32,
    //Int64,
    //Int128,
    Int256, // Decoded as i257
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
                EVMTypes::Int256 => { decode_int256(ref self) }
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

#[inline(always)]
fn decode_int8(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let u256_max: u256 = BoundedInt::<u256>::max();
    // TODO:
    //Minimum: -128 (0b10000000 or 0x80)
    //Maximum: 127 (0b01111111 or 0x7F)

    array![].span()
}

#[inline(always)]
fn decode_int256(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let msb_index: u8 = most_significant_bit(value).unwrap();
    let msb: bool = get_bit_at(value, msb_index);

    if(msb) {
        let u256_max: u256 = BoundedInt::<u256>::max();
        let value = u256_max - value;
        return array![value.low.into(), value.high.into(), msb.into()].span()
    } else {
        //TBD
    }
    


}



#[cfg(test)]
mod tests { 
    use crate::utils::decoder::{EVMCalldata, EVMTypesImpl, EVMTypes};
    use crate::utils::bytes::{Bytes, BytesTrait};
    use core::integer::BoundedInt;

    fn cd() -> EVMCalldata {

        let mut data: Bytes = BytesTrait::blank();

        data.append_u128(0b0);
        data.append_u128(0b1);

        EVMCalldata {
            offset: 0_usize,
            calldata: data
        }
    }

    #[test]
    fn test_decode_signature() {
        let mut calldata = cd();

        let decoded = calldata.decode(array![EVMTypes::Int8].span());
        println!("{:}", BoundedInt::<u256>::max());
        //assert_eq!(decoded.len(), 1);
        //assert_eq!(*decoded.at(0), 0x0);

    }
}