#[derive(Drop, Serde)]
pub struct EVMCalldata {
    calldata: ByteArray,
    offset: usize
}

pub trait AbiDecodeTrait {
    fn decode(ref self: EVMCalldata, evm_type: EVMTypes) -> Span<felt252>; // Returns span of felt252 which directly will be passed to call_syscall
}

pub enum EVMTypes {
    Uint8, 
    Uint16
}


impl EVMTypesImpl of AbiDecodeTrait {
    fn decode(ref self: EVMCalldata, evm_type: EVMTypes) -> Span<felt252> {
        match evm_type {
            EVMTypes::Uint8 => { decode_uint8(ref self) },
            EVMTypes::Uint16 => { decode_uint16(ref self) },
        }
    }
}

// Usage will be
// let x = EVMCalldata { calldata: ByteArray of evm calldata, offset: 0};
// let params_list = array xxx
// each param element calls x.decode(param) and result appended to sn_calldata

#[inline(always)]
fn decode_uint8(ref ctx: EVMCalldata) -> Span<felt252> {
    ctx.offset += 32;
    array![].span()
}

#[inline(always)]
fn decode_uint16(ref ctx: EVMCalldata) -> Span<felt252> {
    array![].span()
}