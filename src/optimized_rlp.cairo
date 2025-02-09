#[derive(Drop, Copy, PartialEq)]
pub enum RLPError {
    EmptyInput,
    InputTooShort,
    PayloadTooLong,
}

#[derive(Drop, Clone, PartialEq)]
pub enum RLPType {
    String,
    List,
}

#[generate_trait]
pub impl OptimizedRLPImpl of OptimizedRLPTrait {
    // Store string with length less than 32
    fn encode_short_string(input: felt252, len: usize) -> Result<@ByteArray, RLPError> {
        let mut output: ByteArray = Default::default();
        if len == 0 {
            output.append_word(0x80, 1);
        } else if len == 1 && input.into() < 0x80_u256 {
            output.append_word(input, 1);
        } else if len < 32 {
            let prefix = 0x80 + len;
            output.append_word(prefix.into(), 1);
            output.append_word(input, len);
        } else {
            // Error here
            panic!("Length too high");
        }

        Result::Ok(@output)
    }

    fn encode_bytearray(input: @ByteArray) -> Result<@ByteArray, RLPError> {
        let mut output: ByteArray = Default::default();
        let len = input.len();
        if len == 0 {
            output.append_word(0x80, 1); // TODO: use append_byte ?
        } else if len == 1 && ((input.at(0).unwrap()) < 0x80_u8) {
            output.append_word(input.at(0).unwrap().into(), 1); // TODO: use append_byte ?
        } else if len < 56 {
            let prefix = 0x80 + len;
            output.append_word(prefix.into(), 1); // TODO: use append_byte ?
            output.append(input);
        } else {
            let len_byte_size = get_byte_size(len.into());
            let prefix = 0xb7 + len_byte_size;
            let prefix_length = get_byte_size(prefix.into());
            output.append_word(prefix.into(), prefix_length.into());
            output.append_word(len.into(), len_byte_size.into());
            output.append(input);
        }

        Result::Ok(@output)
    }

    // Assuming all elements are already encoded rlp items
    // total_len is the sum of lengths of inputs
    // prefix can be used for ex eip1559 is 0x2
    // TODO COMPLETE LIST
    fn encode_as_list(mut inputs: Span<@ByteArray>, total_len: usize, prefix: u8) -> ByteArray {
        let mut output: ByteArray = Default::default();

        if(prefix > 0) {
            output.append_word(prefix.into(), 1);
        }

        let len = inputs.len();

        if len == 0 {
            output.append_word(0xc0, 1);
            return output;
        }

        if len > 55 {
            let len_byte_size = get_byte_size(len.into());
            let prefix = 0xf7 + len_byte_size;
            output.append_word(prefix.into(), get_byte_size(prefix.into()).into());
            output.append_word(len.into(), len_byte_size.into());
        } else {
            let prefix = 0xc0 + len;
            output.append_word(prefix.into(), 1);
        }

        while true {
            match inputs.pop_front() {
                Option::Some(input) => {
                    output.append(*input);
                },
                Option::None => {
                    break;
                }
            };
        };

        output

    }

    fn encode_list(input: @ByteArray) -> Result<@ByteArray, RLPError> {
        let mut output: ByteArray = Default::default();
        let len = input.len();
        if len == 0 {
            output.append_word(0xc0, 1);
        } else {
            let payload = Self::encode_bytearray(input).unwrap();
            let payload_len = payload.len();
            if payload_len > 55 {
                let len_byte_size = get_byte_size(payload_len.into());
                let prefix = 0xf7 + len_byte_size;
                output.append_word(prefix.into(), 1);
                output.append_word(payload_len.into(), len_byte_size.into());
            } else {
                let prefix = 0xc0 + payload_len;
                output.append_word(prefix.into(), 1);
            }

            output.append(input);
        }
        Result::Ok(@output)
    }
}

pub fn u64_word(val: u64, prefix: u8) -> Span<u64> {
    let current_size: u8 = get_byte_size(val);
    if(current_size == 8) {
        return array![prefix.into(), val].span();
    }
    array![val + (prefix.into() * 256_u64 * 256_u64)].span()
}


fn get_byte_size(mut value: u64) -> u8 {
    if value == 0 {
        return 1_u8;
    }

    let mut bytes = 0_u8;

    while value > 0 {
        bytes += 1;
        value = value / 256;  // Simulate `value >>= 8`
    };

    bytes
}


#[cfg(test)]
mod tests {
    use crate::optimized_rlp::{get_byte_size, OptimizedRLPTrait, OptimizedRLPImpl};
    use crate::accounts::encoding;
    use crate::accounts::utils;
    use crate::utils::bytes::{ByteArrayExTrait, U8SpanExTrait};
    use crate::utils::integer::{U256Trait};
    use alexandria_encoding::rlp::{RLPItem, RLPTrait};
    use core::keccak;

    #[test]
    fn compare_keccaks() {
        let calldata = array![0xdead, 0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff];
        let mut long_values = utils::merge_u256s(calldata.span(), array![0,1,0].span());
        let long_values_bytes = encoding::deserialize_u256_span(ref long_values);

        let actual_rlp = RLPItem::String(long_values_bytes);
        let actual_result = RLPTrait::encode(array![actual_rlp].span()).unwrap();

        let actual_keccak = actual_result.compute_keccak256_hash();

        let mut ba: ByteArray = Default::default();

        //ba.append_word(0x095ea7b3, 4); // todo: also test with initial bytes zero
        ba.append_word(0x00, 16);
        ba.append_word(0xdead, 16);
        ba.append_word(0xffffffffffffffffffffffffffffffff, 16);
        ba.append_word(0xffffffffffffffffffffffffffffffff, 16);

        let result = OptimizedRLPTrait::encode_bytearray(@ba).unwrap();

        let opt_keccak = keccak::compute_keccak_byte_array(result).reverse_endianness();

        assert_eq!(result.len(), actual_result.len());

        assert_eq!(opt_keccak, actual_keccak);
    }

    #[test]
    fn step_cost_actual_rlp_long_string() {
        let calldata = array![0x095ea7b3, 0xdead, 0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff];
        let mut long_values = utils::merge_u256s(calldata.span(), array![0,0,1,0].span());
        let long_values_bytes = encoding::deserialize_u256_span(ref long_values);

        let actual_rlp = RLPItem::String(long_values_bytes);
        let actual_result = RLPTrait::encode(array![actual_rlp].span()).unwrap();
    }

    #[test]
    fn step_cost_opt_rlp_long_string() {
        let mut ba: ByteArray = Default::default();

        ba.append_word(0x095ea7b3, 4); // todo: also test with initial bytes zero
        ba.append_word(0x00, 16);
        ba.append_word(0xdead, 16);
        ba.append_word(0xffffffffffffffffffffffffffffffff, 16);
        ba.append_word(0xffffffffffffffffffffffffffffffff, 16);

        let result = OptimizedRLPTrait::encode_bytearray(@ba).unwrap();
    }

    #[test]
    fn step_cost_actual_rlp() {
        let sampledata = 0xFFAABBCC;

        let sample_bytes = encoding::deserialize_bytes_non_zeroes(sampledata, 4);
        let actual_rlp = RLPItem::String(sample_bytes);
        let actual_result = RLPTrait::encode(array![actual_rlp].span()).unwrap();
    }

    #[test]
    fn step_cost_opt_rlp() {
        let sampledata = 0xFFAABBCC;
        let mut ba: ByteArray = Default::default();
        ba.append_word(sampledata, 4);

        let result = OptimizedRLPTrait::encode_bytearray(@ba).unwrap();
    }

    #[test]
    fn compare_rlp_results() {
        let sampledata = 0xFFAABBCC;

        let sample_bytes = encoding::deserialize_bytes_non_zeroes(sampledata, 4);
        let actual_rlp = RLPItem::String(sample_bytes);
        let actual_result = RLPTrait::encode(array![actual_rlp].span()).unwrap();

        let mut ba: ByteArray = Default::default();
        ba.append_word(sampledata, 4);

        let result = OptimizedRLPTrait::encode_bytearray(@ba).unwrap();

        assert_eq!(actual_result.len(), result.len());
        assert_eq!(*actual_result.at(0), result.at(0).unwrap());
        assert_eq!(*actual_result.at(1), result.at(1).unwrap());
        assert_eq!(*actual_result.at(2), result.at(2).unwrap());
    }

    #[test]
    fn test_rlp_encode_example_calldata() {
        let calldata = array![0x095ea7b3, 0xdead, 0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff];

        let mut ba: ByteArray = Default::default();

        ba.append_word(0x095ea7b3, 4); // todo: also test with initial bytes zero
        ba.append_word(0x00, 16);
        ba.append_word(0xdead, 16);
        ba.append_word(0xffffffffffffffffffffffffffffffff, 16);
        ba.append_word(0xffffffffffffffffffffffffffffffff, 16);

        assert_eq!(ba.len(), 68);

        let result = OptimizedRLPTrait::encode_bytearray(@ba).unwrap();

        assert_eq!(result.len(), 70);
        assert_eq!(result.at(0).unwrap(), 0xb8);
        assert_eq!(result.at(1).unwrap(), 68);
        assert_eq!(result.at(2).unwrap(), 0x09);
        assert_eq!(result.at(69).unwrap(), 0xFF);
    }

    #[test]
    fn test_rlp_encode_bytearray_very_long() {
        let result = OptimizedRLPTrait::encode_bytearray(@"TESTLONGSTRINGWITHLENGTHOFHIGHERTHAN56TESTESTESTAAAAAABCVCBCBveryTESTLONGSTRINGWITHLENGTHOFHIGHERTHAN56TESTESTESTAAAAAABCVCBCBveryTESTLONGSTRINGWITHLENGTHOFHIGHERTHAN56TESTESTESTAAAAAABCVCBCBveryTESTLONGSTRINGWITHLENGTHOFHIGHERTHAN56TESTESTESTAAAAAABCVCBCBveryTESTLONGSTRINGWITHLENGTHOFHIGHERTHAN56TESTESTESTAAAAAABCVCBCBvery").unwrap();
        // len 325
        assert_eq!(result.len(), 328);
        assert_eq!(result.at(0).unwrap(), 0xb9); // b7 + length of length
        assert_eq!(result.at(1).unwrap(), 0x01);
        assert_eq!(result.at(2).unwrap(), 0x45);
        assert_eq!(result.at(3).unwrap(), 0x54);
    }

    #[test]
    fn test_rlp_encode_bytearray_long() {
        let result = OptimizedRLPTrait::encode_bytearray(@"TESTLONGSTRINGWITHLENGTHOFHIGHERTHAN56TESTESTESTAAAAAABCVCBCB").unwrap(); // len 61

        assert_eq!(result.len(), 63);
        assert_eq!(result.at(0).unwrap(), 0xb8); // b7 + length of length
        assert_eq!(result.at(1).unwrap(), 61);
        assert_eq!(result.at(2).unwrap(), 0x54);
        assert_eq!(result.at(3).unwrap(), 0x45);
    }

    #[test]
    fn test_rlp_encode_bytearray_mid() {
        let result = OptimizedRLPTrait::encode_bytearray(@"TESTMIDSTRINGWITHLENGTHOFLOWERTHAN56FFAASDSASASDADASDAA").unwrap();

        assert_eq!(result.len(), 56);
        assert_eq!(result.at(0).unwrap(), 0x80_u8 + 55_u8);
        assert_eq!(result.at(1).unwrap(), 0x54);
        assert_eq!(result.at(2).unwrap(), 0x45);
        assert_eq!(result.at(3).unwrap(), 0x53);
    }

    #[test]
    fn test_rlp_encode_bytearray_low() {
        let result = OptimizedRLPTrait::encode_bytearray(@"A").unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result.at(0).unwrap(), 0x41);
    }

    #[test]
    fn test_rlp_encode_bytearray_empty() {
        let result = OptimizedRLPTrait::encode_bytearray(@"").unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result.at(0).unwrap(), 0x80);
    }

    #[test]
    fn test_rlp_short_string() {
        let data = 0xAF;

        let result = OptimizedRLPTrait::encode_short_string(data, 1).unwrap();

        assert_eq!(result.at(0).unwrap(), 0x81);
        assert_eq!(result.at(1).unwrap(), 0xAF);
    }

    #[test]
    fn test_rlp_short_string_lower() {
        let data = 0x7F;

        let result = OptimizedRLPTrait::encode_short_string(data, 1).unwrap();


        assert_eq!(result.at(0).unwrap(), 0x7F);
    }

    #[test]
    fn test_rlp_short_empty() {
        let result = OptimizedRLPTrait::encode_short_string(0x0, 0).unwrap(); // Still we need to pass smth as input

        assert_eq!(result.at(0).unwrap(), 0x80);
    }

    #[test]
    fn test_byte_size() {
        let byte_size = get_byte_size(65535_u64);  // 0xFFFF → 2 bytes needed

        assert_eq!(byte_size, 2);
    }

    #[test]
    fn test_keccak_example() {
        let mut input = array![
            0x0000000000000001,
            0x0000000000000002,
            0x0000000000000003,
            0x0000000000000004,
            0x0000000000000005,
            0x0000000000000006,
            0x0000000000000007,
            0x0000000000000008,
            0x0000000000000009,
            0x000000000000000a,
            0x000000000000000b,
            0x000000000000000c,
            0x000000000000000d,
            0x000000000000000e,
            0x000000000000000f,
            0x0000000000000010,
            0x0000000000000011,
        ];

        let keccak_result = keccak::cairo_keccak(ref input, 0, 0);
        assert_eq!(
            keccak_result,
            0x210740d45b1fe2ac908a497ef45509f55d291eebae35b254ff50ec1fc57832e8,
        );

        let mut input2 = array![
            0x1,
            0x2,
            0x3,
            0x4,
            0x5,
            0x6,
            0x7,
            0x8,
            0x9,
            0xa,
            0xb,
            0xc,
            0xd,
            0xe,
            0xf,
            0x10,
            0x11,
        ];

        let keccak_result2 = keccak::cairo_keccak(ref input2, 0, 0);
        assert_eq!(
            keccak_result2,
            0x210740d45b1fe2ac908a497ef45509f55d291eebae35b254ff50ec1fc57832e8,
        );
    }
}