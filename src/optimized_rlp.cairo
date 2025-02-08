#[derive(Drop, Copy, PartialEq)]
pub enum RLPError {
    EmptyInput,
    InputTooShort,
    PayloadTooLong,
}

#[derive(Drop, Copy, PartialEq)]
pub enum DataLength {
    Dynamic,
    Fixed
}

#[derive(Drop, Copy, Clone)]
pub struct RLPStringData {
    data: Span<u64>,
    length_type: DataLength,
    length: u64, // Byte length
}

pub fn u64_word(val: u64, prefix: u8) -> Span<u64> {
    let current_size: u8 = get_byte_size(val);
    if(current_size == 8) {
        return array![prefix.into(), val].span();
    }
    array![val + (prefix.into() * 256_u64 * 256_u64)].span()
}

// TODO: func for long strings

pub fn encode_short_string(input: u64) -> Result<Span<u64>, RLPError> {
    if(input < 0x80) {
        return Result::Ok(array![input].span());
    } else {
        let byte_size = get_byte_size(input);
        let prefix = 0x80_u8 + byte_size;
        return Result::Ok(u64_word(input, prefix));
    }
}

pub fn get_bit_size(mut value: u64) -> u8 {
    let mut bits = 0_u8;

    while value > 0 {
        bits += 1;
        value = value / 2;
    };

    bits
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
    use crate::optimized_rlp::{get_byte_size};
    use core::keccak;
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