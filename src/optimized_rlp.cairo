use core::array::ArrayTrait;

fn encode_string(data: u256) -> Array<u64> {
    let mut encoded = ArrayTrait::<u64>::new();
    let mut byte_array = ArrayTrait::<u8>::new();
    let mut temp_data: u256 = data;
    
    while temp_data > 0 {
        byte_array.append((temp_data % 256).try_into().unwrap());
        temp_data = temp_data / 256;
    };
    
    
    let length = byte_array.len();
    if length == 1 && (*byte_array.at(0)) < 128 {
        // Single byte < 128 is encoded as itself
        encoded.append((*byte_array.at(0)).into());
    } else if length <= 55 {
        // Short string: 0x80 + length followed by the string
        encoded.append((0x80 + length).into());
        for byte in byte_array.span() {
            encoded.append((*byte).into());
        };
    } else {
        // Long string: 0xb7 + length of length, followed by length, followed by string
        let mut length_bytes = ArrayTrait::<u8>::new();
        let mut len_temp = length;
        while len_temp > 0 {
            length_bytes.append((len_temp % 256).try_into().unwrap());
            len_temp = len_temp / 256;
        };
        
        
        encoded.append((0xb7 + length_bytes.len()).into());
        for byte in length_bytes.span() {
            encoded.append((*byte).into());
        };
        for byte in byte_array.span() {
            encoded.append((*byte).into());
        };
    }
    encoded
}

#[cfg(test)]
mod tests {
    use crate::optimized_rlp::{encode_string};
    use alexandria_encoding::rlp::{RLPItem, RLPTrait};
    use core::array::ArrayTrait;

    #[test]
    fn test_opt_rlp() {
        let data = 0x123123;

        let result = encode_string(data.into());
        
        assert_eq!(result, array![0xc483123123]);
    }
}