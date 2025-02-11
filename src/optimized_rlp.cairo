use core::keccak;
use crate::utils::integer::{U256Trait};

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

    // Works good
    fn encode_bytearray(input: @ByteArray) -> Result<@ByteArray, RLPError> {
        let mut output: ByteArray = Default::default();
        let len = input.len();
        if len == 0 {
            output.append_word(0x80, 1); // TODO: use append_byte ?
        } else if len == 1 && ((input.at(0).unwrap()) == 0_u8){
            output.append_word(0x80, 1); 
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
    fn encode_as_list(mut inputs: Span<@ByteArray>, total_len: usize, prefix: u8) -> @ByteArray {
        let mut output: ByteArray = Default::default();

        if(prefix > 0) {
            output.append_word(prefix.into(), 1);
        }

        if total_len == 0 {
            output.append_word(0xc0, 1);
            return @output;
        }

        if total_len > 55 {
            let len_byte_size = get_byte_size(total_len.into());
            let prefix = 0xf7 + len_byte_size;
            output.append_word(prefix.into(), get_byte_size(prefix.into()).into());
            output.append_word(total_len.into(), len_byte_size.into());
        } else {
            let prefix = 0xc0 + total_len;
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

        @output

    }
}

pub fn u256_to_rlp_input(input: u256) -> @ByteArray {
    let mut rlp_input: ByteArray = Default::default();
    if input.high > 0 {
        rlp_input.append_word(input.high.into(), get_byte_size_u128(input.high).into());
        rlp_input.append_word(input.low.into(), 16);
    } else {
        rlp_input.append_word(input.low.into(), get_byte_size_u128(input.low).into());
    }

    @rlp_input
}

pub fn compute_keccak(input: @ByteArray) -> u256 {
    keccak::compute_keccak_byte_array(input).reverse_endianness()
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

fn get_byte_size_u128(mut value: u128) -> u32 {
    if value == 0 {
        return 1_u32;
    }

    let mut bytes = 0_u32;

    while value > 0 {
        bytes += 1;
        value = value / 256;
    };

    bytes
}


#[cfg(test)]
mod tests {
    use crate::optimized_rlp::{get_byte_size, OptimizedRLPTrait, OptimizedRLPImpl, compute_keccak};
    use crate::accounts::encoding;
    use crate::accounts::utils;
    use crate::utils::bytes::{U8SpanExTrait};
    use crate::utils::integer::{U256Trait};
    use alexandria_encoding::rlp::{RLPItem, RLPTrait};
    use core::keccak;

    #[test]
    fn compare_rlp_results_legacy_tx_with_calldata() {
        let tx = encoding::LegacyTransaction {
            chain_id: 0x1,
            nonce: 0x1,
            gas_limit: 0x5208,
            gas_price: 0x3b9aca00,
            value: 0xde0b6b3a7640000,
            to: 0x742d35cc6634c0532925a3b844bc454e4438f44e.try_into().unwrap(),
            input: array![0xAB, 0xCA, 0xBC,0xAB, 0xCA, 0xBC, 0x00, 0x00, 0x00, 0x1].span(),
        };

        let actual_result: Span<u8> = encoding::rlp_encode_legacy(tx);

        let nonce = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let gas_price = OptimizedRLPTrait::encode_short_string(0x3b9aca00, 4).unwrap();
        let gas_limit = OptimizedRLPTrait::encode_short_string(0x5208, 2).unwrap();
        let to = OptimizedRLPTrait::encode_short_string(0x742d35cc6634c0532925a3b844bc454e4438f44e, 20).unwrap(); // try with address with init zeros
        let value = OptimizedRLPTrait::encode_short_string(0xde0b6b3a7640000, 8).unwrap();
        let mut cd: ByteArray = Default::default();
        cd.append_word(0xABCABCABCABC, 6);
        cd.append_word(0x1, 4);
        let data = OptimizedRLPTrait::encode_bytearray(@cd).unwrap();
        let chain_id = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let empty = OptimizedRLPTrait::encode_short_string(0x0, 0).unwrap();

        let total_len = nonce.len() + gas_price.len() + gas_limit.len() + to.len() + value.len() + data.len() + chain_id.len() + empty.len() + empty.len();
        let result = OptimizedRLPTrait::encode_as_list(array![nonce, gas_price, gas_limit, to, value, data, chain_id, empty, empty].span(), total_len, 0);

        assert_eq!(actual_result.len(), result.len());

        let mut i = 0;

        while i < actual_result.len() {
            assert_eq!(*actual_result.at(i), result.at(i).unwrap());
            i += 1;
        };

        let actual_tx_hash = encoding::calculate_tx_hash(actual_result);
        let tx_hash = compute_keccak(result);

        assert_eq!(actual_tx_hash, tx_hash);
    }

    #[test]
    fn test_rlp_encode_legacy_tx_calldata_long() {
        let nonce = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let max_priority_fee_per_gas = OptimizedRLPTrait::encode_short_string(0x3b9aca00, 4).unwrap();
        let max_fee_per_gas = OptimizedRLPTrait::encode_short_string(0x3b9aca00, 4).unwrap();
        let gas_limit = OptimizedRLPTrait::encode_short_string(0x5208, 2).unwrap();
        let to = OptimizedRLPTrait::encode_short_string(0x000035cc6634c0532925a3b844bc454e4438f44e, 20).unwrap(); // try with address with init zeros
        let value = OptimizedRLPTrait::encode_short_string(0xde0b6b3a7640000, 8).unwrap();
        let chain_id = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let access_list = OptimizedRLPTrait::encode_as_list(array![].span(), 0, 0);

        let mut ba: ByteArray = Default::default();

        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);
        ba.append_word(0xFFF, 16);

        let calldata = OptimizedRLPTrait::encode_bytearray(@ba).unwrap();
        let total_len = nonce.len() + max_priority_fee_per_gas.len() + max_fee_per_gas.len() + gas_limit.len() + to.len() + value.len() + calldata.len() + chain_id.len() + access_list.len();
        let result = OptimizedRLPTrait::encode_as_list(array![chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, calldata, access_list].span(), total_len, 0x2);

        assert_eq!(result.len(), 517);
    }

    #[test]
    fn compare_rlp_encode_actual_eip1559_tx_no_calldata() {
        let tx = encoding::Eip1559Transaction {
            chain_id: 0x1,
            nonce: 0x1,
            gas_limit: 0x5208,
            max_priority_fee_per_gas: 0x3b9aca00,
            max_fee_per_gas: 0x3b9aca00, 
            value: 0xde0b6b3a7640000,
            to: 0x000035cc6634c0532925a3b844bc454e4438f44e.try_into().unwrap(),
            input: array![].span(),
            access_list: array![].span()
        };

        let actual_result: Span<u8> = encoding::rlp_encode_eip1559(tx);

        let nonce = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let max_priority_fee_per_gas = OptimizedRLPTrait::encode_short_string(0x3b9aca00, 4).unwrap();
        let max_fee_per_gas = OptimizedRLPTrait::encode_short_string(0x3b9aca00, 4).unwrap();
        let gas_limit = OptimizedRLPTrait::encode_short_string(0x5208, 2).unwrap();
        let to = OptimizedRLPTrait::encode_short_string(0x000035cc6634c0532925a3b844bc454e4438f44e, 20).unwrap(); // try with address with init zeros
        let value = OptimizedRLPTrait::encode_short_string(0xde0b6b3a7640000, 8).unwrap();
        let data = OptimizedRLPTrait::encode_short_string(0x0, 0).unwrap();
        let chain_id = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let access_list = OptimizedRLPTrait::encode_as_list(array![].span(), 0, 0);

        let total_len = nonce.len() + max_priority_fee_per_gas.len() + max_fee_per_gas.len() + gas_limit.len() + to.len() + value.len() + data.len() + chain_id.len() + access_list.len();
        let result = OptimizedRLPTrait::encode_as_list(array![chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list].span(), total_len, 0x2);
        
        assert_eq!(actual_result.len(), result.len());

        assert_eq!(*actual_result.at(0), result.at(0).unwrap());
        assert_eq!(*actual_result.at(1), result.at(1).unwrap());
        assert_eq!(*actual_result.at(2), result.at(2).unwrap());
        assert_eq!(*actual_result.at(3), result.at(3).unwrap());
        assert_eq!(*actual_result.at(4), result.at(4).unwrap());
        assert_eq!(*actual_result.at(5), result.at(5).unwrap());
    }

    #[test]
    fn test_rlp_encode_eip1559_tx_no_calldata() {
        let nonce = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let max_priority_fee_per_gas = OptimizedRLPTrait::encode_short_string(0x3b9aca00, 4).unwrap();
        let max_fee_per_gas = OptimizedRLPTrait::encode_short_string(0x3b9aca00, 4).unwrap();
        let gas_limit = OptimizedRLPTrait::encode_short_string(0x5208, 2).unwrap();
        let to = OptimizedRLPTrait::encode_short_string(0x000035cc6634c0532925a3b844bc454e4438f44e, 20).unwrap(); // try with address with init zeros
        let value = OptimizedRLPTrait::encode_short_string(0xde0b6b3a7640000, 8).unwrap();
        let data = OptimizedRLPTrait::encode_short_string(0x0, 0).unwrap();
        let chain_id = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let access_list = OptimizedRLPTrait::encode_as_list(array![].span(), 0, 0);

        let total_len = nonce.len() + max_priority_fee_per_gas.len() + max_fee_per_gas.len() + gas_limit.len() + to.len() + value.len() + data.len() + chain_id.len() + access_list.len();
        let result = OptimizedRLPTrait::encode_as_list(array![chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list].span(), total_len, 0x2);
        assert_eq!(total_len, 47);
        assert_eq!(result.len(), 49);

        assert_eq!(result.at(0).unwrap(), 0x02);
        assert_eq!(result.at(1).unwrap(), 0xef);
        assert_eq!(result.at(2).unwrap(), 0x01);
        assert_eq!(result.at(3).unwrap(), 0x01);
        assert_eq!(result.at(4).unwrap(), 0x84);
        assert_eq!(result.at(48).unwrap(), 0xc0);
    }
 
    #[test]
    fn compare_rlp_encode_actual_legacy_tx_no_calldata() {
        let tx = encoding::LegacyTransaction {
            chain_id: 0x1,
            nonce: 0x1,
            gas_limit: 0x5208,
            gas_price: 0x3b9aca00,
            value: 0xde0b6b3a7640000,
            to: 0x742d35cc6634c0532925a3b844bc454e4438f44e.try_into().unwrap(),
            input: array![].span(),
        };

        let actual_result: Span<u8> = encoding::rlp_encode_legacy(tx);

        let nonce = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let gas_price = OptimizedRLPTrait::encode_short_string(0x3b9aca00, 4).unwrap();
        let gas_limit = OptimizedRLPTrait::encode_short_string(0x5208, 2).unwrap();
        let to = OptimizedRLPTrait::encode_short_string(0x742d35cc6634c0532925a3b844bc454e4438f44e, 20).unwrap(); // try with address with init zeros
        let value = OptimizedRLPTrait::encode_short_string(0xde0b6b3a7640000, 8).unwrap();
        let data = OptimizedRLPTrait::encode_short_string(0x0, 0).unwrap();
        let chain_id = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let empty = OptimizedRLPTrait::encode_short_string(0x0, 0).unwrap();

        let total_len = nonce.len() + gas_price.len() + gas_limit.len() + to.len() + value.len() + data.len() + chain_id.len() + empty.len() + empty.len();
        let result = OptimizedRLPTrait::encode_as_list(array![nonce, gas_price, gas_limit, to, value, data, chain_id, empty, empty].span(), total_len, 0);

        assert_eq!(actual_result.len(), result.len());
    }

    #[test]
    fn test_rlp_encode_legacy_tx_no_calldata() {
        let nonce = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let gas_price = OptimizedRLPTrait::encode_short_string(0x3b9aca00, 4).unwrap();
        let gas_limit = OptimizedRLPTrait::encode_short_string(0x5208, 2).unwrap();
        let to = OptimizedRLPTrait::encode_short_string(0x000035cc6634c0532925a3b844bc454e4438f44e, 20).unwrap(); // try with address with init zeros
        let value = OptimizedRLPTrait::encode_short_string(0xde0b6b3a7640000, 8).unwrap();
        let data = OptimizedRLPTrait::encode_short_string(0x0, 0).unwrap();
        let chain_id = OptimizedRLPTrait::encode_short_string(0x1, 1).unwrap();
        let empty = OptimizedRLPTrait::encode_short_string(0x0, 0).unwrap();

        let total_len = nonce.len() + gas_price.len() + gas_limit.len() + to.len() + value.len() + data.len() + chain_id.len() + empty.len() + empty.len();
        let result = OptimizedRLPTrait::encode_as_list(array![nonce, gas_price, gas_limit, to, value, data, chain_id, empty, empty].span(), total_len, 0);
        assert_eq!(total_len, 43);
        assert_eq!(result.len(), 44);
    }

    #[test]
    fn test_rlp_encode_list_long_multi() {
        let first_elem = OptimizedRLPTrait::encode_bytearray(@"LONGSTRINGTHATINCLUDESMORETHAN55BYTESTESTESTESTESTESTESTESTE").unwrap();
        let second_elem = OptimizedRLPTrait::encode_bytearray(@"cat").unwrap();
        let result = OptimizedRLPTrait::encode_as_list(array![first_elem, second_elem].span(), first_elem.len() + second_elem.len(), 0);

        assert_eq!(result.len(), 68);
        assert_eq!(result.at(0).unwrap(), 0xF8);
    }

    #[test]
    fn test_rlp_encode_list_long() {
        let first_elem = OptimizedRLPTrait::encode_bytearray(@"LONGSTRINGTHATINCLUDESMORETHAN55BYTESTESTESTESTESTESTESTESTE").unwrap();
        let result = OptimizedRLPTrait::encode_as_list(array![first_elem].span(), first_elem.len(), 0);

        assert_eq!(result.len(), 64);
        assert_eq!(result.at(0).unwrap(), 0xF8);
        assert_eq!(result.at(1).unwrap(), 0x3E);
        assert_eq!(result.at(2).unwrap(), 0xB8);
        assert_eq!(result.at(3).unwrap(), 0x3C);
    }

    #[test]
    fn test_rlp_encode_list_short_multi() {
        let first_elem = OptimizedRLPTrait::encode_bytearray(@"cat").unwrap();
        assert_eq!(first_elem.len(), 4);
        let second_elem = OptimizedRLPTrait::encode_bytearray(@"gorilla").unwrap();
        assert_eq!(second_elem.len(), 8);
        let result = OptimizedRLPTrait::encode_as_list(array![first_elem, second_elem].span(), first_elem.len() + second_elem.len(), 0);

        assert_eq!(first_elem.len() + second_elem.len(), 12);

        assert_eq!(result.len(), 13);
        assert_eq!(result.at(0).unwrap(), 0xcc);
        assert_eq!(result.at(1).unwrap(), 0x83);
        assert_eq!(result.at(2).unwrap(), 0x63);
        assert_eq!(result.at(3).unwrap(), 0x61);
        assert_eq!(result.at(4).unwrap(), 0x74);
        assert_eq!(result.at(5).unwrap(), 0x87);
        assert_eq!(result.at(6).unwrap(), 0x67);
        assert_eq!(result.at(7).unwrap(), 0x6F);
        assert_eq!(result.at(8).unwrap(), 0x72);
    }

    #[test]
    fn test_rlp_encode_list_short() {
        let first_elem = OptimizedRLPTrait::encode_bytearray(@"cat").unwrap();
        let result = OptimizedRLPTrait::encode_as_list(array![first_elem].span(), first_elem.len(), 0);

        assert_eq!(result.len(), 5);
        assert_eq!(result.at(0).unwrap(), 0xc4);
        assert_eq!(result.at(1).unwrap(), 0x83);
        assert_eq!(result.at(2).unwrap(), 0x63);
        assert_eq!(result.at(3).unwrap(), 0x61);
        assert_eq!(result.at(4).unwrap(), 0x74);
    }

    #[test]
    fn test_rlp_encode_list_empty() {
        let mut ba: ByteArray = Default::default();

        let result = OptimizedRLPTrait::encode_as_list(array![@ba].span(), 0, 0);
        assert_eq!(result.len(), 1);
        assert_eq!(result.at(0).unwrap(), 0xc0);
    }

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