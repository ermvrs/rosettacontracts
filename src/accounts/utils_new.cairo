use crate::accounts::utils::{RosettanetCall, CHAIN_ID};
use crate::optimized_rlp::{OptimizedRLPTrait, OptimizedRLPImpl, compute_keccak, u256_to_rlp_input};

pub fn generate_tx_hash(call: RosettanetCall) -> u256 {
    let encoded_tx = rlp_encode_tx(call);

    compute_keccak(encoded_tx)
}

fn rlp_encode_tx(call: RosettanetCall) -> @ByteArray {
    if call.tx_type != 0 && call.tx_type != 2 {
        panic!("Unsupported tx type");
    }
    if call.tx_type == 0 {
        // Legacy tx
        let nonce = OptimizedRLPTrait::encode_short_string(call.nonce.into(), get_byte_size(call.nonce.into())).unwrap();
        let gas_price = OptimizedRLPTrait::encode_short_string(call.gas_price.into(), get_byte_size(call.gas_price.into())).unwrap();
        let gas_limit = OptimizedRLPTrait::encode_short_string(call.gas_limit.into(), get_byte_size(call.gas_limit.into())).unwrap();
        let to = OptimizedRLPTrait::encode_short_string(call.to.into(), 20).unwrap();
        let chain_id = OptimizedRLPTrait::encode_short_string(CHAIN_ID.into(), 4).unwrap();
        let value = OptimizedRLPTrait::encode_bytearray(u256_to_rlp_input(call.value)).unwrap();
        //let value = OptimizedRLPTrait::encode_short_string(call.value.try_into().unwrap(), get_byte_size(call.value.low) + get_byte_size(call.value.high)).unwrap();
        let empty = OptimizedRLPTrait::encode_short_string(0x0, 0).unwrap();

        let calldata = OptimizedRLPTrait::encode_bytearray(convert_calldata_to_bytearray(call.calldata, call.directives)).unwrap();

        let total_len = nonce.len() + gas_price.len() + gas_limit.len() + to.len() + chain_id.len() + value.len() + empty.len() + empty.len() + calldata.len();
        let result = OptimizedRLPTrait::encode_as_list(array![nonce, gas_price, gas_limit, to, value, calldata, chain_id, empty, empty].span(), total_len, 0);

        return result;
        
    } else {
        let nonce = OptimizedRLPTrait::encode_short_string(call.nonce.into(), get_byte_size(call.nonce.into())).unwrap();
        let max_priority_fee_per_gas = OptimizedRLPTrait::encode_short_string(call.max_priority_fee_per_gas.into(), get_byte_size(call.max_priority_fee_per_gas)).unwrap();
        let max_fee_per_gas = OptimizedRLPTrait::encode_short_string(call.max_fee_per_gas.into(), get_byte_size(call.max_fee_per_gas)).unwrap();
        let gas_limit = OptimizedRLPTrait::encode_short_string(call.gas_limit.into(), get_byte_size(call.gas_limit.into())).unwrap();
        let to = OptimizedRLPTrait::encode_short_string(call.to.into(), 20).unwrap();
        let value = OptimizedRLPTrait::encode_bytearray(u256_to_rlp_input(call.value)).unwrap();
        let chain_id = OptimizedRLPTrait::encode_short_string(CHAIN_ID.into(), 4).unwrap();
        let access_list = OptimizedRLPTrait::encode_as_list(array![].span(), 0, 0);

        let calldata = OptimizedRLPTrait::encode_bytearray(convert_calldata_to_bytearray(call.calldata, call.directives)).unwrap();
        
        let total_len = nonce.len() + max_priority_fee_per_gas.len() + max_fee_per_gas.len() + gas_limit.len() + to.len() + value.len() + calldata.len() + chain_id.len() + access_list.len();
        let result = OptimizedRLPTrait::encode_as_list(array![chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, calldata, access_list].span(), total_len, 0x2);
        
        return result;
    }
}

fn convert_calldata_to_bytearray(mut calldata: Span<felt252>, directives: Span<u8>) -> @ByteArray {
    if calldata.len() == 0 {
        return @Default::default();
    }
    assert(calldata.len() - 1 == directives.len(), 'directives sanity error');

    let mut ba: ByteArray = Default::default();
    let function_signature: felt252 = *calldata.pop_front().unwrap(); // Safe bcs length is not zero

    ba.append_word(function_signature, 4);

    let mut i = 0; // Signature already removed 
    while i < calldata.len() {
        let current_directive = *directives.at(i);
        if(current_directive == 1) {
            let elem = u256 {
                low: (*calldata.at(i))
                    .try_into()
                    .unwrap(),
                high: (*calldata.at(i + 1)).try_into().unwrap()
            };
            ba.append_word(elem.low.into(), 16);
            ba.append_word(elem.high.into(), 16);
            i += 1;
        } else {
            let elem: u256 = (*calldata.at(i)).into();
            ba.append_word(elem.low.into(), 16);
            ba.append_word(elem.high.into(), 16);
        }

        i += 1;
    };

    @ba
}

fn get_byte_size(mut value: u128) -> u32 {
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
    use crate::accounts::utils_new::{convert_calldata_to_bytearray, rlp_encode_tx, generate_tx_hash};
    use crate::accounts::utils::{RosettanetCall};
    // TODO: tests with calldata. Validation error on calldata txs
    #[test]
    fn test_generate_eip1559_tx_hash() {
        let tx = RosettanetCall {
            tx_type: 2,
            to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
            nonce: 59,
            max_priority_fee_per_gas: 158129478,
            max_fee_per_gas: 50742206232,
            gas_price: 0,
            gas_limit: 21000,
            value: 1,
            calldata: array![].span(),
            access_list: array![].span(),
            directives: array![].span(),
            target_function: array![].span()
        };

        let tx_hash = generate_tx_hash(tx);
        assert_eq!(
            tx_hash,
            u256 {
                low: 0x59b1204cfc1f34f0be0f12910c1cf268, high: 0xe035616511002e798765243361a7d52f
            }
        );
    }

    #[test]
    fn test_generate_legacy_tx_hash() {
        let tx = RosettanetCall {
            tx_type: 0,
            to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
            nonce: 4,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_price: 152345,
            gas_limit: 21000,
            value: 1000000000000000000,
            calldata: array![].span(),
            access_list: array![].span(),
            directives: array![].span(),
            target_function: array![].span()
        };

        let tx_hash = generate_tx_hash(tx);
        assert_eq!(tx_hash, u256 { low: 0x5e26225cec38d1e0310e925b2b7565e9, high: 0x147b5df4a6e91fdbd967747f7b375f15});
    }

    #[test]
    fn test_rlp_encode_legacy() {
        let calldata = array![].span(); // transferFrom(0x123123,0x456456, u256 {0,0x666})
        let directives = array![].span(); // Directive length must be -1 bcs first is selector
        let target_function = array![].span(); // transferFrom
        let call = RosettanetCall {
            tx_type: 0,
            to: 0xDC1Be555a2B02aEd499141FF9fAF1A13934a5D2d.try_into().unwrap(),
            nonce: 6,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_price: 151515,
            gas_limit: 21000,
            value: 0,
            calldata: calldata,
            access_list: array![].span(),
            directives: directives,
            target_function: target_function
        };

        let rlp_encoded_tx = rlp_encode_tx(call);

        assert_eq!(rlp_encoded_tx.len(), 39);
    }
    
    #[test]
    fn test_calldata_conversion() {
        let mut calldata = array![0x23b872dd, 0x123123, 0x456456, 0x0, 0x666].span();
        let directives = array![0, 1, 0, 0].span();
        
        let result = convert_calldata_to_bytearray(calldata, directives);

        assert_eq!(result.len(), 100);
    }

    #[test]
    fn test_calldata_conversion_long() {
        let mut calldata = array![0x23b872dd, 0x123123, 0x456456, 0x0, 0x666, 0xfff, 0xff, 0x0, 0x123, 0xbb, 0xccccc, 0xabc, 0xfff, 0x123123123].span();
        let directives = array![0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0].span();
        
        let result = convert_calldata_to_bytearray(calldata, directives);

        assert_eq!(result.len(), 292);
    }
}