use starknet::secp256_trait::{Signature, signature_from_vrs};
use starknet::{EthAddress};
use crate::accounts::encoding::{Eip1559Transaction, deserialize_u256_span};
use crate::utils::traits::SpanDefault;
use crate::utils::bytes::{U8SpanExTrait};
use starknet::eth_signature::{verify_eth_signature};

pub const CHAIN_ID: u64 = 2933; // TODO: Correct it

#[derive(Copy, Drop, Serde)]
pub struct EthSignature {
    pub r: u256,
    pub s: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct RosettanetSignature {
    pub v: u32, // 27 or 28
    pub r: u256,
    pub s: u256,
}

#[derive(Copy, Drop, Clone, Serde)]
pub struct RosettanetCall {
    pub to: EthAddress, // This has to be this account address for multicalls
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub value: u256, // To be used future
    pub calldata: Span<felt252>,
    pub directives: Span<bool>, // We use this directives to figure out u256 splitting happened in element in same index For ex if 3rd element of this array is true, it means 3rd elem is low, 4th elem is high of u256
}

pub fn parse_transaction(call: RosettanetCall) -> Eip1559Transaction {
    let calldata = call.calldata;
    let directives = call.directives;

    let mut merged_calldata = merge_u256s(calldata, directives); // Bunun içinde test yaz
    let deserialized_calldata = deserialize_u256_span(ref merged_calldata); // TODO: check is correct Loop ile byte ayırmalı 
    // TODO: u256 span decodesi içi test yaz

    let eip1559 = Eip1559Transaction {
        chain_id: CHAIN_ID,
        nonce: call.nonce,
        max_priority_fee_per_gas: call.max_priority_fee_per_gas,
        max_fee_per_gas: call.max_fee_per_gas,
        gas_limit: call.gas_limit,
        to: call.to,
        value: call.value,
        access_list: array![].span(),
        input: deserialized_calldata
    };

    eip1559
}

// Merges u256s coming from calldata according to directives
pub fn merge_u256s(calldata: Span<felt252>, directives: Span<bool>) -> Span<u256> {
    assert(calldata.len() == directives.len(), 'R-AU-1 Sanity check fails');
    let mut merged_array = ArrayTrait::<u256>::new();
    let mut index = 0;

    while index < calldata.len() {
        let current_directive = *directives.at(index);
        if(current_directive) {
            let element = u256 {
                low: (*calldata.at(index)).try_into().unwrap(), // We can assume it always fits u128 limit since u256s already splitted low highs
                high: (*calldata.at(index + 1)).try_into().unwrap()
            };
            merged_array.append(element);
            index +=1;
        } else {
            merged_array.append((*calldata.at(index)).into());
        }
        index +=1;
    };

    merged_array.span()
}

#[inline(always)]
pub fn compute_hash(encoded_tx_data: Span<u8>) -> u256 {
    encoded_tx_data.compute_keccak256_hash()
}


pub fn is_valid_eth_signature(
    msg_hash: u256, eth_address: EthAddress, signature: RosettanetSignature
) -> bool {
    let secp256_signature: Signature = signature_from_vrs(signature.v, signature.r, signature.s);
    verify_eth_signature(msg_hash, secp256_signature, eth_address); // TODO: how to check and revert?
    true
}


#[cfg(test)]
mod tests {
    use crate::accounts::utils::{merge_u256s};

    #[test]
    fn test_merge_one() {
        let data = array![0xFF, 0xAB].span();
        let directive = array![true, false].span();

        let merged = merge_u256s(data, directive);

        assert_eq!(*merged.at(0), u256 {low: 0xFF, high: 0xAB});
    }

    #[test]
    fn test_merge_two() {
        let data = array![0xFF, 0xAB, 0x123123, 0x0].span();
        let directive = array![true, false, true, false].span();

        let merged = merge_u256s(data, directive);

        assert_eq!(*merged.at(0), u256 {low: 0xFF, high: 0xAB});
        assert_eq!(*merged.at(1), u256 {low: 0x123123, high: 0x0});
    }

    #[test]
    #[should_panic(expected: 'R-AU-1 Sanity check fails')]
    fn test_merge_wrong_sanity() {
        let data = array![0xFF, 0xAB, 0x123123, 0x0].span();
        let directive = array![true, false, true, false, true].span();

        let merged = merge_u256s(data, directive);

        assert_eq!(*merged.at(0), u256 {low: 0xFF, high: 0xAB});
        assert_eq!(*merged.at(1), u256 {low: 0x123123, high: 0x0});
    }
}