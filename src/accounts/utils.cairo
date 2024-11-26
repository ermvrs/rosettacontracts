use starknet::secp256_trait::{Signature, signature_from_vrs};
use starknet::{EthAddress};
use crate::accounts::encoding::{Eip1559Transaction, deserialize_bytes};
use crate::utils::transaction::eip2930::{AccessListItem};
use crate::utils::rlp::{RLPTrait, RLPItem, RLPHelpersTrait};
use crate::utils::traits::SpanDefault;
use crate::errors::{EthTransactionError, RLPError, RLPErrorTrait};
use crate::utils::bytes::{U8SpanExTrait};
use crate::accounts::base::{RosettanetCall};
use starknet::eth_signature::{verify_eth_signature};

const CHAIN_ID: u64 = 2933; // TODO: Correct it

#[derive(Copy, Drop, Serde)]
pub struct EthSignature {
    pub r: u256,
    pub s: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct RosettanetTransaction {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: EthAddress,
    value: u256,
    input: Span<u8>,
    access_list: Span<AccessListItem>,
    hash: u256
}

#[derive(Copy, Drop, Serde)]
pub struct RosettanetSignature {
    pub v: u32, // 27 or 28
    pub r: u256,
    pub s: u256,
    pub y_parity: bool // 0 or 1
}

pub fn parse_transaction(call: RosettanetCall) -> Eip1559Transaction {
    let calldata = call.calldata;
    let directives = call.directives;

    let merged_calldata = merge_u256s(calldata.span(), directives.span());
    let deserialized_calldata = deserialize_bytes(merged_calldata);

    // TODO: fix visibility error
    Eip1559Transaction {
        chain_id: CHAIN_ID,
        nonce: call.nonce,
        max_priority_fee_per_gas: call.max_priority_fee_per_gas,
        max_fee_per_gas: call.max_fee_per_gas,
        gas_limit: call.gas_limit,
        to: call.to,
        value: call.value,
        access_list: array![].span(),
        input: deserialized_calldata
    }
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

pub fn decode_encoded_eip1559_transaction(ref encoded_tx: Span<u8>) -> Result<RosettanetTransaction, EthTransactionError> {
    let original_data = encoded_tx;
    let rlp_decoded_data = RLPTrait::decode(encoded_tx).map_err()?;
    //if (rlp_decoded_data.len() != 1) {
        // todo Error
    //    EthTransactionError::RLPError(RLPError::Custom('not encoded as list'))
    //}

    let mut rlp_decoded_data = match *rlp_decoded_data.at(0) {
        RLPItem::String => {
            return Result::Err(
                EthTransactionError::RLPError(RLPError::Custom('not encoded as list'))
            );
        },
        RLPItem::List(v) => { v }
    };

    let boxed_fields = rlp_decoded_data
            .multi_pop_front::<9>()
            .ok_or(EthTransactionError::RLPError(RLPError::InputTooShort))?;
    let [
        chain_id_encoded,
        nonce_encoded,
        max_priority_fee_per_gas_encoded,
        max_fee_per_gas_encoded,
        gas_limit_encoded,
        to_encoded,
        value_encoded,
        input_encoded,
        access_list_encoded
    ] =
        (*boxed_fields)
        .unbox();

    let chain_id = chain_id_encoded.parse_u64_from_string().map_err()?;
    let nonce = nonce_encoded.parse_u64_from_string().map_err()?;
    let max_priority_fee_per_gas = max_priority_fee_per_gas_encoded
        .parse_u128_from_string()
        .map_err()?;
    let max_fee_per_gas = max_fee_per_gas_encoded.parse_u128_from_string().map_err()?;
    let gas_limit = gas_limit_encoded.parse_u64_from_string().map_err()?;
    let to = to_encoded.try_parse_address_from_string().map_err()?.unwrap();
    let value = value_encoded.parse_u256_from_string().map_err()?;
    let input = input_encoded.parse_bytes_from_string().map_err()?;
    let access_list = access_list_encoded.parse_access_list().map_err()?;

    let hash = compute_hash(original_data);

    let tx = RosettanetTransaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        input,
        access_list,
        hash
    };

    Result::Ok(tx)
}


pub fn is_valid_eth_signature(
    msg_hash: u256, eth_address: EthAddress, signature: RosettanetSignature
) -> bool {
    let secp256_signature: Signature = signature_from_vrs(signature.v, signature.r, signature.s);
    let verified = verify_eth_signature(msg_hash, secp256_signature, eth_address).unwrap();
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

    // Decode tests

    use crate::accounts::utils::{decode_encoded_eip1559_transaction, RosettanetTransaction};
    use crate::utils::test_data::{eip_1559_encoded_tx};

    #[test]
    fn test_decode_eip1559() {
        let mut data = eip_1559_encoded_tx();

        let decoded_tx: RosettanetTransaction = decode_encoded_eip1559_transaction(ref data).unwrap();

        assert_eq!(decoded_tx.nonce, 0);
        assert_eq!(decoded_tx.chain_id, 0x4b4b5254);
        assert_eq!(decoded_tx.value, 0x016345785d8a0000);
    }
}